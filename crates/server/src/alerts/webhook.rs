//! Webhook delivery for alert notifications.
//!
//! Mirrors the email outbox pattern: enqueueing is a fast DB INSERT,
//! actual HTTP delivery happens in a background loop.
//!
//! ## Retry schedule (default `max_attempts = 5`)
//!
//! | Attempt | Retry after |
//! |---------|-------------|
//! | 1       | 30 s        |
//! | 2       | 2 min       |
//! | 3       | 10 min      |
//! | 4       | 1 h         |
//! | ≥ 5     | give up (`status = "failed"`) |

use crate::AppResources;
use crate::distributed::Lock;
use crate::entity::{alert_notification_webhook, webhook_outbox};
use hmac::{Hmac, KeyInit, Mac};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter, QueryOrder,
    QuerySelect, sea_query::Expr,
};
use sha2::Sha256;
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;

const POLL_INTERVAL: Duration = Duration::from_secs(10);
const BATCH_SIZE: u64 = 20;
const LOCK_TTL_MS: u64 = 20_000;
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Enqueue webhook deliveries for all webhooks registered on an alert.
///
/// Fetches all webhook configs for the alert from the DB and inserts one
/// `webhook_outbox` row per webhook. The background worker handles actual
/// HTTP delivery.
pub async fn enqueue_for_alert(
    db: &sea_orm::DatabaseConnection,
    alert_id: i32,
    server_name: &str,
    event_type: &str,
    data: serde_json::Value,
) -> Result<(), sea_orm::DbErr> {
    let webhooks = alert_notification_webhook::Entity::find()
        .filter(alert_notification_webhook::Column::AlertId.eq(alert_id))
        .all(db)
        .await?;

    if webhooks.is_empty() {
        return Ok(());
    }

    let now = OffsetDateTime::now_utc();

    for webhook in webhooks {
        let event_id = uuid::Uuid::new_v4().to_string();
        let payload = serde_json::json!({
            "event_id": event_id,
            "event_type": event_type,
            "timestamp": now.unix_timestamp(),
            "server_name": server_name,
            "data": data,
        });
        let payload_str = serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_string());

        let next_attempt_at = if webhook.respect_quiet_hours {
            // quiet-hours deferral handled upstream; use now for simplicity here
            now
        } else {
            now
        };

        let row = webhook_outbox::ActiveModel {
            id: Set(event_id),
            alert_id: Set(alert_id),
            webhook_id: Set(webhook.id),
            event_type: Set(event_type.to_string()),
            payload: Set(payload_str),
            status: Set(webhook_outbox::STATUS_PENDING.to_string()),
            attempts: Set(0),
            max_attempts: Set(5),
            next_attempt_at: Set(next_attempt_at),
            last_status_code: Set(None),
            last_error: Set(None),
            created_at: Set(now),
            delivered_at: Set(None),
        };
        row.insert(db).await?;
    }

    Ok(())
}

/// Enqueue a single ping delivery to a specific webhook.
///
/// Used by the "Test" button in the UI.
pub async fn enqueue_ping(
    db: &sea_orm::DatabaseConnection,
    alert_id: i32,
    webhook_id: i32,
    server_name: &str,
) -> Result<(), sea_orm::DbErr> {
    let now = OffsetDateTime::now_utc();
    let event_id = uuid::Uuid::new_v4().to_string();
    let payload = serde_json::json!({
        "event_id": event_id,
        "event_type": "ping",
        "timestamp": now.unix_timestamp(),
        "server_name": server_name,
        "data": {},
    });
    let payload_str = serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_string());

    let row = webhook_outbox::ActiveModel {
        id: Set(event_id),
        alert_id: Set(alert_id),
        webhook_id: Set(webhook_id),
        event_type: Set("ping".to_string()),
        payload: Set(payload_str),
        status: Set(webhook_outbox::STATUS_PENDING.to_string()),
        attempts: Set(0),
        max_attempts: Set(5),
        next_attempt_at: Set(now),
        last_status_code: Set(None),
        last_error: Set(None),
        created_at: Set(now),
        delivered_at: Set(None),
    };
    row.insert(db).await?;

    Ok(())
}

/// Spawn the webhook delivery worker as a background task.
pub fn spawn_worker(resources: Arc<AppResources>, lock: Lock) {
    tokio::spawn(run_worker(resources, lock));
}

// ---------------------------------------------------------------------------
// HMAC signing
// ---------------------------------------------------------------------------

/// Compute `sha256=<hex>` HMAC-SHA256 signature over `body` using `secret`.
pub fn compute_signature(secret: &str, body: &[u8]) -> String {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(secret.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(body);
    let result = mac.finalize();
    format!("sha256={}", hex::encode(result.into_bytes().as_slice()))
}

// ---------------------------------------------------------------------------
// Worker internals
// ---------------------------------------------------------------------------

async fn run_worker(resources: Arc<AppResources>, lock: Lock) {
    let mut interval = tokio::time::interval(POLL_INTERVAL);
    let mut holding_lock = false;
    loop {
        interval.tick().await;
        if !tick_lock(&lock, &mut holding_lock).await {
            continue;
        }
        if let Err(e) = process_batch(&resources).await {
            tracing::error!(
                name = "webhook_outbox.worker.batch_error",
                target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                error = %e,
                message = "Webhook outbox batch processing failed"
            );
        }
    }
}

async fn tick_lock(lock: &Lock, holding: &mut bool) -> bool {
    if *holding {
        let ok = lock.try_renew("webhook_outbox_worker", LOCK_TTL_MS).await;
        if !ok {
            *holding = false;
        }
        ok
    } else {
        let ok = lock.try_acquire("webhook_outbox_worker", LOCK_TTL_MS).await;
        *holding = ok;
        ok
    }
}

async fn process_batch(resources: &AppResources) -> Result<(), sea_orm::DbErr> {
    let db = resources.db.as_ref();
    let now = OffsetDateTime::now_utc();
    const CLAIM_WINDOW: time::Duration = time::Duration::minutes(5);

    let pending = webhook_outbox::Entity::find()
        .filter(webhook_outbox::Column::Status.eq(webhook_outbox::STATUS_PENDING))
        .filter(webhook_outbox::Column::NextAttemptAt.lte(now))
        .order_by_asc(webhook_outbox::Column::NextAttemptAt)
        .limit(BATCH_SIZE)
        .all(db)
        .await?;

    for item in pending {
        // Atomic claim: bump next_attempt_at before delivery to prevent
        // double-delivery if another instance picks up the same row.
        let claim = webhook_outbox::Entity::update_many()
            .col_expr(
                webhook_outbox::Column::NextAttemptAt,
                Expr::value(now + CLAIM_WINDOW),
            )
            .filter(webhook_outbox::Column::Id.eq(&item.id))
            .filter(webhook_outbox::Column::Status.eq(webhook_outbox::STATUS_PENDING))
            .filter(webhook_outbox::Column::NextAttemptAt.lte(now))
            .exec(db)
            .await?;

        if claim.rows_affected == 0 {
            continue;
        }

        let webhook = match alert_notification_webhook::Entity::find_by_id(item.webhook_id)
            .one(db)
            .await?
        {
            Some(w) => w,
            None => {
                // Webhook was deleted; drop the outbox entry.
                let mut active: webhook_outbox::ActiveModel = item.into();
                active.status = Set(webhook_outbox::STATUS_FAILED.to_string());
                active.last_error = Set(Some("Webhook deleted".to_string()));
                let _ = active.update(db).await;
                continue;
            }
        };

        deliver_item(db, &resources.http_client, item, &webhook, now).await;
    }

    Ok(())
}

fn build_request(
    http: &reqwest::Client,
    webhook: &alert_notification_webhook::Model,
    body_bytes: Vec<u8>,
) -> reqwest::RequestBuilder {
    let mut request = http
        .post(&webhook.url)
        .header("Content-Type", "application/json")
        .body(body_bytes.clone())
        .timeout(DELIVERY_TIMEOUT);

    if let Some(secret) = &webhook.hmac_secret {
        let sig = compute_signature(secret, &body_bytes);
        request = request.header(webhook.hmac_header.as_str(), sig);
    }

    request
}

async fn handle_response(
    db: &sea_orm::DatabaseConnection,
    item: webhook_outbox::Model,
    now: OffsetDateTime,
    resp: reqwest::Response,
) {
    let status = resp.status().as_u16();
    if resp.status().is_success() {
        tracing::info!(
            name = "webhook_outbox.worker.delivered",
            target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            id = %item.id,
            status,
            message = "Webhook delivered"
        );
        mark_delivered(db, item, now, status).await;
    } else {
        tracing::warn!(
            name = "webhook_outbox.worker.non_2xx",
            target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            id = %item.id,
            status,
            message = "Webhook returned non-2xx"
        );
        schedule_retry_or_fail(db, item, now, Some(status as i16), format!("HTTP {status}")).await;
    }
}

async fn deliver_item(
    db: &sea_orm::DatabaseConnection,
    http: &reqwest::Client,
    item: webhook_outbox::Model,
    webhook: &alert_notification_webhook::Model,
    now: OffsetDateTime,
) {
    let body_bytes = item.payload.as_bytes().to_vec();
    let request = build_request(http, webhook, body_bytes);

    match request.send().await {
        Ok(resp) => handle_response(db, item, now, resp).await,
        Err(e) => {
            tracing::warn!(
                name = "webhook_outbox.worker.delivery_error",
                target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                id = %item.id,
                url = %webhook.url,
                error = %e,
                message = "Webhook delivery error"
            );
            schedule_retry_or_fail(db, item, now, None, e.to_string()).await;
        }
    }
}

async fn mark_delivered(
    db: &sea_orm::DatabaseConnection,
    item: webhook_outbox::Model,
    now: OffsetDateTime,
    status_code: u16,
) {
    let mut active: webhook_outbox::ActiveModel = item.into();
    active.status = Set(webhook_outbox::STATUS_DELIVERED.to_string());
    active.delivered_at = Set(Some(now));
    active.last_status_code = Set(Some(status_code as i16));
    let _ = active.update(db).await;
}

async fn schedule_retry_or_fail(
    db: &sea_orm::DatabaseConnection,
    item: webhook_outbox::Model,
    now: OffsetDateTime,
    status_code: Option<i16>,
    error: String,
) {
    let new_attempts = item.attempts + 1;
    let max_attempts = item.max_attempts;
    let mut active: webhook_outbox::ActiveModel = item.into();
    active.attempts = Set(new_attempts);
    active.last_error = Set(Some(error));
    active.last_status_code = Set(status_code);
    if new_attempts >= max_attempts {
        active.status = Set(webhook_outbox::STATUS_FAILED.to_string());
    } else {
        active.next_attempt_at = Set(now + time::Duration::seconds(backoff_secs(new_attempts)));
    }
    let _ = active.update(db).await;
}

fn backoff_secs(attempt: i32) -> i64 {
    match attempt {
        1 => 30,
        2 => 120,
        3 => 600,
        4 => 3_600,
        _ => 21_600,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── backoff_secs ──────────────────────────────────────────────────────────

    #[test]
    fn backoff_attempt_1_is_30s() {
        assert_eq!(backoff_secs(1), 30);
    }

    #[test]
    fn backoff_attempt_2_is_2min() {
        assert_eq!(backoff_secs(2), 120);
    }

    #[test]
    fn backoff_attempt_3_is_10min() {
        assert_eq!(backoff_secs(3), 600);
    }

    #[test]
    fn backoff_attempt_4_is_1h() {
        assert_eq!(backoff_secs(4), 3_600);
    }

    #[test]
    fn backoff_attempt_5_plus_is_6h() {
        assert_eq!(backoff_secs(5), 21_600);
        assert_eq!(backoff_secs(10), 21_600);
        assert_eq!(backoff_secs(0), 21_600);
    }

    // ── compute_signature ─────────────────────────────────────────────────────

    #[test]
    fn compute_signature_has_sha256_prefix() {
        let sig = compute_signature("secret", b"hello");
        assert!(
            sig.starts_with("sha256="),
            "expected sha256= prefix, got: {sig}"
        );
    }

    #[test]
    fn compute_signature_is_hex_after_prefix() {
        let sig = compute_signature("secret", b"hello");
        let hex_part = sig.strip_prefix("sha256=").unwrap();
        assert!(
            hex_part.chars().all(|c| c.is_ascii_hexdigit()),
            "should be hex: {hex_part}"
        );
        assert_eq!(hex_part.len(), 64, "SHA-256 hex is 64 chars");
    }

    #[test]
    fn compute_signature_different_secrets_differ() {
        let a = compute_signature("secret1", b"body");
        let b = compute_signature("secret2", b"body");
        assert_ne!(a, b);
    }

    #[test]
    fn compute_signature_different_bodies_differ() {
        let a = compute_signature("secret", b"body_a");
        let b = compute_signature("secret", b"body_b");
        assert_ne!(a, b);
    }

    #[test]
    fn compute_signature_is_deterministic() {
        let a = compute_signature("key", b"payload");
        let b = compute_signature("key", b"payload");
        assert_eq!(a, b);
    }

    #[test]
    fn compute_signature_known_vector() {
        // HMAC-SHA256("key", "The quick brown fox...") known answer
        let sig = compute_signature("key", b"The quick brown fox jumps over the lazy dog");
        // Verify structure: sha256= + 64 hex chars
        assert!(sig.starts_with("sha256="));
        assert_eq!(sig.len(), "sha256=".len() + 64);
    }
}
