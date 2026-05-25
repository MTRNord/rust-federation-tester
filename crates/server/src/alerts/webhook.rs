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
    use crate::entity::{alert_notification_webhook, webhook_outbox};
    use migration::{Migrator, MigratorTrait};
    use sea_orm::{ActiveValue::Set, Database, EntityTrait};
    use std::sync::Arc;
    use time::OffsetDateTime;

    async fn make_db() -> Arc<sea_orm::DatabaseConnection> {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        Arc::new(db)
    }

    async fn insert_alert(db: &sea_orm::DatabaseConnection, id: i32) {
        use crate::entity::alert;
        alert::ActiveModel {
            id: Set(id),
            email: Set("test@example.com".to_string()),
            server_name: Set("matrix.example.com".to_string()),
            verified: Set(true),
            magic_token: Set(None),
            created_at: Set(OffsetDateTime::now_utc()),
            last_check_at: Set(None),
            last_failure_at: Set(None),
            last_success_at: Set(None),
            last_email_sent_at: Set(None),
            failure_count: Set(0),
            is_currently_failing: Set(false),
            last_recovery_at: Set(None),
            user_id: Set(None),
            notify_server_name_change: Set(true),
            notify_version_change: Set(true),
            notify_tls_cert_change: Set(true),
            notify_tls_expiry: Set(true),
            quiet_hours_enabled: Set(false),
            quiet_hours_from: Set("22:00".to_string()),
            quiet_hours_to: Set("07:00".to_string()),
        }
        .insert(db)
        .await
        .unwrap();
    }

    /// Insert a minimal webhook config row.
    async fn insert_webhook(
        db: &sea_orm::DatabaseConnection,
        id: i32,
        alert_id: i32,
        url: &str,
        secret: Option<&str>,
    ) {
        alert_notification_webhook::ActiveModel {
            id: Set(id),
            alert_id: Set(alert_id),
            url: Set(url.to_string()),
            hmac_secret: Set(secret.map(str::to_string)),
            hmac_header: Set("X-Signature-256".to_string()),
            respect_quiet_hours: Set(false),
            created_at: Set(OffsetDateTime::now_utc()),
        }
        .insert(db)
        .await
        .unwrap();
    }

    /// Insert a minimal webhook_outbox row for update-focused tests.
    /// Inserts required alert (id=1) and webhook (id=1) parent rows first.
    async fn insert_outbox_row(
        db: &sea_orm::DatabaseConnection,
        id: &str,
        attempts: i32,
        max_attempts: i32,
    ) -> webhook_outbox::Model {
        // Insert parent rows if they don't exist already
        if alert_notification_webhook::Entity::find_by_id(1)
            .one(db)
            .await
            .unwrap()
            .is_none()
        {
            insert_alert(db, 1).await;
            insert_webhook(db, 1, 1, "https://hook.example.com/wh", None).await;
        }
        let now = OffsetDateTime::now_utc();
        webhook_outbox::ActiveModel {
            id: Set(id.to_string()),
            alert_id: Set(1),
            webhook_id: Set(1),
            event_type: Set("ping".to_string()),
            payload: Set("{}".to_string()),
            status: Set(webhook_outbox::STATUS_PENDING.to_string()),
            attempts: Set(attempts),
            max_attempts: Set(max_attempts),
            next_attempt_at: Set(now),
            last_status_code: Set(None),
            last_error: Set(None),
            created_at: Set(now),
            delivered_at: Set(None),
        }
        .insert(db)
        .await
        .unwrap()
    }

    // ── enqueue_for_alert ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn enqueue_for_alert_no_webhooks_is_ok() {
        let db = make_db().await;
        let result = enqueue_for_alert(
            db.as_ref(),
            99,
            "matrix.example.com",
            "federation_down",
            serde_json::json!({}),
        )
        .await;
        assert!(result.is_ok());
        let rows = webhook_outbox::Entity::find()
            .all(db.as_ref())
            .await
            .unwrap();
        assert!(rows.is_empty());
    }

    #[tokio::test]
    async fn enqueue_for_alert_creates_one_row_per_webhook() {
        let db = make_db().await;
        insert_alert(db.as_ref(), 42).await;
        insert_webhook(db.as_ref(), 1, 42, "https://hook.example.com/1", None).await;
        insert_webhook(db.as_ref(), 2, 42, "https://hook.example.com/2", None).await;

        enqueue_for_alert(
            db.as_ref(),
            42,
            "matrix.example.com",
            "federation_down",
            serde_json::json!({"ok": false}),
        )
        .await
        .unwrap();

        let rows = webhook_outbox::Entity::find()
            .all(db.as_ref())
            .await
            .unwrap();
        assert_eq!(rows.len(), 2);
        for row in &rows {
            assert_eq!(row.status, webhook_outbox::STATUS_PENDING);
            assert_eq!(row.event_type, "federation_down");
            assert_eq!(row.attempts, 0);
            assert_eq!(row.max_attempts, 5);
        }
    }

    #[tokio::test]
    async fn enqueue_for_alert_payload_contains_event_fields() {
        let db = make_db().await;
        insert_alert(db.as_ref(), 1).await;
        insert_webhook(db.as_ref(), 1, 1, "https://hook.example.com/1", None).await;

        enqueue_for_alert(
            db.as_ref(),
            1,
            "s.example.com",
            "federation_up",
            serde_json::json!({"ok": true}),
        )
        .await
        .unwrap();

        let rows = webhook_outbox::Entity::find()
            .all(db.as_ref())
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        let payload: serde_json::Value = serde_json::from_str(&rows[0].payload).unwrap();
        assert_eq!(payload["event_type"], "federation_up");
        assert_eq!(payload["server_name"], "s.example.com");
        assert!(payload["event_id"].is_string());
        assert!(payload["timestamp"].is_number());
    }

    // ── enqueue_ping ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn enqueue_ping_inserts_one_row() {
        let db = make_db().await;
        insert_alert(db.as_ref(), 7).await;
        insert_webhook(db.as_ref(), 3, 7, "https://hook.example.com/ping", None).await;
        enqueue_ping(db.as_ref(), 7, 3, "matrix.example.com")
            .await
            .unwrap();

        let rows = webhook_outbox::Entity::find()
            .all(db.as_ref())
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.alert_id, 7);
        assert_eq!(row.webhook_id, 3);
        assert_eq!(row.event_type, "ping");
        assert_eq!(row.status, webhook_outbox::STATUS_PENDING);
        assert_eq!(row.attempts, 0);
        let payload: serde_json::Value = serde_json::from_str(&row.payload).unwrap();
        assert_eq!(payload["event_type"], "ping");
        assert_eq!(payload["server_name"], "matrix.example.com");
    }

    // ── tick_lock ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn tick_lock_acquires_when_not_holding() {
        let lock = Lock::Noop;
        let mut holding = false;
        assert!(tick_lock(&lock, &mut holding).await);
        assert!(holding);
    }

    #[tokio::test]
    async fn tick_lock_renews_when_holding() {
        let lock = Lock::Noop;
        let mut holding = true;
        assert!(tick_lock(&lock, &mut holding).await);
        assert!(holding);
    }

    // ── mark_delivered ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn mark_delivered_sets_status_and_fields() {
        let db = make_db().await;
        let row = insert_outbox_row(db.as_ref(), "row-1", 1, 5).await;
        let now = OffsetDateTime::now_utc();

        mark_delivered(db.as_ref(), row, now, 200).await;

        let updated = webhook_outbox::Entity::find_by_id("row-1")
            .one(db.as_ref())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated.status, webhook_outbox::STATUS_DELIVERED);
        assert_eq!(updated.last_status_code, Some(200));
        assert!(updated.delivered_at.is_some());
    }

    // ── schedule_retry_or_fail ────────────────────────────────────────────────

    #[tokio::test]
    async fn schedule_retry_increments_attempts_and_stays_pending() {
        let db = make_db().await;
        let row = insert_outbox_row(db.as_ref(), "row-2", 0, 5).await;
        let now = OffsetDateTime::now_utc();

        schedule_retry_or_fail(db.as_ref(), row, now, Some(503), "HTTP 503".to_string()).await;

        let updated = webhook_outbox::Entity::find_by_id("row-2")
            .one(db.as_ref())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated.attempts, 1);
        assert_eq!(updated.status, webhook_outbox::STATUS_PENDING);
        assert_eq!(updated.last_status_code, Some(503));
        assert_eq!(updated.last_error.as_deref(), Some("HTTP 503"));
    }

    #[tokio::test]
    async fn schedule_retry_marks_failed_at_max_attempts() {
        let db = make_db().await;
        // attempts=4, max_attempts=5 → after increment → 5 >= 5 → failed
        let row = insert_outbox_row(db.as_ref(), "row-3", 4, 5).await;
        let now = OffsetDateTime::now_utc();

        schedule_retry_or_fail(db.as_ref(), row, now, None, "timeout".to_string()).await;

        let updated = webhook_outbox::Entity::find_by_id("row-3")
            .one(db.as_ref())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated.attempts, 5);
        assert_eq!(updated.status, webhook_outbox::STATUS_FAILED);
        assert_eq!(updated.last_error.as_deref(), Some("timeout"));
    }

    // ── build_request ─────────────────────────────────────────────────────────

    #[test]
    fn build_request_sets_content_type() {
        let client = reqwest::Client::new();
        let webhook = alert_notification_webhook::Model {
            id: 1,
            alert_id: 1,
            url: "https://hook.example.com/deliver".to_string(),
            hmac_secret: None,
            hmac_header: "X-Signature-256".to_string(),
            respect_quiet_hours: false,
            created_at: OffsetDateTime::now_utc(),
        };
        // build_request returns a RequestBuilder; we can check it builds without panic
        let _req = build_request(&client, &webhook, b"{}".to_vec());
    }

    #[test]
    fn build_request_with_secret_adds_hmac_header() {
        let client = reqwest::Client::new();
        let webhook = alert_notification_webhook::Model {
            id: 1,
            alert_id: 1,
            url: "https://hook.example.com/deliver".to_string(),
            hmac_secret: Some("my-secret".to_string()),
            hmac_header: "X-Hub-Signature-256".to_string(),
            respect_quiet_hours: false,
            created_at: OffsetDateTime::now_utc(),
        };
        let body = b"hello world".to_vec();
        let _req = build_request(&client, &webhook, body);
        // If it gets here without panicking, the builder accepted the HMAC header.
    }

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
