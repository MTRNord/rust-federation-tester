//! Database-backed email outbox with automatic retry and multi-instance coordination.
//!
//! ## Why an outbox?
//!
//! Calling `mailer.send()` inside an HTTP handler blocks the response for the
//! full SMTP round-trip (often 300–2000 ms). An outbox decouples enqueueing
//! (a fast DB INSERT) from delivery (a background worker), so HTTP handlers
//! return immediately while emails are sent reliably in the background.
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
//!
//! ## Multi-instance safety
//!
//! The worker acquires a distributed [`Lock`] before processing each batch so
//! only one pod processes the outbox in any given 30-second window. This
//! mirrors how the alert check loops work.
//!
//! ## Expiring emails
//!
//! Set `expires_at` for emails containing time-sensitive content (e.g. magic
//! link emails whose embedded JWT is only valid for 1 hour). The worker marks
//! such rows `"expired"` without attempting delivery once the deadline passes.
//!
//! The [`requeue_failed`] function can reset `"failed"` rows back to
//! `"pending"` after an SMTP outage, skipping rows whose `expires_at` has
//! already passed.

use std::sync::Arc;
use std::time::Duration;

use lettre::AsyncTransport;
use lettre::message::{MultiPart, SinglePart, header};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter,
    QueryOrder, QuerySelect,
};
use time::OffsetDateTime;

use crate::AppResources;
use crate::distributed::Lock;
use crate::entity::email_outbox::{
    self, Entity as EmailOutboxEntity, STATUS_EXPIRED, STATUS_FAILED, STATUS_PENDING, STATUS_SENT,
};

const POLL_INTERVAL: Duration = Duration::from_secs(10);
const BATCH_SIZE: u64 = 20;
/// Lock TTL: 2× POLL_INTERVAL so a slow batch still has headroom, while a
/// crashed holder is detected within one TTL + one poll = ~30 s.
/// The holder renews on every tick, so processing happens every POLL_INTERVAL
/// rather than once per TTL.
const LOCK_TTL_MS: u64 = 20_000;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Enqueue an email for background delivery.
///
/// Performs a single DB INSERT and returns immediately. The outbox worker
/// (started via [`spawn_worker`]) picks up the row within ~10 seconds.
///
/// `expires_at`: set for emails containing time-sensitive tokens such as
/// magic-link JWTs, which expire 1 hour after issuance. Pass
/// `Some(jwt_expiry)` so the worker can mark the row `"expired"` rather than
/// delivering a link the recipient can no longer use.
pub async fn enqueue(
    db: &DatabaseConnection,
    to: &str,
    subject: &str,
    html_body: Option<String>,
    text_body: String,
    expires_at: Option<OffsetDateTime>,
) -> Result<(), sea_orm::DbErr> {
    let now = OffsetDateTime::now_utc();
    let row = email_outbox::ActiveModel {
        id: Set(uuid::Uuid::new_v4().to_string()),
        to_email: Set(to.to_string()),
        subject: Set(subject.to_string()),
        html_body: Set(html_body),
        text_body: Set(text_body),
        status: Set(STATUS_PENDING.to_string()),
        attempts: Set(0),
        max_attempts: Set(5),
        next_attempt_at: Set(now),
        expires_at: Set(expires_at),
        last_error: Set(None),
        created_at: Set(now),
        sent_at: Set(None),
    };
    row.insert(db).await?;
    Ok(())
}

/// Spawn the outbox delivery worker as a background task.
///
/// The worker polls every 10 seconds. Pass the same `lock` used by the alert
/// check loops so distributed locking works across all background tasks.
pub fn spawn_worker(resources: Arc<AppResources>, lock: Lock) {
    tokio::spawn(run_worker(resources, lock));
}

/// Reset all non-expired `"failed"` outbox rows back to `"pending"` so they
/// will be retried by the next worker tick.
///
/// Rows whose `expires_at` is set and in the past are **skipped** — those
/// emails contain stale tokens (magic links) that can no longer be used even
/// if delivered. The user must request a fresh magic link.
///
/// Returns `(requeued, skipped_because_expired)`.
pub async fn requeue_failed(db: &DatabaseConnection) -> Result<(u64, u64), sea_orm::DbErr> {
    let now = OffsetDateTime::now_utc();

    let failed = EmailOutboxEntity::find()
        .filter(email_outbox::Column::Status.eq(STATUS_FAILED))
        .all(db)
        .await?;

    let mut requeued = 0u64;
    let mut skipped = 0u64;

    for item in failed {
        if let Some(exp) = item.expires_at
            && exp <= now
        {
            skipped += 1;
            continue;
        }
        let mut active: email_outbox::ActiveModel = item.into();
        active.status = Set(STATUS_PENDING.to_string());
        active.attempts = Set(0);
        active.next_attempt_at = Set(now);
        active.last_error = Set(None);
        active.update(db).await?;
        requeued += 1;
    }

    Ok((requeued, skipped))
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
                name = "email_outbox.worker.batch_error",
                target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                error = %e,
                message = "Email outbox batch processing failed"
            );
        }
    }
}

/// Acquire or renew the outbox worker lock for this tick.
/// Returns `true` if this instance should process the current cycle.
// tracing! macros expand to `if` blocks that inflate the cognitive complexity
// score beyond what the two logical branches here actually warrant.
#[allow(clippy::cognitive_complexity)]
async fn tick_lock(lock: &Lock, holding: &mut bool) -> bool {
    if *holding {
        let ok = lock.try_renew("email_outbox_worker", LOCK_TTL_MS).await;
        if !ok {
            *holding = false;
            tracing::debug!(
                name = "email_outbox.worker.lock_lost",
                target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                message = "outbox worker: lock lost (another instance took over), skipping cycle"
            );
        }
        ok
    } else {
        let ok = lock.try_acquire("email_outbox_worker", LOCK_TTL_MS).await;
        *holding = ok;
        if !ok {
            tracing::debug!(
                name = "email_outbox.worker.skipped",
                target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                message = "outbox worker: another instance holds the lock, skipping cycle"
            );
        }
        ok
    }
}

async fn process_batch(resources: &AppResources) -> Result<(), sea_orm::DbErr> {
    let Some(mailer) = &resources.mailer else {
        return Ok(());
    };

    let db = resources.db.as_ref();
    let now = OffsetDateTime::now_utc();

    let pending = EmailOutboxEntity::find()
        .filter(email_outbox::Column::Status.eq(STATUS_PENDING))
        .filter(email_outbox::Column::NextAttemptAt.lte(now))
        .order_by_asc(email_outbox::Column::NextAttemptAt)
        .limit(BATCH_SIZE)
        .all(db)
        .await?;

    for item in pending {
        // Before attempting delivery, check whether the email's embedded
        // content has expired (e.g. a magic-link JWT with a 1-hour TTL).
        if let Some(exp) = item.expires_at
            && exp <= now
        {
            tracing::warn!(
                name = "email_outbox.worker.expired",
                target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                id = %item.id,
                to = %item.to_email,
                subject = %item.subject,
                message = "Email outbox: entry expired before delivery; dropping"
            );
            let mut active: email_outbox::ActiveModel = item.into();
            active.status = Set(STATUS_EXPIRED.to_string());
            let _ = active.update(db).await;
            continue;
        }

        deliver_item(db, mailer, &resources.config.smtp.from, item, now).await;
    }

    Ok(())
}

// tracing! macros expand to `if` blocks that inflate the cognitive complexity
// score beyond what the three logical branches here actually warrant.
#[allow(clippy::cognitive_complexity)]
async fn deliver_item(
    db: &DatabaseConnection,
    mailer: &Arc<lettre::AsyncSmtpTransport<lettre::Tokio1Executor>>,
    from: &str,
    item: email_outbox::Model,
    now: OffsetDateTime,
) {
    let msg = match build_message(from, &item) {
        Ok(m) => m,
        Err(e) => {
            tracing::error!(
                name = "email_outbox.worker.build_failed",
                target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                id = %item.id,
                to = %item.to_email,
                error = %e,
                message = "Email outbox: could not build message; marking failed"
            );
            mark_failed(db, item, now, e.to_string()).await;
            return;
        }
    };

    match mailer.send(msg).await {
        Ok(_) => {
            tracing::info!(
                name = "email_outbox.worker.delivered",
                target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                id = %item.id,
                to = %item.to_email,
                message = "Email outbox: delivered"
            );
            mark_sent(db, item, now).await;
        }
        Err(e) => {
            tracing::warn!(
                name = "email_outbox.worker.delivery_failed",
                target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                id = %item.id,
                to = %item.to_email,
                attempts = item.attempts + 1,
                max_attempts = item.max_attempts,
                error = %e,
                message = "Email outbox: delivery failed"
            );
            schedule_retry_or_fail(db, item, now, e.to_string()).await;
        }
    }
}

async fn mark_sent(db: &DatabaseConnection, item: email_outbox::Model, now: OffsetDateTime) {
    let mut active: email_outbox::ActiveModel = item.into();
    active.status = Set(STATUS_SENT.to_string());
    active.sent_at = Set(Some(now));
    let _ = active.update(db).await;
}

async fn mark_failed(
    db: &DatabaseConnection,
    item: email_outbox::Model,
    _now: OffsetDateTime,
    error: String,
) {
    let mut active: email_outbox::ActiveModel = item.into();
    active.status = Set(STATUS_FAILED.to_string());
    active.last_error = Set(Some(error));
    let _ = active.update(db).await;
}

async fn schedule_retry_or_fail(
    db: &DatabaseConnection,
    item: email_outbox::Model,
    now: OffsetDateTime,
    error: String,
) {
    let new_attempts = item.attempts + 1;
    let max_attempts = item.max_attempts;
    let mut active: email_outbox::ActiveModel = item.into();
    active.attempts = Set(new_attempts);
    active.last_error = Set(Some(error));
    if new_attempts >= max_attempts {
        active.status = Set(STATUS_FAILED.to_string());
    } else {
        active.next_attempt_at = Set(now + time::Duration::seconds(backoff_secs(new_attempts)));
    }
    let _ = active.update(db).await;
}

/// Exponential back-off delay for each successive failed attempt.
fn backoff_secs(attempt: i32) -> i64 {
    match attempt {
        1 => 30,
        2 => 120,
        3 => 600,
        4 => 3_600,
        _ => 21_600,
    }
}

fn build_message(
    from: &str,
    item: &email_outbox::Model,
) -> Result<lettre::Message, Box<dyn std::error::Error + Send + Sync>> {
    let builder = lettre::Message::builder()
        .from(from.parse()?)
        .to(item.to_email.parse()?)
        .subject(&item.subject)
        .header(header::MIME_VERSION_1_0)
        .message_id(None);

    let msg = if let Some(html) = &item.html_body {
        builder.multipart(
            MultiPart::alternative()
                .singlepart(
                    SinglePart::builder()
                        .header(header::ContentType::TEXT_PLAIN)
                        .body(item.text_body.clone()),
                )
                .singlepart(
                    SinglePart::builder()
                        .header(header::ContentType::TEXT_HTML)
                        .body(html.clone()),
                ),
        )?
    } else {
        builder
            .header(header::ContentType::TEXT_PLAIN)
            .body(item.text_body.clone())?
    };

    Ok(msg)
}
