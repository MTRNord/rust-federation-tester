//! Recurring federation check execution.
//!
//! Contains two background loops and the per-alert check helpers:
//!
//! - [`healthy_check_loop`] — runs every 5 minutes for non-failing alerts.
//! - [`active_check_loop`] — runs every 1 minute for alerts in the
//!   confirmation phase or already confirmed as failing.
//!
//! ## State machine
//!
//! ```text
//! Healthy ──fail──► InConfirmation (1..CONFIRMATION_THRESHOLD failures)
//!                        │ ok        │ CONFIRMATION_THRESHOLD reached
//!                        ▼           ▼
//!                    Healthy   ConfirmedFailing ──ok──► Healthy
//!                                    │ still failing
//!                                    ▼
//!                              (reminder emails every 12 h)
//! ```
//!
//! ## Horizontal scaling
//!
//! Both loops acquire a [`Lock`] at the start of each cycle. When Redis/Valkey
//! is configured, only one instance runs checks per cycle; the others skip.
//! The [`Registry`] keeps confirmation counts consistent across instances.
//! The [`crate::AppResources::email_guard`] prevents duplicate emails.
//!
//! See [`crate::distributed`] for details.

use crate::AppResources;
use crate::alerts::email::{REMINDER_EMAIL_INTERVAL, send_failure_email, send_recovery_email};
use crate::connection_pool::ConnectionPool;
use crate::distributed::{Lock, Registry};
use crate::entity::{alert, alert_notification_email, alert_status_history};
use crate::response::{Root, generate_json_report};
use hickory_resolver::Resolver;
use hickory_resolver::name_server::ConnectionProvider;
use sea_orm::{ActiveModelTrait, ActiveValue, ColumnTrait, EntityTrait, QueryFilter};
use std::collections::HashSet;
use std::sync::Arc;
use time::OffsetDateTime;
use tokio::task::JoinSet;
use tokio::time::Duration;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// How frequently healthy (non-failing) servers are checked.
pub const CHECK_INTERVAL: Duration = Duration::from_secs(5 * 60); // 5 minutes

/// How frequently servers in the confirmation phase or confirmed failing are checked.
pub const ACTIVE_CHECK_INTERVAL: Duration = Duration::from_secs(60); // 1 minute

/// Number of consecutive 1-minute failures required before a server is
/// considered "confirmed failing" and an alert email is sent.
///
/// At [`ACTIVE_CHECK_INTERVAL`] this gives a ~5-minute confirmation window
/// that filters out transient blips.
pub const CONFIRMATION_THRESHOLD: u32 = 5;

// ---------------------------------------------------------------------------
// Event type constants (used in log_status_event calls)
// ---------------------------------------------------------------------------

const EVENT_CHECK_FAIL: &str = "check_fail";
const EVENT_CHECK_OK: &str = "check_ok";
const EVENT_EMAIL_FAILURE: &str = "email_failure";
const EVENT_EMAIL_REMINDER: &str = "email_reminder";
const EVENT_EMAIL_RECOVERY: &str = "email_recovery";

// ---------------------------------------------------------------------------
// AlertState — explicit state machine
// ---------------------------------------------------------------------------

/// The resolved state of an alert at check time.
///
/// Derived from the [`Registry`] and the DB `is_currently_failing` flag.
enum AlertState {
    /// In the confirmation phase — consecutive rapid failures are accumulating.
    /// Contains the current failure count before this check.
    InConfirmation { count: u32 },
    /// The DB flag `is_currently_failing = true` — confirmed failing, periodic
    /// reminder emails are active.
    ConfirmedFailing,
    /// Healthy and not in the confirmation registry.
    ///
    /// This state should not appear in the active loop; it is handled
    /// gracefully with a warning and an early return.
    Healthy,
}

// ---------------------------------------------------------------------------
// Public API: should_send_reminder_email
// ---------------------------------------------------------------------------

/// Determine if a reminder email should be sent for a confirmed-failing alert.
///
/// Returns `true` if no email has been sent yet, or if the last email was sent
/// more than [`REMINDER_EMAIL_INTERVAL`] ago.
///
/// Only called for alerts where `is_currently_failing = true`.
#[tracing::instrument(skip_all)]
pub fn should_send_reminder_email(alert: &alert::Model, now: OffsetDateTime) -> bool {
    let Some(last_email) = alert.last_email_sent_at else {
        return true;
    };
    let elapsed = now - last_email;
    elapsed >= time::Duration::try_from(REMINDER_EMAIL_INTERVAL).unwrap()
}

// ---------------------------------------------------------------------------
// Healthy check loop (5-minute interval)
// ---------------------------------------------------------------------------

/// Background loop that periodically checks all healthy (non-failing) alerts.
///
/// At the start of each cycle it acquires the distributed [`Lock`]. If another
/// instance holds the lock, this instance skips the cycle and waits for the
/// next interval.
///
/// Alerts already in the [`Registry`] (confirmation phase) are skipped —
/// they belong to the active loop. On the first failure, an alert is added
/// to the registry with count 1 and the active loop takes over rapid checking.
#[tracing::instrument(skip_all)]
pub async fn healthy_check_loop<P: ConnectionProvider + Send + Sync + 'static>(
    resources: Arc<AppResources>,
    registry: Registry,
    lock: Lock,
    resolver: Arc<Resolver<P>>,
    pool: ConnectionPool,
) {
    let mut interval = tokio::time::interval(CHECK_INTERVAL);
    let mut holding_lock = false;
    loop {
        interval.tick().await;

        let ttl_ms = resources.config.redis.healthy_lock_ttl_secs * 1000;
        let should_run = if holding_lock {
            let ok = lock.try_renew("healthy_check_loop", ttl_ms).await;
            if !ok {
                holding_lock = false;
            }
            ok
        } else {
            let ok = lock.try_acquire("healthy_check_loop", ttl_ms).await;
            holding_lock = ok;
            ok
        };

        if !should_run {
            tracing::debug!(
                name = "alerts.healthy_loop.skipped",
                target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                message = "healthy_check_loop: another instance is running this cycle, skipping"
            );
            continue;
        }

        // 1. Load all verified, non-failing alerts
        let alerts = alert::Entity::find()
            .filter(alert::Column::Verified.eq(true))
            .filter(alert::Column::IsCurrentlyFailing.eq(false))
            .all(resources.db.as_ref())
            .await
            .unwrap_or_default();

        // 2. Skip alerts already in the confirmation registry (active loop owns them)
        let registry_ids = registry.all_ids().await;
        let healthy_alerts: Vec<_> = alerts
            .into_iter()
            .filter(|a| !registry_ids.contains(&a.id))
            .collect();

        tracing::debug!(
            name = "alerts.healthy_loop.iteration",
            target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            alert_count = healthy_alerts.len(),
            message = "Running healthy check loop iteration"
        );

        // 3. Run all healthy checks concurrently
        let mut join_set: JoinSet<()> = JoinSet::new();
        for a in healthy_alerts {
            let resources = resources.clone();
            let registry = registry.clone();
            let resolver = resolver.clone();
            let pool = pool.clone();
            join_set.spawn(async move {
                run_healthy_check(a, &resources, &registry, &resolver, &pool).await;
            });
        }
        while join_set.join_next().await.is_some() {}

        // 4. Housekeeping
        run_housekeeping(&resources.db).await;
    }
}

// ---------------------------------------------------------------------------
// Active check loop (1-minute interval)
// ---------------------------------------------------------------------------

/// Background loop that handles alerts in the confirmation phase or already
/// confirmed as failing.
///
/// At the start of each cycle it acquires the distributed [`Lock`]. If another
/// instance holds the lock, this instance skips the cycle and waits for the
/// next interval.
///
/// Combines:
/// - Alerts from the DB where `is_currently_failing = true`
/// - Alerts in the [`Registry`] (pending confirmation)
#[tracing::instrument(skip_all)]
pub async fn active_check_loop<P: ConnectionProvider + Send + Sync + 'static>(
    resources: Arc<AppResources>,
    registry: Registry,
    lock: Lock,
    resolver: Arc<Resolver<P>>,
    pool: ConnectionPool,
) {
    let mut interval = tokio::time::interval(ACTIVE_CHECK_INTERVAL);
    let mut holding_lock = false;
    loop {
        interval.tick().await;

        let ttl_ms = resources.config.redis.active_lock_ttl_secs * 1000;
        let should_run = if holding_lock {
            let ok = lock.try_renew("active_check_loop", ttl_ms).await;
            if !ok {
                holding_lock = false;
            }
            ok
        } else {
            let ok = lock.try_acquire("active_check_loop", ttl_ms).await;
            holding_lock = ok;
            ok
        };

        if !should_run {
            tracing::debug!(
                name = "alerts.active_loop.skipped",
                target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                message = "active_check_loop: another instance is running this cycle, skipping"
            );
            continue;
        }

        // 1. Confirmed-failing alerts from DB
        let failing_alerts = alert::Entity::find()
            .filter(alert::Column::Verified.eq(true))
            .filter(alert::Column::IsCurrentlyFailing.eq(true))
            .all(resources.db.as_ref())
            .await
            .unwrap_or_default();

        // 2. Confirmation-phase IDs not already in the failing list
        let failing_ids: HashSet<i32> = failing_alerts.iter().map(|a| a.id).collect();
        let registry_ids = registry.all_ids().await;
        let confirmation_ids: Vec<i32> = registry_ids
            .into_iter()
            .filter(|id| !failing_ids.contains(id))
            .collect();

        // 3. Load alert models for confirmation-phase IDs
        let extra_alerts = if confirmation_ids.is_empty() {
            vec![]
        } else {
            alert::Entity::find()
                .filter(alert::Column::Id.is_in(confirmation_ids))
                .all(resources.db.as_ref())
                .await
                .unwrap_or_default()
        };

        // 4. Run all active checks concurrently
        let all_active: Vec<_> = failing_alerts.into_iter().chain(extra_alerts).collect();

        tracing::debug!(
            name = "alerts.active_loop.iteration",
            target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            alert_count = all_active.len(),
            message = "Running active check loop iteration"
        );

        let mut join_set: JoinSet<()> = JoinSet::new();
        for a in all_active {
            let resources = resources.clone();
            let registry = registry.clone();
            let resolver = resolver.clone();
            let pool = pool.clone();
            join_set.spawn(async move {
                run_active_check(a, &resources, &registry, &resolver, &pool).await;
            });
        }
        while join_set.join_next().await.is_some() {}
    }
}

// ---------------------------------------------------------------------------
// Per-alert check helpers
// ---------------------------------------------------------------------------

/// Handle the `Ok(report)` result of a healthy-loop check.
async fn handle_healthy_report(
    a: &alert::Model,
    report: &Root,
    registry: &Registry,
    db: &sea_orm::DatabaseConnection,
    now: OffsetDateTime,
) {
    let mut active = start_active_model(a, now);

    if report.federation_ok {
        active.last_success_at = ActiveValue::Set(Some(now));
        let _ = active.update(db).await;
        return;
    }

    let failure_reason = extract_failure_reason(report);
    active.last_failure_at = ActiveValue::Set(Some(now));
    registry.set(a.id, 1).await;
    log_status_event(
        db,
        a.id,
        &a.server_name,
        EVENT_CHECK_FAIL,
        false,
        0,
        Some(format!("confirmation: 1/{CONFIRMATION_THRESHOLD}")),
        failure_reason,
    )
    .await;
    let _ = active.update(db).await;
    tracing::info!(
        name = "alerts.state.confirmation_started",
        target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
        server_name = %a.server_name,
        alert_id = a.id,
        message = "Server failed healthy check, entering confirmation phase"
    );
}

/// Run a single federation check for a healthy alert.
///
/// On the first failure: inserts the alert into the registry with count 1 so
/// the active loop takes over rapid confirmation checking.
async fn run_healthy_check<P: ConnectionProvider>(
    a: alert::Model,
    resources: &AppResources,
    registry: &Registry,
    resolver: &Resolver<P>,
    pool: &ConnectionPool,
) {
    tracing::debug!(
        name = "alerts.healthy_check.running",
        target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
        server_name = %a.server_name,
        alert_id = a.id,
        message = "Running healthy federation check"
    );

    let Ok(report) = generate_json_report(&a.server_name, resolver, pool).await else {
        tracing::error!(
            name = "alerts.healthy_check.error",
            target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            server_name = %a.server_name,
            alert_id = a.id,
            message = "Federation check error in healthy loop"
        );
        return;
    };

    let now = OffsetDateTime::now_utc();
    handle_healthy_report(&a, &report, registry, resources.db.as_ref(), now).await;
}

/// Dispatch the outcome of an active-loop check to the correct state handler.
async fn dispatch_active_result(
    a: alert::Model,
    state: AlertState,
    report: &Root,
    registry: &Registry,
    resources: &AppResources,
    now: OffsetDateTime,
) {
    match (state, report.federation_ok) {
        (AlertState::InConfirmation { count }, false) => {
            handle_confirmation_failure(
                a,
                count + 1,
                registry,
                resources,
                now,
                extract_failure_reason(report),
            )
            .await;
        }
        (AlertState::InConfirmation { .. }, true) => {
            handle_confirmation_recovery(a, registry, resources, now).await;
        }
        (AlertState::ConfirmedFailing, false) => {
            handle_confirmed_failure(a, resources, now, extract_failure_reason(report)).await;
        }
        (AlertState::ConfirmedFailing, true) => {
            handle_confirmed_recovery(a, resources, now).await;
        }
        (AlertState::Healthy, _) => {
            tracing::warn!(
                name = "alerts.active_check.unexpected_state",
                target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                server_name = %a.server_name,
                alert_id = a.id,
                message = "Alert in active loop but healthy and not in registry — skipping"
            );
        }
    }
}

/// Run a single federation check for an alert in the confirmation phase or
/// already confirmed as failing.
///
/// Resolves the [`AlertState`] from the registry and DB, then dispatches to
/// the appropriate handler.
async fn run_active_check<P: ConnectionProvider>(
    a: alert::Model,
    resources: &AppResources,
    registry: &Registry,
    resolver: &Resolver<P>,
    pool: &ConnectionPool,
) {
    tracing::debug!(
        name = "alerts.active_check.running",
        target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
        server_name = %a.server_name,
        alert_id = a.id,
        message = "Running active federation check"
    );

    let state = match (registry.get(a.id).await, a.is_currently_failing) {
        (Some(count), _) => AlertState::InConfirmation { count },
        (None, true) => AlertState::ConfirmedFailing,
        (None, false) => AlertState::Healthy,
    };

    let Ok(report) = generate_json_report(&a.server_name, resolver, pool).await else {
        tracing::error!(
            name = "alerts.active_check.error",
            target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            server_name = %a.server_name,
            alert_id = a.id,
            message = "Federation check error in active loop"
        );
        return;
    };

    let now = OffsetDateTime::now_utc();
    dispatch_active_result(a, state, &report, registry, resources, now).await;
}

// ---------------------------------------------------------------------------
// State transition handlers
// ---------------------------------------------------------------------------

/// An alert in confirmation phase received another failure.
///
/// If `new_count` reaches [`CONFIRMATION_THRESHOLD`]: removes from registry,
/// promotes to confirmed failing in DB, and sends the first failure email.
/// Otherwise: updates the registry count and DB timestamps.
async fn handle_confirmation_failure(
    a: alert::Model,
    new_count: u32,
    registry: &Registry,
    resources: &AppResources,
    now: OffsetDateTime,
    failure_reason: Option<String>,
) {
    let db = resources.db.as_ref();
    let mut active = start_active_model(&a, now);
    active.last_failure_at = ActiveValue::Set(Some(now));

    log_status_event(
        db,
        a.id,
        &a.server_name,
        EVENT_CHECK_FAIL,
        false,
        0,
        Some(format!(
            "confirmation: {new_count}/{CONFIRMATION_THRESHOLD}"
        )),
        failure_reason.clone(),
    )
    .await;

    if new_count >= CONFIRMATION_THRESHOLD {
        // Promote to confirmed failing and send first alert email.
        registry.remove(a.id).await;
        active.is_currently_failing = ActiveValue::Set(true);
        active.failure_count = ActiveValue::Set(1);

        tracing::info!(
            name = "alerts.state.transition_to_failing",
            target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            server_name = %a.server_name,
            alert_id = a.id,
            message = "Server confirmed failing after rapid checks"
        );

        let Ok(updated) = active.update(db).await else {
            return;
        };
        if let Some(mailer) = &resources.mailer
            && resources.email_guard.try_claim(a.id, "failure").await
        {
            let emails = get_notification_emails(db, &a).await;
            let mut any_sent = false;
            for email in &emails {
                if send_failure_email(
                    mailer,
                    &resources.config,
                    &resources.db,
                    email,
                    &a.server_name,
                    a.id,
                    updated.failure_count,
                    failure_reason.clone(),
                )
                .await
                .is_ok()
                {
                    any_sent = true;
                }
            }
            if any_sent {
                log_status_event(
                    db,
                    a.id,
                    &a.server_name,
                    EVENT_EMAIL_FAILURE,
                    false,
                    1,
                    None,
                    None,
                )
                .await;
                update_email_sent_at(updated, now, db).await;
            }
        }
    } else {
        // Accumulating confirmation failures — update registry and DB.
        registry.set(a.id, new_count).await;
        let _ = active.update(db).await;
    }
}

/// An alert in confirmation phase checked as healthy.
///
/// Cancels the confirmation window — no email is sent.
async fn handle_confirmation_recovery(
    a: alert::Model,
    registry: &Registry,
    resources: &AppResources,
    now: OffsetDateTime,
) {
    let db = resources.db.as_ref();
    registry.remove(a.id).await;

    let mut active = start_active_model(&a, now);
    active.last_success_at = ActiveValue::Set(Some(now));

    log_status_event(
        db,
        a.id,
        &a.server_name,
        EVENT_CHECK_OK,
        true,
        0,
        Some("recovered during confirmation phase".to_string()),
        None,
    )
    .await;

    let _ = active.update(db).await;

    tracing::info!(
        name = "alerts.state.confirmation_cancelled",
        target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
        server_name = %a.server_name,
        alert_id = a.id,
        message = "Server recovered during confirmation phase — no alert sent"
    );
}

/// A confirmed-failing alert checked as still failing.
///
/// Increments the failure count and sends a reminder email if the
/// reminder interval has elapsed and the email guard allows it.
async fn handle_confirmed_failure(
    a: alert::Model,
    resources: &AppResources,
    now: OffsetDateTime,
    failure_reason: Option<String>,
) {
    let db = resources.db.as_ref();
    let new_failure_count = a.failure_count + 1;
    let send_reminder = should_send_reminder_email(&a, now);

    let mut active = start_active_model(&a, now);
    active.last_failure_at = ActiveValue::Set(Some(now));
    active.failure_count = ActiveValue::Set(new_failure_count);

    log_status_event(
        db,
        a.id,
        &a.server_name,
        EVENT_CHECK_FAIL,
        false,
        new_failure_count,
        None,
        failure_reason.clone(),
    )
    .await;

    let Ok(updated) = active.update(db).await else {
        return;
    };

    if send_reminder
        && let Some(mailer) = &resources.mailer
        && resources.email_guard.try_claim(a.id, "reminder").await
    {
        let emails = get_notification_emails(db, &a).await;
        let mut any_sent = false;
        for email in &emails {
            if send_failure_email(
                mailer,
                &resources.config,
                &resources.db,
                email,
                &a.server_name,
                a.id,
                updated.failure_count,
                failure_reason.clone(),
            )
            .await
            .is_ok()
            {
                any_sent = true;
            }
        }
        if any_sent {
            log_status_event(
                db,
                a.id,
                &a.server_name,
                EVENT_EMAIL_REMINDER,
                false,
                updated.failure_count,
                None,
                None,
            )
            .await;
            update_email_sent_at(updated, now, db).await;
        }
    }
}

/// A confirmed-failing alert checked as healthy — it has recovered.
///
/// Marks the alert as no longer failing in DB and sends a recovery email.
async fn handle_confirmed_recovery(a: alert::Model, resources: &AppResources, now: OffsetDateTime) {
    let db = resources.db.as_ref();

    let mut active = start_active_model(&a, now);
    active.is_currently_failing = ActiveValue::Set(false);
    active.last_success_at = ActiveValue::Set(Some(now));
    active.last_recovery_at = ActiveValue::Set(Some(now));

    log_status_event(
        db,
        a.id,
        &a.server_name,
        EVENT_CHECK_OK,
        true,
        a.failure_count,
        Some("recovered from failing state".to_string()),
        None,
    )
    .await;

    if active.update(db).await.is_ok()
        && let Some(mailer) = &resources.mailer
        && resources.email_guard.try_claim(a.id, "recovery").await
    {
        let emails = get_notification_emails(db, &a).await;
        let mut any_sent = false;
        for email in &emails {
            if send_recovery_email(
                mailer,
                &resources.config,
                &resources.db,
                email,
                &a.server_name,
                a.id,
            )
            .await
            .is_ok()
            {
                any_sent = true;
            }
        }
        if any_sent {
            log_status_event(
                db,
                a.id,
                &a.server_name,
                EVENT_EMAIL_RECOVERY,
                true,
                a.failure_count,
                None,
                None,
            )
            .await;
            if let Ok(Some(refreshed)) = alert::Entity::find_by_id(a.id).one(db).await {
                update_email_sent_at(refreshed, now, db).await;
            }
        }
    }

    tracing::info!(
        name = "alerts.state.recovered",
        target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
        server_name = %a.server_name,
        alert_id = a.id,
        message = "Server recovered to healthy state"
    );
}

// ---------------------------------------------------------------------------
// Housekeeping
// ---------------------------------------------------------------------------

/// Delete stale unverified alerts and old status history entries.
///
/// Called at the end of each healthy loop iteration.
async fn run_housekeeping(db: &Arc<sea_orm::DatabaseConnection>) {
    let now = OffsetDateTime::now_utc();

    // Remove unverified alerts older than 1 day (user never confirmed email).
    let cutoff = now - time::Duration::days(1);
    let _ = alert::Entity::delete_many()
        .filter(alert::Column::Verified.eq(false))
        .filter(alert::Column::CreatedAt.lt(cutoff))
        .exec(db.as_ref())
        .await;

    // Prune status history older than 30 days.
    let history_cutoff = now - time::Duration::days(30);
    let _ = alert_status_history::Entity::delete_many()
        .filter(alert_status_history::Column::CreatedAt.lt(history_cutoff))
        .exec(db.as_ref())
        .await;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build an `ActiveModel` from an alert model, pre-setting `last_check_at`.
fn start_active_model(a: &alert::Model, now: OffsetDateTime) -> alert::ActiveModel {
    let mut active: alert::ActiveModel = a.clone().into();
    active.last_check_at = ActiveValue::Set(Some(now));
    active
}

/// Set `last_email_sent_at` on a model and persist it.
async fn update_email_sent_at(
    model: alert::Model,
    now: OffsetDateTime,
    db: &sea_orm::DatabaseConnection,
) {
    let mut active: alert::ActiveModel = model.into();
    active.last_email_sent_at = ActiveValue::Set(Some(now));
    let _ = active.update(db).await;
}

/// Return the notification email addresses for an alert.
///
/// For OAuth2 alerts (`user_id` set): queries `alert_notification_email`.
/// Falls back to `alert.email` if the table is empty (e.g. pre-migration row).
/// For legacy magic-link alerts (`user_id` unset): always uses `alert.email`.
pub async fn get_notification_emails(
    db: &sea_orm::DatabaseConnection,
    alert: &alert::Model,
) -> Vec<String> {
    if alert.user_id.is_some() {
        match alert_notification_email::Entity::find()
            .filter(alert_notification_email::Column::AlertId.eq(alert.id))
            .all(db)
            .await
        {
            Ok(rows) if !rows.is_empty() => rows.into_iter().map(|r| r.email).collect(),
            _ => vec![alert.email.clone()],
        }
    } else {
        vec![alert.email.clone()]
    }
}

/// Extract a human-readable failure reason from a federation report.
///
/// Returns the first available error message, preferring the top-level error
/// (set during server name validation, well-known, or DNS phases) over
/// per-connection errors.
///
/// Example error strings that may be returned:
/// - `"Invalid server name: ..."` (server name validation failure)
/// - `"No A/AAAA-Records for example.org found"` (DNS / well-known DNS failure)
/// - `"A record lookup error for example.org: ..."` (DNS lookup failure)
/// - `"SRV lookup timeout for example.org"` (DNS timeout)
/// - `"SRV record for example.org points to CNAME ..., which is not allowed per RFC2782"`
/// - `"Error fetching well-known URL: 404 Not Found"` (HTTP error during well-known)
/// - `"Timeout while fetching well-known URL: ..."` (network timeout during well-known)
/// - `"m.server points to private/internal address: ..."` (SSRF protection triggered)
/// - `"Error fetching server version from 1.2.3.4:8448: ..."` (connection failure)
/// - `"Error fetching keys from 1.2.3.4:8448: ..."` (key fetch failure)
fn extract_failure_reason(report: &Root) -> Option<String> {
    report.error.as_ref().map(|e| e.error.clone()).or_else(|| {
        report
            .connection_errors
            .values()
            .next()
            .map(|e| e.error.clone())
    })
}

/// Log a status event to the `alert_status_history` table.
#[allow(clippy::too_many_arguments)]
async fn log_status_event(
    db: &sea_orm::DatabaseConnection,
    alert_id: i32,
    server_name: &str,
    event_type: &str,
    federation_ok: bool,
    failure_count: i32,
    details: Option<String>,
    failure_reason: Option<String>,
) {
    let entry = alert_status_history::ActiveModel {
        id: ActiveValue::NotSet,
        alert_id: ActiveValue::Set(alert_id),
        server_name: ActiveValue::Set(server_name.to_string()),
        event_type: ActiveValue::Set(event_type.to_string()),
        federation_ok: ActiveValue::Set(federation_ok),
        failure_count: ActiveValue::Set(failure_count),
        created_at: ActiveValue::Set(OffsetDateTime::now_utc()),
        details: ActiveValue::Set(details),
        failure_reason: ActiveValue::Set(failure_reason),
    };

    if let Err(e) = entry.insert(db).await {
        tracing::error!(
            name = "alerts.status_history.insert_failed",
            target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            error = %e,
            alert_id = alert_id,
            server_name = %server_name,
            event_type = %event_type,
            message = "Failed to log status event to alert_status_history"
        );
    }
}
