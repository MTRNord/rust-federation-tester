//! Recurring federation check execution.
//!
//! Contains two batch check loops:
//! - `healthy_check_loop`: runs every 5 minutes for non-failing servers
//! - `active_check_loop`: runs every 1 minute for servers in the confirmation
//!   phase or already confirmed as failing
//!
//! A shared [`ConfirmationRegistry`] tracks how many consecutive 1-minute
//! failures each alert has accumulated before being promoted to "confirmed
//! failing" and triggering an email.

use crate::AppResources;
use crate::alerts::email::{REMINDER_EMAIL_INTERVAL, send_failure_email, send_recovery_email};
use crate::connection_pool::ConnectionPool;
use crate::entity::{alert, alert_status_history};
use crate::response::{Root, generate_json_report};
use hickory_resolver::Resolver;
use hickory_resolver::name_server::ConnectionProvider;
use sea_orm::{ActiveModelTrait, ActiveValue, ColumnTrait, EntityTrait, QueryFilter};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use time::OffsetDateTime;
use tokio::sync::Mutex;
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
/// At [`ACTIVE_CHECK_INTERVAL`] this gives a ~5-minute confirmation window
/// that filters out transient blips.
pub const CONFIRMATION_THRESHOLD: u32 = 5;

// ---------------------------------------------------------------------------
// Event type string constants (used in log_status_event calls)
// ---------------------------------------------------------------------------

const EVENT_CHECK_FAIL: &str = "check_fail";
const EVENT_CHECK_OK: &str = "check_ok";
const EVENT_EMAIL_FAILURE: &str = "email_failure";
const EVENT_EMAIL_REMINDER: &str = "email_reminder";
const EVENT_EMAIL_RECOVERY: &str = "email_recovery";

// ---------------------------------------------------------------------------
// ConfirmationRegistry
// ---------------------------------------------------------------------------

/// In-memory tracking of alerts in the confirmation phase.
///
/// Maps `alert_id → consecutive 1-minute failure count` (`1..CONFIRMATION_THRESHOLD`).
///
/// **Intentionally not persisted.** On restart the registry is empty, so any
/// in-progress confirmation window resets. This is the correct behaviour:
/// stale failure counts from an unknown time in the past should not be resumed,
/// because we cannot determine whether those failures happened at 1-minute
/// intervals or were spread over a much longer period.
pub type ConfirmationRegistry = Arc<Mutex<HashMap<i32, u32>>>;

// ---------------------------------------------------------------------------
// Public API: should_send_reminder_email
// ---------------------------------------------------------------------------

/// Determine if a reminder email should be sent for a confirmed-failing alert.
///
/// Returns `true` if no email has been sent yet, or if the last email was sent
/// more than [`REMINDER_EMAIL_INTERVAL`] ago.
///
/// This function is only called for alerts where `is_currently_failing = true`.
/// The confirmation phase (before the first email) is handled separately by the
/// active loop using the [`ConfirmationRegistry`].
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
/// Skips any alert that is already in the [`ConfirmationRegistry`] — those
/// belong to the active loop. On the first failure for a server, adds it to
/// the registry with count 1 so the active loop takes over rapid checking.
#[tracing::instrument(skip_all)]
pub async fn healthy_check_loop<P: ConnectionProvider + Send + Sync + 'static>(
    resources: Arc<AppResources>,
    registry: ConfirmationRegistry,
    resolver: Arc<Resolver<P>>,
    pool: ConnectionPool,
) {
    loop {
        // 1. Load all verified, non-failing alerts
        let alerts = alert::Entity::find()
            .filter(alert::Column::Verified.eq(true))
            .filter(alert::Column::IsCurrentlyFailing.eq(false))
            .all(resources.db.as_ref())
            .await
            .unwrap_or_default();

        // 2. Skip any already in the confirmation registry (active loop owns them)
        let registry_ids: HashSet<i32> = {
            let reg = registry.lock().await;
            reg.keys().copied().collect()
        };
        let healthy_alerts: Vec<_> = alerts
            .into_iter()
            .filter(|a| !registry_ids.contains(&a.id))
            .collect();

        // 3. Run all healthy checks concurrently
        let mut join_set: JoinSet<()> = JoinSet::new();
        for a in healthy_alerts {
            let resources = resources.clone();
            let registry = registry.clone();
            let resolver = resolver.clone();
            let pool = pool.clone();
            join_set.spawn(async move {
                run_healthy_check(a, &resources, registry, &resolver, &pool).await;
            });
        }
        while join_set.join_next().await.is_some() {}

        // 4. Housekeeping: clean up unverified alerts older than 1 day
        let cutoff = OffsetDateTime::now_utc() - time::Duration::days(1);
        let _ = alert::Entity::delete_many()
            .filter(alert::Column::Verified.eq(false))
            .filter(alert::Column::CreatedAt.lt(cutoff))
            .exec(resources.db.as_ref())
            .await;

        // 5. Housekeeping: clean up status history older than 30 days
        let history_cutoff = OffsetDateTime::now_utc() - time::Duration::days(30);
        let _ = alert_status_history::Entity::delete_many()
            .filter(alert_status_history::Column::CreatedAt.lt(history_cutoff))
            .exec(resources.db.as_ref())
            .await;

        tokio::time::sleep(CHECK_INTERVAL).await;
    }
}

// ---------------------------------------------------------------------------
// Active check loop (1-minute interval)
// ---------------------------------------------------------------------------

/// Background loop that handles alerts in the confirmation phase or already
/// confirmed as failing.
///
/// Combines:
/// - Alerts from the DB where `is_currently_failing = true`
/// - Alerts in the [`ConfirmationRegistry`] (pending confirmation)
#[tracing::instrument(skip_all)]
pub async fn active_check_loop<P: ConnectionProvider + Send + Sync + 'static>(
    resources: Arc<AppResources>,
    registry: ConfirmationRegistry,
    resolver: Arc<Resolver<P>>,
    pool: ConnectionPool,
) {
    loop {
        // 1. Confirmed-failing alerts from DB
        let failing_alerts = alert::Entity::find()
            .filter(alert::Column::Verified.eq(true))
            .filter(alert::Column::IsCurrentlyFailing.eq(true))
            .all(resources.db.as_ref())
            .await
            .unwrap_or_default();

        // 2. Confirmation-phase IDs not already in the failing list
        let failing_ids: HashSet<i32> = failing_alerts.iter().map(|a| a.id).collect();
        let confirmation_ids: Vec<i32> = {
            let reg = registry.lock().await;
            reg.keys()
                .copied()
                .filter(|id| !failing_ids.contains(id))
                .collect()
        };

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
        let mut join_set: JoinSet<()> = JoinSet::new();
        for a in all_active {
            let resources = resources.clone();
            let registry = registry.clone();
            let resolver = resolver.clone();
            let pool = pool.clone();
            join_set.spawn(async move {
                run_active_check(a, &resources, registry, &resolver, &pool).await;
            });
        }
        while join_set.join_next().await.is_some() {}

        tokio::time::sleep(ACTIVE_CHECK_INTERVAL).await;
    }
}

// ---------------------------------------------------------------------------
// Per-alert check helpers
// ---------------------------------------------------------------------------

/// Run a single federation check for a healthy alert.
///
/// On first failure: inserts the alert into the registry (count = 1) and
/// transitions it to the active loop. On success: updates timestamps.
async fn run_healthy_check<P: ConnectionProvider>(
    a: alert::Model,
    resources: &AppResources,
    registry: ConfirmationRegistry,
    resolver: &Resolver<P>,
    pool: &ConnectionPool,
) {
    let report = generate_json_report(&a.server_name, resolver, pool).await;
    let now = OffsetDateTime::now_utc();
    let db = resources.db.as_ref();

    match report {
        Ok(report) => {
            let mut active: alert::ActiveModel = a.clone().into();
            active.last_check_at = ActiveValue::Set(Some(now));

            if !report.federation_ok {
                let failure_reason = extract_failure_reason(&report);
                active.last_failure_at = ActiveValue::Set(Some(now));

                // Enter confirmation phase
                registry.lock().await.insert(a.id, 1);

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
            } else {
                active.last_success_at = ActiveValue::Set(Some(now));
                let _ = active.update(db).await;
            }
        }
        Err(e) => {
            tracing::error!(
                name = "alerts.healthy_check.error",
                target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                server_name = %a.server_name,
                error = ?e,
                message = "Federation check error in healthy loop"
            );
        }
    }
}

/// Run a single federation check for an alert in the confirmation phase or
/// already confirmed as failing.
#[allow(clippy::too_many_lines)]
async fn run_active_check<P: ConnectionProvider>(
    a: alert::Model,
    resources: &AppResources,
    registry: ConfirmationRegistry,
    resolver: &Resolver<P>,
    pool: &ConnectionPool,
) {
    let report = generate_json_report(&a.server_name, resolver, pool).await;
    let now = OffsetDateTime::now_utc();
    let db = resources.db.as_ref();
    let mailer = &resources.mailer;
    let config = &resources.config;
    let db_arc = &resources.db;

    // Read confirmation count without holding the lock across await points
    let confirmation_count: Option<u32> = {
        let reg = registry.lock().await;
        reg.get(&a.id).copied()
    };

    match report {
        Ok(report) => {
            let mut active: alert::ActiveModel = a.clone().into();
            active.last_check_at = ActiveValue::Set(Some(now));

            if !report.federation_ok {
                let failure_reason = extract_failure_reason(&report);
                active.last_failure_at = ActiveValue::Set(Some(now));

                if let Some(count) = confirmation_count {
                    // ── Confirmation phase ──────────────────────────────────
                    let new_count = count + 1;

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
                        // Confirmed failing — promote and send first email
                        registry.lock().await.remove(&a.id);
                        active.is_currently_failing = ActiveValue::Set(true);
                        active.failure_count = ActiveValue::Set(1);

                        tracing::info!(
                            name = "alerts.state.transition_to_failing",
                            target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                            server_name = %a.server_name,
                            alert_id = a.id,
                            message = "Server confirmed failing after rapid checks"
                        );

                        if let Ok(updated) = active.update(db).await
                            && send_failure_email(
                                mailer,
                                config,
                                db_arc,
                                &a.email,
                                &a.server_name,
                                a.id,
                                updated.failure_count,
                                failure_reason,
                            )
                            .await
                            .is_ok()
                        {
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

                            let mut email_update: alert::ActiveModel = updated.into();
                            email_update.last_email_sent_at = ActiveValue::Set(Some(now));
                            let _ = email_update.update(db).await;
                        }
                    } else {
                        // Still accumulating confirmation failures
                        registry.lock().await.insert(a.id, new_count);
                        let _ = active.update(db).await;
                    }
                } else if a.is_currently_failing {
                    // ── Confirmed failing — reminder logic ──────────────────
                    let new_failure_count = a.failure_count + 1;
                    let send_reminder = should_send_reminder_email(&a, now);

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

                    if let Ok(updated) = active.update(db).await
                        && send_reminder
                        && send_failure_email(
                            mailer,
                            config,
                            db_arc,
                            &a.email,
                            &a.server_name,
                            a.id,
                            updated.failure_count,
                            failure_reason,
                        )
                        .await
                        .is_ok()
                    {
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

                        let mut email_update: alert::ActiveModel = updated.into();
                        email_update.last_email_sent_at = ActiveValue::Set(Some(now));
                        let _ = email_update.update(db).await;
                    }
                }
                // (If !is_currently_failing and not in registry, alert shouldn't
                // be in the active loop — skip gracefully.)
            } else {
                // ── Server is healthy ───────────────────────────────────────
                if confirmation_count.is_some() {
                    // Recovered during confirmation phase — no email needed
                    registry.lock().await.remove(&a.id);
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
                } else if a.is_currently_failing {
                    // Transition from confirmed failing to healthy
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
                        && send_recovery_email(
                            mailer,
                            config,
                            db_arc,
                            &a.email,
                            &a.server_name,
                            a.id,
                        )
                        .await
                        .is_ok()
                    {
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

                        // Fetch refreshed model to update last_email_sent_at
                        if let Ok(Some(refreshed)) = alert::Entity::find_by_id(a.id).one(db).await {
                            let mut email_update: alert::ActiveModel = refreshed.into();
                            email_update.last_email_sent_at = ActiveValue::Set(Some(now));
                            let _ = email_update.update(db).await;
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
                // (Still healthy and not in registry — no action needed.)
            }
        }
        Err(e) => {
            tracing::error!(
                name = "alerts.active_check.error",
                target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                server_name = %a.server_name,
                error = ?e,
                message = "Federation check error in active loop"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
