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
use crate::alerts::email::{
    REMINDER_EMAIL_INTERVAL, format_email_datetime, send_failure_email, send_recovery_email,
};
use crate::alerts::webhook::enqueue_for_alert;
use crate::connection_pool::ConnectionPool;
use crate::distributed::{Lock, Registry};
use crate::email_outbox;
use crate::email_templates::{FailureEmailTemplate, env_subject};
use crate::entity::{
    alert, alert_notification_email, alert_status_history, oauth2_user, user_email,
};
use crate::response::{Root, generate_json_report};
use hickory_resolver::ConnectionProvider;
use hickory_resolver::Resolver;
use sea_orm::{ActiveModelTrait, ActiveValue, ColumnTrait, EntityTrait, QueryFilter};
use std::collections::HashSet;
use std::sync::Arc;
use time::OffsetDateTime;
use time_tz::{OffsetDateTimeExt, PrimitiveDateTimeExt, timezones};
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
// Quiet hours helper
// ---------------------------------------------------------------------------

/// Check whether `now` (UTC) falls within the quiet window defined by `from`/`to` (both "HH:MM"),
/// interpreted in the recipient's `timezone` (IANA name, e.g. "Europe/Berlin").
/// Handles overnight windows (e.g., "22:00" → "07:00").
///
/// Returns `Some(wake_at)` — the UTC time when the quiet window ends — if we are currently
/// inside the window, or `None` if we are outside it or quiet hours are disabled.
fn quiet_hours_end(
    enabled: bool,
    from: &str,
    to: &str,
    now: OffsetDateTime,
    timezone: &str,
) -> Option<OffsetDateTime> {
    if !enabled {
        return None;
    }

    let parse_hm = |s: &str| -> Option<(u8, u8)> {
        let (h, m) = s.split_once(':')?;
        Some((h.parse().ok()?, m.parse().ok()?))
    };

    let (fh, fm) = parse_hm(from)?;
    let (th, tm) = parse_hm(to)?;

    let tz = timezones::get_by_name(timezone).unwrap_or(timezones::db::UTC);
    let now_local = now.to_timezone(tz);

    let now_mins = now_local.hour() as u32 * 60 + now_local.minute() as u32;
    let from_mins = fh as u32 * 60 + fm as u32;
    let to_mins = th as u32 * 60 + tm as u32;

    let overnight = from_mins > to_mins;
    let in_window = if !overnight {
        now_mins >= from_mins && now_mins < to_mins
    } else {
        now_mins >= from_mins || now_mins < to_mins
    };

    if !in_window {
        return None;
    }

    // Build the local end time, advancing to next day for the evening side of overnight windows.
    let local_date = now_local.date();
    let end_date = if overnight && now_mins >= from_mins {
        local_date.next_day()?
    } else {
        local_date
    };

    let end_time = time::Time::from_hms(th, tm, 0).ok()?;
    let end_primitive = time::PrimitiveDateTime::new(end_date, end_time);
    Some(end_primitive.assume_timezone_utc(tz))
}

/// Queue a failure notification email to the outbox, delayed until `send_after`.
/// Includes a note in the email body so the recipient knows when the failure
/// was actually detected (it may have already resolved by send time).
#[allow(clippy::too_many_arguments)]
async fn queue_failure_email_delayed(
    db: &sea_orm::DatabaseConnection,
    config: &Arc<crate::config::AppConfig>,
    email: &str,
    server_name: &str,
    alert_id: i32,
    failure_count: i32,
    failure_reason: Option<String>,
    detected_at: OffsetDateTime,
    send_after: OffsetDateTime,
) {
    let detected_str = format_email_datetime(detected_at);

    let base = format!("{}/", config.frontend_url.trim_end_matches('/'));
    let check_url = format!("{}results?serverName={}", base, server_name);
    let alert_url = format!("{}alerts/edit/{}", base, alert_id);
    let manage_url = format!("{}alerts", base);
    let unsubscribe_url = format!(
        "{}alerts/unsubscribe?alert_id={}&email={}",
        base,
        alert_id,
        urlencoding::encode(email)
    );
    let sponsor_url = config
        .github_sponsors_url
        .clone()
        .or_else(|| config.liberapay_url.clone());

    let now = OffsetDateTime::now_utc();
    let minutes_down = Some((now - detected_at).whole_minutes().max(0) as u64);
    let first_detected_str = Some(detected_str.clone());

    let reminder_hours = REMINDER_EMAIL_INTERVAL.as_secs() / 3600;
    let reminder_interval_text = format!("{} hours", reminder_hours);

    let template = FailureEmailTemplate {
        server_name: server_name.to_string(),
        check_url,
        failure_count,
        reminder_interval: reminder_interval_text,
        unsubscribe_url,
        failure_reason,
        environment_name: config.environment_name.clone(),
        quiet_hours_note: Some(format!(
            "This failure was detected at {} UTC. It may have already resolved by the time you read this.",
            detected_str
        )),
        first_detected: first_detected_str,
        minutes_down,
        last_healthy: None,
        error_hint: None,
        reminder_total: None,
        alert_url,
        manage_url,
        sponsor_url,
    };

    let html_body = template.render_html().ok();
    let text_body = template.render_text();
    let subject = env_subject(
        &format!("Federation Alert: {server_name} is not healthy"),
        config.environment_name.as_deref(),
    );

    if let Err(e) = email_outbox::enqueue_at(
        db,
        email,
        &subject,
        html_body,
        text_body,
        None,
        Some(send_after),
    )
    .await
    {
        tracing::error!(
            alert_id,
            server_name,
            error = %e,
            "Failed to enqueue quiet-hours failure email"
        );
    }
}

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
    crate::alerts::change_checks::check_change_alerts(&a, &report, resources, now).await;
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
    // Change detection borrows `a`; dispatch consumes it — order matters.
    crate::alerts::change_checks::check_change_alerts(&a, &report, resources, now).await;
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
        registry.remove(a.id).await;
        promote_to_confirmed_failing(a, active, resources, failure_reason, now).await;
    } else {
        // Accumulating confirmation failures — update registry and DB.
        registry.set(a.id, new_count).await;
        let _ = active.update(db).await;
    }
}

async fn promote_to_confirmed_failing(
    a: alert::Model,
    mut active: alert::ActiveModel,
    resources: &AppResources,
    failure_reason: Option<String>,
    now: OffsetDateTime,
) {
    let db = resources.db.as_ref();
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
    if !resources.email_guard.try_claim(a.id, "failure").await {
        return;
    }
    let recipients = get_notification_emails(db, &a).await;
    let any_sent = dispatch_failure_emails(
        resources,
        &a,
        &recipients,
        updated.failure_count,
        failure_reason.clone(),
        now,
    )
    .await;
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

    // Enqueue webhook notifications regardless of whether email was sent.
    let _ = enqueue_for_alert(
        db,
        a.id,
        &a.server_name,
        "federation_down",
        serde_json::json!({
            "failure_count": 1,
            "failure_reason": failure_reason,
        }),
    )
    .await;
}

async fn dispatch_failure_emails(
    resources: &AppResources,
    a: &alert::Model,
    recipients: &[NotificationRecipient],
    failure_count: i32,
    failure_reason: Option<String>,
    now: OffsetDateTime,
) -> bool {
    let db = resources.db.as_ref();
    let mut any_sent = false;
    for r in recipients {
        let wake_at = quiet_hours_end(
            a.quiet_hours_enabled,
            &a.quiet_hours_from,
            &a.quiet_hours_to,
            now,
            &r.timezone,
        );
        if let Some(send_after) = wake_at {
            queue_failure_email_delayed(
                db,
                &resources.config,
                &r.email,
                &a.server_name,
                a.id,
                failure_count,
                failure_reason.clone(),
                now,
                send_after,
            )
            .await;
            any_sent = true;
        } else if let Some(mailer) = &resources.mailer
            && send_failure_email(
                mailer,
                &resources.config,
                &resources.db,
                &r.email,
                &a.server_name,
                a.id,
                failure_count,
                failure_reason.clone(),
                Some(now),
                a.last_success_at,
            )
            .await
            .is_ok()
        {
            any_sent = true;
        }
    }
    any_sent
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
        let recipients = get_notification_emails(db, &a).await;
        let mut any_sent = false;
        for r in &recipients {
            // Skip reminders for recipients currently in their quiet window —
            // the next 12-hour cycle will likely fall outside it.
            let in_quiet = quiet_hours_end(
                a.quiet_hours_enabled,
                &a.quiet_hours_from,
                &a.quiet_hours_to,
                now,
                &r.timezone,
            )
            .is_some();
            if in_quiet {
                continue;
            }
            if send_failure_email(
                mailer,
                &resources.config,
                &resources.db,
                &r.email,
                &a.server_name,
                a.id,
                updated.failure_count,
                failure_reason.clone(),
                a.last_failure_at,
                a.last_success_at,
            )
            .await
            .is_ok()
            {
                any_sent = true;
            }
        }
        let current_failure_count = updated.failure_count;
        if any_sent {
            log_status_event(
                db,
                a.id,
                &a.server_name,
                EVENT_EMAIL_REMINDER,
                false,
                current_failure_count,
                None,
                None,
            )
            .await;
            update_email_sent_at(updated, now, db).await;
        }

        // Enqueue reminder webhooks regardless of email.
        let _ = enqueue_for_alert(
            db,
            a.id,
            &a.server_name,
            "federation_reminder",
            serde_json::json!({
                "failure_count": current_failure_count,
                "failure_reason": failure_reason,
            }),
        )
        .await;
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
        let recipients = get_notification_emails(db, &a).await;
        let mut any_sent = false;
        for r in &recipients {
            if send_recovery_email(
                mailer,
                &resources.config,
                &resources.db,
                &r.email,
                &a.server_name,
                a.id,
                now,
                a.last_success_at,
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

        // Enqueue recovery webhooks regardless of email.
        let _ = enqueue_for_alert(
            db,
            a.id,
            &a.server_name,
            "federation_up",
            serde_json::json!({
                "failure_count": a.failure_count,
            }),
        )
        .await;
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

/// A notification recipient with their timezone for quiet-hours interpretation.
#[derive(Debug, PartialEq)]
pub struct NotificationRecipient {
    pub email: String,
    pub timezone: String,
}

/// Return notification recipients (email + timezone) for an alert.
///
/// For OAuth2 alerts (`user_id` set): queries `alert_notification_email`.
/// Falls back to `alert.email` if the table is empty (e.g. pre-migration row).
/// For legacy magic-link alerts (`user_id` unset): always uses `alert.email`.
pub async fn get_notification_emails(
    db: &sea_orm::DatabaseConnection,
    alert: &alert::Model,
) -> Vec<NotificationRecipient> {
    let emails: Vec<String> = match alert_notification_email::Entity::find()
        .filter(alert_notification_email::Column::AlertId.eq(alert.id))
        .all(db)
        .await
    {
        Ok(rows) if !rows.is_empty() => rows
            .into_iter()
            .map(|r| r.email)
            .filter(|e| !e.is_empty())
            .collect(),
        _ => {
            if alert.email.is_empty() {
                vec![]
            } else {
                vec![alert.email.clone()]
            }
        }
    };

    let mut recipients = Vec::with_capacity(emails.len());
    for email in emails {
        let timezone = get_email_timezone(db, &email).await;
        recipients.push(NotificationRecipient { email, timezone });
    }
    recipients
}

/// Look up the IANA timezone stored for an email address.
///
/// Checks `user_email` first (additional addresses), then `oauth2_user`
/// (primary login email). Falls back to "UTC" if the address is not found.
async fn get_email_timezone(db: &sea_orm::DatabaseConnection, email: &str) -> String {
    if let Ok(Some(row)) = user_email::Entity::find()
        .filter(user_email::Column::Email.eq(email))
        .one(db)
        .await
    {
        return row.timezone;
    }
    if let Ok(Some(row)) = oauth2_user::Entity::find()
        .filter(oauth2_user::Column::Email.eq(email))
        .one(db)
        .await
    {
        return row.timezone;
    }
    "UTC".to_string()
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
pub(crate) async fn log_status_event(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::response::{Error, ErrorCode};
    use time::OffsetDateTime;

    fn base_alert(last_email: Option<OffsetDateTime>) -> alert::Model {
        alert::Model {
            id: 1,
            email: "test@example.com".into(),
            server_name: "example.com".into(),
            verified: true,
            magic_token: None,
            created_at: OffsetDateTime::now_utc(),
            last_check_at: None,
            last_failure_at: None,
            last_success_at: None,
            last_email_sent_at: last_email,
            failure_count: 0,
            is_currently_failing: false,
            last_recovery_at: None,
            user_id: None,
            notify_server_name_change: true,
            notify_version_change: true,
            notify_tls_cert_change: true,
            notify_tls_expiry: true,
            quiet_hours_enabled: false,
            quiet_hours_from: "22:00".into(),
            quiet_hours_to: "07:00".into(),
        }
    }

    fn utc_hms(h: u8, m: u8, s: u8) -> OffsetDateTime {
        time::Date::from_calendar_date(2026, time::Month::January, 1)
            .unwrap()
            .with_hms(h, m, s)
            .unwrap()
            .assume_utc()
    }

    // ── quiet_hours_end ────────────────────────────────────────────────────

    #[test]
    fn quiet_hours_disabled_returns_none() {
        assert!(quiet_hours_end(false, "22:00", "07:00", utc_hms(23, 0, 0), "UTC").is_none());
    }

    #[test]
    fn quiet_hours_outside_overnight_window() {
        // 12:00 is outside 22:00–07:00
        assert!(quiet_hours_end(true, "22:00", "07:00", utc_hms(12, 0, 0), "UTC").is_none());
    }

    #[test]
    fn quiet_hours_inside_overnight_window_evening_side() {
        // 23:00 is inside 22:00–07:00, evening side → wake at 07:00 next day
        let result = quiet_hours_end(true, "22:00", "07:00", utc_hms(23, 0, 0), "UTC");
        assert!(result.is_some());
        let wake = result.unwrap();
        assert_eq!(wake.hour(), 7);
        assert_eq!(wake.minute(), 0);
        // Date should be Jan 2 (next day)
        assert_eq!(wake.day(), 2);
    }

    #[test]
    fn quiet_hours_inside_overnight_window_morning_side() {
        // 03:00 is inside 22:00–07:00, morning side → wake at 07:00 same day
        let result = quiet_hours_end(true, "22:00", "07:00", utc_hms(3, 0, 0), "UTC");
        assert!(result.is_some());
        let wake = result.unwrap();
        assert_eq!(wake.hour(), 7);
        assert_eq!(wake.day(), 1);
    }

    #[test]
    fn quiet_hours_inside_daytime_window() {
        // 14:00 inside 09:00–18:00 (not overnight) → wake at 18:00 same day
        let result = quiet_hours_end(true, "09:00", "18:00", utc_hms(14, 0, 0), "UTC");
        assert!(result.is_some());
        assert_eq!(result.unwrap().hour(), 18);
    }

    #[test]
    fn quiet_hours_outside_daytime_window() {
        // 08:00 is outside 09:00–18:00
        assert!(quiet_hours_end(true, "09:00", "18:00", utc_hms(8, 0, 0), "UTC").is_none());
    }

    #[test]
    fn quiet_hours_invalid_from_returns_none() {
        assert!(quiet_hours_end(true, "nottime", "07:00", utc_hms(23, 0, 0), "UTC").is_none());
    }

    #[test]
    fn quiet_hours_invalid_to_returns_none() {
        assert!(quiet_hours_end(true, "22:00", "nottime", utc_hms(23, 0, 0), "UTC").is_none());
    }

    #[test]
    fn quiet_hours_unknown_timezone_falls_back_to_utc() {
        // Unknown timezone → falls back to UTC; 23:00 is in 22:00–07:00 window
        let result = quiet_hours_end(true, "22:00", "07:00", utc_hms(23, 0, 0), "Not/ATimezone");
        assert!(result.is_some());
    }

    // ── should_send_reminder_email ─────────────────────────────────────────

    #[test]
    fn reminder_true_when_never_sent() {
        assert!(should_send_reminder_email(
            &base_alert(None),
            OffsetDateTime::now_utc()
        ));
    }

    #[test]
    fn reminder_true_when_sent_more_than_12h_ago() {
        let sent = OffsetDateTime::now_utc() - time::Duration::hours(13);
        assert!(should_send_reminder_email(
            &base_alert(Some(sent)),
            OffsetDateTime::now_utc()
        ));
    }

    #[test]
    fn reminder_false_when_sent_less_than_12h_ago() {
        let sent = OffsetDateTime::now_utc() - time::Duration::hours(1);
        assert!(!should_send_reminder_email(
            &base_alert(Some(sent)),
            OffsetDateTime::now_utc()
        ));
    }

    #[test]
    fn reminder_true_when_exactly_at_12h_boundary() {
        // exactly 12 h ago: elapsed >= interval → true
        let sent = OffsetDateTime::now_utc() - time::Duration::hours(12);
        assert!(should_send_reminder_email(
            &base_alert(Some(sent)),
            OffsetDateTime::now_utc()
        ));
    }

    // ── extract_failure_reason ─────────────────────────────────────────────

    #[test]
    fn failure_reason_none_when_no_errors() {
        assert!(extract_failure_reason(&Root::default()).is_none());
    }

    #[test]
    fn failure_reason_returns_top_level_error() {
        let r = Root {
            error: Some(Error {
                error: "Invalid server name".into(),
                error_code: ErrorCode::Unknown,
            }),
            ..Root::default()
        };
        assert_eq!(
            extract_failure_reason(&r).as_deref(),
            Some("Invalid server name")
        );
    }

    #[test]
    fn failure_reason_returns_connection_error_when_no_top_level() {
        let mut r = Root::default();
        r.connection_errors.insert(
            "1.2.3.4:8448".into(),
            Error {
                error: "Connection refused".into(),
                error_code: ErrorCode::Unknown,
            },
        );
        assert_eq!(
            extract_failure_reason(&r).as_deref(),
            Some("Connection refused")
        );
    }

    #[test]
    fn failure_reason_prefers_top_level_over_connection_error() {
        let mut r = Root {
            error: Some(Error {
                error: "Top level".into(),
                error_code: ErrorCode::Unknown,
            }),
            ..Root::default()
        };
        r.connection_errors.insert(
            "addr".into(),
            Error {
                error: "Connection".into(),
                error_code: ErrorCode::Unknown,
            },
        );
        assert_eq!(extract_failure_reason(&r).as_deref(), Some("Top level"));
    }

    // ── get_notification_emails with SQLite ────────────────────────────────

    async fn create_test_db() -> Arc<sea_orm::DatabaseConnection> {
        use migration::MigratorTrait;
        let db = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
        migration::Migrator::up(&db, None).await.unwrap();
        Arc::new(db)
    }

    #[tokio::test]
    async fn get_notification_emails_empty_alert() {
        let db = create_test_db().await;
        let alert = base_alert(None);
        let recipients = get_notification_emails(&db, &alert).await;
        // alert.email is "test@example.com" and no notification_email rows → falls back to alert.email
        assert_eq!(recipients.len(), 1);
        assert_eq!(recipients[0].email, "test@example.com");
        assert_eq!(recipients[0].timezone, "UTC");
    }

    #[tokio::test]
    async fn get_notification_emails_empty_email_returns_empty() {
        let db = create_test_db().await;
        let mut alert = base_alert(None);
        alert.email = "".into();
        let recipients = get_notification_emails(&db, &alert).await;
        assert!(recipients.is_empty());
    }

    #[tokio::test]
    async fn get_notification_emails_uses_oauth2_user_timezone() {
        use sea_orm::{ConnectionTrait, DbBackend, Statement};
        let db = create_test_db().await;
        // Insert oauth2_user with non-UTC timezone
        db.execute(Statement::from_string(
            DbBackend::Sqlite,
            r#"INSERT INTO oauth2_user (id, email, email_verified, name, receives_alerts, created_at, timezone)
               VALUES ('u1', 'tz@example.com', 1, NULL, 1, datetime('now'), 'Europe/Berlin');"#,
        ))
        .await
        .unwrap();

        let mut alert = base_alert(None);
        alert.email = "tz@example.com".into();
        let recipients = get_notification_emails(&db, &alert).await;
        assert_eq!(recipients.len(), 1);
        assert_eq!(recipients[0].timezone, "Europe/Berlin");
    }
}
