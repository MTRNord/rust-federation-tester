//! Change-detection alert logic.
//!
//! Runs after every successful `generate_json_report` call in both check loops.
//! Compares the current report against the last stored observation and sends
//! per-type notification emails when a tracked value changes.
//!
//! Each alert has four opt-in boolean flags (all default `false` in the DB so
//! existing alerts are unaffected):
//!
//! - `notify_server_name_change` — self-reported name or well-known target
//! - `notify_version_change` — software name or version string
//! - `notify_tls_cert_change` — set of TLS cert SHA-256 fingerprints
//! - `notify_tls_expiry` — cert expiry within 14 days (at most once per 24 h)

use crate::AppResources;
use crate::alerts::checks::{get_notification_emails, log_status_event};
use crate::alerts::email::{
    send_server_name_change_email, send_tls_cert_change_email, send_tls_expiry_email,
    send_version_change_email,
};
use crate::entity::{alert, alert_observed_state};
use crate::response::{Certificate, Root};
use sea_orm::{ActiveModelTrait, ActiveValue, EntityTrait};
use std::collections::{HashMap, HashSet};
use time::OffsetDateTime;

const TLS_EXPIRY_WARNING_DAYS: i64 = 14;
const TLS_EXPIRY_EMAIL_THROTTLE_HOURS: i64 = 24;

const EVENT_SERVER_NAME_CHANGE: &str = "server_name_change";
const EVENT_VERSION_CHANGE: &str = "version_change";
const EVENT_TLS_CERT_CHANGE: &str = "tls_cert_change";
const EVENT_TLS_EXPIRY: &str = "tls_expiry_warning";

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Run change-detection checks for a single alert after obtaining a report.
///
/// Compares the current `report` against the stored observation for this alert.
/// On the first call (no stored state), the current values are recorded and no
/// emails are sent. On subsequent calls, emails are sent for each changed
/// dimension that the alert has opted into.
///
/// This function is infallible at the call site: all errors are logged
/// internally and swallowed so the existing fail/recovery state machine is
/// never disrupted.
pub async fn check_change_alerts(
    a: &alert::Model,
    report: &Root,
    resources: &AppResources,
    now: OffsetDateTime,
) {
    // Skip entirely when the report contains no usable data.
    if report.version.name.is_empty()
        && report.version.version.is_empty()
        && report.connection_reports.is_empty()
    {
        return;
    }

    let current = extract_current_state(report);
    let db = resources.db.as_ref();

    let prev = match alert_observed_state::Entity::find_by_id(a.id).one(db).await {
        Ok(Some(p)) => p,
        Ok(None) => {
            // First observation: store and return without sending emails.
            insert_initial_state(db, a.id, &current, now).await;
            return;
        }
        Err(e) => {
            tracing::error!(
                name = "alerts.change_checks.db_error",
                target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                error = %e,
                alert_id = a.id,
                message = "DB error reading alert_observed_state"
            );
            return;
        }
    };

    // Run each check helper. check_tls_expiry returns Some(now) if it sent an
    // email so we can persist last_tls_expiry_email_at.
    let expiry_email_at = check_tls_expiry(a, &prev, &current, resources, now).await;
    check_server_name_change(a, &prev, &current, resources, now).await;
    check_version_change(a, &prev, &current, resources, now).await;
    check_tls_cert_change(a, &prev, &current, resources, now).await;

    // Persist updated observed state.
    let mut update: alert_observed_state::ActiveModel = prev.clone().into();
    update.server_name_seen = ActiveValue::Set(current.server_name.clone());
    update.well_known_seen = ActiveValue::Set(current.well_known_json.clone());
    update.version_name_seen = ActiveValue::Set(Some(current.version_name.clone()));
    update.version_string_seen = ActiveValue::Set(Some(current.version_string.clone()));
    update.tls_fingerprints_seen = ActiveValue::Set(current.fingerprints_json.clone());
    update.tls_earliest_expiry_at = ActiveValue::Set(current.earliest_expiry);
    update.last_tls_expiry_email_at =
        ActiveValue::Set(expiry_email_at.or(prev.last_tls_expiry_email_at));
    update.observed_at = ActiveValue::Set(now);

    if let Err(e) = update.update(db).await {
        tracing::error!(
            name = "alerts.change_checks.update_error",
            target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            error = %e,
            alert_id = a.id,
            message = "Failed to update alert_observed_state"
        );
    }
}

// ---------------------------------------------------------------------------
// Current state extraction
// ---------------------------------------------------------------------------

struct CurrentState {
    server_name: Option<String>,
    well_known_json: Option<String>,
    version_name: String,
    version_string: String,
    fingerprints_json: Option<String>,
    /// Sorted, deduplicated fingerprint set for comparison.
    fingerprints: Vec<String>,
    /// Sorted, deduplicated well-known targets for comparison.
    well_known: Vec<String>,
    earliest_expiry: Option<OffsetDateTime>,
    /// Cert details keyed by SHA-256 fingerprint for the current probe.
    cert_details: HashMap<String, Certificate>,
}

fn extract_current_state(report: &Root) -> CurrentState {
    let server_name = report
        .connection_reports
        .values()
        .map(|r| r.keys.server_name.clone())
        .find(|s| !s.is_empty());

    let mut well_known: Vec<String> = report
        .well_known_result
        .values()
        .map(|w| w.m_server.clone())
        .filter(|s| !s.is_empty())
        .collect();
    well_known.sort();
    well_known.dedup();

    let well_known_json = if well_known.is_empty() {
        None
    } else {
        serde_json::to_string(&well_known).ok()
    };

    let cert_details: HashMap<String, Certificate> = report
        .connection_reports
        .values()
        .flat_map(|r| r.certificates.iter())
        .filter(|c| !c.sha256fingerprint.is_empty())
        .map(|c| (c.sha256fingerprint.clone(), c.clone()))
        .collect();

    let mut fingerprints: Vec<String> = cert_details.keys().cloned().collect();
    fingerprints.sort();
    fingerprints.dedup();

    let fingerprints_json = if fingerprints.is_empty() {
        None
    } else {
        serde_json::to_string(&fingerprints).ok()
    };

    let earliest_expiry = report
        .connection_reports
        .values()
        .flat_map(|r| r.certificates.iter().filter_map(|c| c.not_after))
        .min();

    CurrentState {
        server_name,
        well_known_json,
        version_name: report.version.name.clone(),
        version_string: report.version.version.clone(),
        fingerprints_json,
        fingerprints,
        well_known,
        earliest_expiry,
        cert_details,
    }
}

// ---------------------------------------------------------------------------
// First-run insert
// ---------------------------------------------------------------------------

async fn insert_initial_state(
    db: &sea_orm::DatabaseConnection,
    alert_id: i32,
    current: &CurrentState,
    now: OffsetDateTime,
) {
    let model = alert_observed_state::ActiveModel {
        alert_id: ActiveValue::Set(alert_id),
        server_name_seen: ActiveValue::Set(current.server_name.clone()),
        well_known_seen: ActiveValue::Set(current.well_known_json.clone()),
        version_name_seen: ActiveValue::Set(Some(current.version_name.clone())),
        version_string_seen: ActiveValue::Set(Some(current.version_string.clone())),
        tls_fingerprints_seen: ActiveValue::Set(current.fingerprints_json.clone()),
        tls_earliest_expiry_at: ActiveValue::Set(current.earliest_expiry),
        last_tls_expiry_email_at: ActiveValue::Set(None),
        observed_at: ActiveValue::Set(now),
    };
    if let Err(e) = model.insert(db).await {
        tracing::error!(
            name = "alerts.change_checks.insert_error",
            target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            error = %e,
            alert_id = alert_id,
            message = "Failed to insert initial alert_observed_state"
        );
    }
}

// ---------------------------------------------------------------------------
// Per-dimension helpers
// ---------------------------------------------------------------------------

async fn check_server_name_change(
    a: &alert::Model,
    prev: &alert_observed_state::Model,
    current: &CurrentState,
    resources: &AppResources,
    now: OffsetDateTime,
) {
    if !a.notify_server_name_change {
        return;
    }

    let name_changed = current.server_name.as_deref() != prev.server_name_seen.as_deref()
        && current.server_name.is_some()
        && prev.server_name_seen.is_some();

    let prev_well_known = deserialize_json_array(prev.well_known_seen.as_deref());
    let well_known_changed = current.well_known != prev_well_known
        && (!current.well_known.is_empty() || !prev_well_known.is_empty());

    if !name_changed && !well_known_changed {
        return;
    }

    let db = resources.db.as_ref();
    log_status_event(
        db,
        a.id,
        &a.server_name,
        EVENT_SERVER_NAME_CHANGE,
        true,
        0,
        Some(format!(
            "name_changed={name_changed} well_known_changed={well_known_changed}"
        )),
        None,
    )
    .await;

    let Some(mailer) = &resources.mailer else {
        return;
    };
    if !resources
        .email_guard
        .try_claim(a.id, "server_name_change")
        .await
    {
        return;
    }

    let old_delegation = prev_well_known
        .first()
        .cloned()
        .or_else(|| prev.server_name_seen.clone())
        .unwrap_or_else(|| a.server_name.clone());
    let old_method = if !prev_well_known.is_empty() {
        "well-known".to_string()
    } else {
        "direct / SRV".to_string()
    };
    let new_delegation = current
        .well_known
        .first()
        .cloned()
        .or_else(|| current.server_name.clone())
        .unwrap_or_else(|| a.server_name.clone());
    let new_method = if !current.well_known.is_empty() {
        "well-known".to_string()
    } else {
        "direct / SRV".to_string()
    };

    let recipients = get_notification_emails(db, a).await;
    for email in recipients.iter().map(|r| r.email.as_str()) {
        if let Err(e) = send_server_name_change_email(
            mailer,
            &resources.config,
            &resources.db,
            email,
            &a.server_name,
            a.id,
            old_delegation.clone(),
            old_method.clone(),
            new_delegation.clone(),
            new_method.clone(),
            current.version_name.clone(),
            current.version_string.clone(),
            "healthy".to_string(),
            now,
        )
        .await
        {
            tracing::error!(
                name = "alerts.change_checks.server_name_email_failed",
                target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                error = %e,
                alert_id = a.id,
                message = "Failed to send server_name_change email"
            );
        }
    }

    tracing::info!(
        name = "alerts.change_checks.server_name_changed",
        target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
        alert_id = a.id,
        server_name = %a.server_name,
        name_changed = name_changed,
        well_known_changed = well_known_changed,
        message = "Server name change detected and notified"
    );

    let _ = now; // used in caller for state update
}

async fn check_version_change(
    a: &alert::Model,
    prev: &alert_observed_state::Model,
    current: &CurrentState,
    resources: &AppResources,
    now: OffsetDateTime,
) {
    if !a.notify_version_change {
        return;
    }
    if current.version_name.is_empty() && current.version_string.is_empty() {
        return;
    }

    let old_name = prev.version_name_seen.clone().unwrap_or_default();
    let old_ver = prev.version_string_seen.clone().unwrap_or_default();

    // Skip if there was no prior version recorded.
    if old_name.is_empty() && old_ver.is_empty() {
        return;
    }

    if current.version_name == old_name && current.version_string == old_ver {
        return;
    }

    let db = resources.db.as_ref();
    log_status_event(
        db,
        a.id,
        &a.server_name,
        EVENT_VERSION_CHANGE,
        true,
        0,
        Some(format!(
            "{} {} -> {} {}",
            old_name, old_ver, current.version_name, current.version_string
        )),
        None,
    )
    .await;

    let Some(mailer) = &resources.mailer else {
        return;
    };
    if !resources
        .email_guard
        .try_claim(a.id, "version_change")
        .await
    {
        return;
    }

    let recipients = get_notification_emails(db, a).await;
    for email in recipients.iter().map(|r| r.email.as_str()) {
        if let Err(e) = send_version_change_email(
            mailer,
            &resources.config,
            &resources.db,
            &resources.release_cache,
            email,
            &a.server_name,
            a.id,
            old_name.clone(),
            old_ver.clone(),
            current.version_name.clone(),
            current.version_string.clone(),
            now,
        )
        .await
        {
            tracing::error!(
                name = "alerts.change_checks.version_email_failed",
                target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                error = %e,
                alert_id = a.id,
                message = "Failed to send version_change email"
            );
        }
    }

    tracing::info!(
        name = "alerts.change_checks.version_changed",
        target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
        alert_id = a.id,
        server_name = %a.server_name,
        old = %format!("{old_name} {old_ver}"),
        new = %format!("{} {}", current.version_name, current.version_string),
        message = "Version change detected and notified"
    );

    let _ = now;
}

async fn check_tls_cert_change(
    a: &alert::Model,
    prev: &alert_observed_state::Model,
    current: &CurrentState,
    resources: &AppResources,
    now: OffsetDateTime,
) {
    if !a.notify_tls_cert_change {
        return;
    }
    if current.fingerprints.is_empty() {
        return;
    }

    let prev_fps = deserialize_json_array(prev.tls_fingerprints_seen.as_deref());
    if prev_fps.is_empty() {
        return; // no prior state to compare against
    }

    let current_set: HashSet<&str> = current.fingerprints.iter().map(|s| s.as_str()).collect();
    let prev_set: HashSet<&str> = prev_fps.iter().map(|s| s.as_str()).collect();

    if current_set == prev_set {
        return;
    }

    let mut added: Vec<String> = current_set
        .difference(&prev_set)
        .map(|s| s.to_string())
        .collect();
    let mut removed: Vec<String> = prev_set
        .difference(&current_set)
        .map(|s| s.to_string())
        .collect();
    added.sort();
    removed.sort();

    let db = resources.db.as_ref();
    log_status_event(
        db,
        a.id,
        &a.server_name,
        EVENT_TLS_CERT_CHANGE,
        true,
        0,
        Some(format!("added={} removed={}", added.len(), removed.len())),
        None,
    )
    .await;

    let Some(mailer) = &resources.mailer else {
        return;
    };
    if !resources
        .email_guard
        .try_claim(a.id, "tls_cert_change")
        .await
    {
        return;
    }

    // Look up full cert details for the first added fingerprint.
    let new_cert = added
        .first()
        .and_then(|fp| current.cert_details.get(fp))
        .cloned();

    let recipients = get_notification_emails(db, a).await;
    for email in recipients.iter().map(|r| r.email.as_str()) {
        if let Err(e) = send_tls_cert_change_email(
            mailer,
            &resources.config,
            &resources.db,
            email,
            &a.server_name,
            a.id,
            added.clone(),
            removed.clone(),
            now,
            new_cert.clone(),
        )
        .await
        {
            tracing::error!(
                name = "alerts.change_checks.tls_cert_email_failed",
                target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                error = %e,
                alert_id = a.id,
                message = "Failed to send tls_cert_change email"
            );
        }
    }

    tracing::info!(
        name = "alerts.change_checks.tls_cert_changed",
        target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
        alert_id = a.id,
        server_name = %a.server_name,
        added = added.len(),
        removed = removed.len(),
        message = "TLS cert change detected and notified"
    );
}

/// Returns `Some(now)` if a TLS expiry warning email was sent this cycle.
async fn check_tls_expiry(
    a: &alert::Model,
    prev: &alert_observed_state::Model,
    current: &CurrentState,
    resources: &AppResources,
    now: OffsetDateTime,
) -> Option<OffsetDateTime> {
    if !a.notify_tls_expiry {
        return None;
    }
    let expiry = current.earliest_expiry?;
    let days_remaining = (expiry - now).whole_days();

    // Find the cert that expires soonest (to populate cert details in the email).
    let expiring_cert = current
        .cert_details
        .values()
        .filter(|c| c.not_after.is_some())
        .min_by_key(|c| c.not_after.unwrap());

    if days_remaining > TLS_EXPIRY_WARNING_DAYS {
        return None;
    }

    // 24-hour application-level throttle.
    if let Some(last) = prev.last_tls_expiry_email_at
        && (now - last).whole_hours() < TLS_EXPIRY_EMAIL_THROTTLE_HOURS
    {
        return None;
    }

    let db = resources.db.as_ref();
    log_status_event(
        db,
        a.id,
        &a.server_name,
        EVENT_TLS_EXPIRY,
        true,
        0,
        Some(format!("days_remaining={days_remaining}")),
        None,
    )
    .await;

    let mailer = resources.mailer.as_ref()?;
    if !resources
        .email_guard
        .try_claim(a.id, "tls_expiry_warning")
        .await
    {
        return None;
    }

    let recipients = get_notification_emails(db, a).await;
    let mut any_sent = false;
    for email in recipients.iter().map(|r| r.email.as_str()) {
        if send_tls_expiry_email(
            mailer,
            &resources.config,
            &resources.db,
            email,
            &a.server_name,
            a.id,
            expiry,
            days_remaining,
            expiring_cert,
        )
        .await
        .is_ok()
        {
            any_sent = true;
        }
    }

    if any_sent {
        tracing::info!(
            name = "alerts.change_checks.tls_expiry_warned",
            target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            alert_id = a.id,
            server_name = %a.server_name,
            days_remaining = days_remaining,
            message = "TLS expiry warning sent"
        );
        Some(now)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn deserialize_json_array(json: Option<&str>) -> Vec<String> {
    json.and_then(|s| serde_json::from_str::<Vec<String>>(s).ok())
        .unwrap_or_default()
}
