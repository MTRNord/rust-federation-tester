//! Email sending for alert notifications.
//!
//! Handles sending failure and recovery notification emails.

use crate::api::alerts::MagicClaims;
use crate::email_templates::{
    FailureEmailTemplate, RecoveryEmailTemplate, ServerNameChangeEmailTemplate,
    TlsCertChangeEmailTemplate, TlsExpiryEmailTemplate, VersionChangeEmailTemplate, env_subject,
};
use crate::entity::email_log;
use crate::release_notes::{ReleaseCache, get_release_info};
use jsonwebtoken::{EncodingKey, Header as JwtHeader, encode};
use lettre::AsyncTransport;
use lettre::message::header::{Header, HeaderName, HeaderValue};
use lettre::message::{MultiPart, SinglePart};
use sea_orm::{ActiveModelTrait, ActiveValue};
use std::sync::Arc;
use time::OffsetDateTime;
use tokio::time::Duration;
use tracing::info;

/// Email sending policy configuration - reminder interval.
pub const REMINDER_EMAIL_INTERVAL: Duration = Duration::from_secs(12 * 3600); // 12 hours

/// Return `url` with exactly one trailing slash.
///
/// Prevents double-slash URLs when the configured `frontend_url` already
/// ends with `/` and it is concatenated with a path segment.
fn frontend_base(url: &str) -> String {
    format!("{}/", url.trim_end_matches('/'))
}

/// Format a UTC timestamp for email display: `2026-05-19 09:59 UTC`.
/// Strips sub-second precision and the ISO-8601 `T` separator for readability.
pub(crate) fn format_email_datetime(dt: time::OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02} UTC",
        dt.year(),
        dt.month() as u8,
        dt.day(),
        dt.hour(),
        dt.minute()
    )
}

fn format_downtime(minutes: u64) -> String {
    if minutes < 60 {
        format!("{} min", minutes)
    } else {
        let h = minutes / 60;
        let m = minutes % 60;
        if m == 0 {
            format!("{}h", h)
        } else {
            format!("{}h {}m", h, m)
        }
    }
}

/// Error type for email sending operations.
#[derive(Debug, thiserror::Error)]
pub enum EmailError {
    #[error("Invalid email address '{address}': {detail}")]
    InvalidAddress { address: String, detail: String },
    #[error("Failed to render email template: {0}")]
    TemplateFailed(String),
    #[error("Failed to build email message: {0}")]
    BuildFailed(#[from] lettre::error::Error),
    #[error("SMTP transport error: {0}")]
    SendFailed(#[from] lettre::transport::smtp::Error),
}

/// Send a failure notification email.
#[allow(clippy::too_many_arguments)]
#[tracing::instrument(skip(mailer, config, db, email))]
pub async fn send_failure_email(
    mailer: &Arc<lettre::AsyncSmtpTransport<lettre::Tokio1Executor>>,
    config: &Arc<crate::config::AppConfig>,
    db: &Arc<sea_orm::DatabaseConnection>,
    email: &str,
    server_name: &str,
    alert_id: i32,
    failure_count: i32,
    failure_reason: Option<String>,
    first_detected: Option<time::OffsetDateTime>,
    last_healthy: Option<time::OffsetDateTime>,
) -> Result<(), EmailError> {
    let base = frontend_base(&config.frontend_url);
    let check_url = format!("{}results?serverName={}", base, server_name);
    let alert_url = format!("{}alerts/edit/{}", base, alert_id);
    let manage_url = format!("{}alerts", base);
    let sponsor_url = config
        .github_sponsors_url
        .clone()
        .or_else(|| config.liberapay_url.clone());

    let now = time::OffsetDateTime::now_utc();
    let (first_detected_str, minutes_down) = if let Some(t) = first_detected {
        let mins = (now - t).whole_minutes().max(0) as u64;
        (Some(format_email_datetime(t)), Some(mins))
    } else {
        (None, None)
    };
    let last_healthy_str = last_healthy.map(format_email_datetime);

    // Convert REMINDER_EMAIL_INTERVAL to hours for display
    let reminder_hours = REMINDER_EMAIL_INTERVAL.as_secs() / 3600;
    let reminder_interval_text = if reminder_hours >= 24 {
        let days = reminder_hours / 24;
        if days == 1 {
            "24 hours".to_string()
        } else {
            format!("{} days", days)
        }
    } else if reminder_hours == 1 {
        "1 hour".to_string()
    } else {
        format!("{} hours", reminder_hours)
    };

    let unsubscribe_url = generate_list_unsubscribe_url(
        &config.magic_token_secret,
        email,
        server_name,
        alert_id,
        &config.frontend_url,
    );

    let template = FailureEmailTemplate {
        server_name: server_name.to_string(),
        check_url: check_url.clone(),
        failure_count,
        reminder_interval: reminder_interval_text,
        unsubscribe_url: unsubscribe_url.clone(),
        failure_reason,
        environment_name: config.environment_name.clone(),
        quiet_hours_note: None,
        first_detected: first_detected_str,
        minutes_down,
        last_healthy: last_healthy_str,
        error_hint: None,
        reminder_total: None,
        alert_url,
        manage_url,
        sponsor_url,
    };

    let subject = env_subject(
        &format!("Federation Alert: {server_name} is not healthy"),
        config.environment_name.as_deref(),
    );

    // Render both HTML and plain text versions
    let html_body = match template.render_html() {
        Ok(html) => html,
        Err(e) => {
            tracing::error!(
                name = "alerts.send_failure_email.template_render_failed",
                target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                error = %e,
                server_name = %server_name,
                alert_id = alert_id,
                message = "Failed to render HTML email template"
            );
            return Err(EmailError::TemplateFailed(e.to_string()));
        }
    };
    let text_body = template.render_text();

    let from_mailbox: lettre::message::Mailbox = config.smtp.from.parse().map_err(|e| {
        tracing::error!(
            name = "alerts.send_failure_email.invalid_from_address",
            target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            address = %config.smtp.from,
            message = "Invalid SMTP from address in configuration"
        );
        EmailError::InvalidAddress {
            address: config.smtp.from.clone(),
            detail: format!("{e}"),
        }
    })?;

    let to_mailbox: lettre::message::Mailbox = email.parse().map_err(|e| {
        tracing::error!(
            name = "alerts.send_failure_email.invalid_to_address",
            target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            alert_id = alert_id,
            message = "Invalid recipient email address"
        );
        EmailError::InvalidAddress {
            address: email.to_string(),
            detail: format!("{e}"),
        }
    })?;

    // Create multipart email with both HTML and plain text
    let email_msg = lettre::Message::builder()
        .from(from_mailbox)
        .to(to_mailbox)
        .subject(subject)
        .header(lettre::message::header::MIME_VERSION_1_0)
        .header(UnsubscribeHeader::from(unsubscribe_url))
        .message_id(None)
        .multipart(
            MultiPart::alternative()
                .singlepart(
                    SinglePart::builder()
                        .header(lettre::message::header::ContentType::TEXT_PLAIN)
                        .body(text_body),
                )
                .singlepart(
                    SinglePart::builder()
                        .header(lettre::message::header::ContentType::TEXT_HTML)
                        .body(html_body),
                ),
        )
        .map_err(EmailError::BuildFailed)?;

    mailer.send(email_msg).await.map_err(|e| {
        tracing::error!(
            name = "alerts.send_failure_email.email_send_failed",
            target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            error = %e,
            server_name = %server_name,
            alert_id = alert_id,
            message = "Failed to send failure alert email"
        );
        EmailError::SendFailed(e)
    })?;

    info!(
        target: "rust-federation-tester",
        "Sent failure alert email #{} to {} for server {}",
        failure_count, email, server_name
    );

    // Log the email to database
    let email_log_entry = email_log::ActiveModel {
        id: ActiveValue::NotSet,
        alert_id: ActiveValue::Set(alert_id),
        email: ActiveValue::Set(email.to_string()),
        server_name: ActiveValue::Set(server_name.to_string()),
        email_type: ActiveValue::Set("failure".to_string()),
        sent_at: ActiveValue::Set(OffsetDateTime::now_utc()),
        failure_count: ActiveValue::Set(Some(failure_count)),
    };

    if let Err(e) = email_log_entry.insert(db.as_ref()).await {
        tracing::error!(
            name = "alerts.send_failure_email.log_insert_failed",
            target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            error = %e,
            server_name = %server_name,
            alert_id = alert_id,
            message = "Failed to log failure email to database"
        );
    }

    Ok(())
}

/// Send a recovery notification email.
#[allow(clippy::too_many_arguments)]
#[tracing::instrument(skip(mailer, config, db, email))]
pub async fn send_recovery_email(
    mailer: &Arc<lettre::AsyncSmtpTransport<lettre::Tokio1Executor>>,
    config: &Arc<crate::config::AppConfig>,
    db: &Arc<sea_orm::DatabaseConnection>,
    email: &str,
    server_name: &str,
    alert_id: i32,
    recovered_at: time::OffsetDateTime,
    first_detected: Option<time::OffsetDateTime>,
) -> Result<(), EmailError> {
    let base = frontend_base(&config.frontend_url);
    let check_url = format!("{}results?serverName={}", base, server_name);
    let manage_url = format!("{}alerts", base);
    let sponsor_url = config
        .github_sponsors_url
        .clone()
        .or_else(|| config.liberapay_url.clone());

    let recovered_at_str = format_email_datetime(recovered_at);

    let (first_detected_str, minutes_down, downtime_human) = if let Some(fd) = first_detected {
        let mins = (recovered_at - fd).whole_minutes().max(0) as u64;
        let human = format_downtime(mins);
        (Some(format_email_datetime(fd)), Some(mins), Some(human))
    } else {
        (None, None, None)
    };

    let unsubscribe_url = generate_list_unsubscribe_url(
        &config.magic_token_secret,
        email,
        server_name,
        alert_id,
        &config.frontend_url,
    );

    let template = RecoveryEmailTemplate {
        server_name: server_name.to_string(),
        check_url: check_url.clone(),
        unsubscribe_url: unsubscribe_url.clone(),
        environment_name: config.environment_name.clone(),
        recovered_at: Some(recovered_at_str),
        first_detected: first_detected_str,
        minutes_down,
        downtime_human,
        recovery_signal: None,
        recovery_hint: None,
        manage_url,
        sponsor_url,
    };

    let subject = env_subject(
        &format!("Federation Alert: {server_name} has recovered!"),
        config.environment_name.as_deref(),
    );

    // Render both HTML and plain text versions
    let html_body = match template.render_html() {
        Ok(html) => html,
        Err(e) => {
            tracing::error!(
                name = "alerts.send_recovery_email.template_render_failed",
                target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                error = %e,
                server_name = %server_name,
                alert_id = alert_id,
                message = "Failed to render HTML email template for recovery"
            );
            return Err(EmailError::TemplateFailed(e.to_string()));
        }
    };
    let text_body = template.render_text();

    let from_mailbox: lettre::message::Mailbox = config.smtp.from.parse().map_err(|e| {
        tracing::error!(
            name = "alerts.send_recovery_email.invalid_from_address",
            target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            address = %config.smtp.from,
            message = "Invalid SMTP from address in configuration"
        );
        EmailError::InvalidAddress {
            address: config.smtp.from.clone(),
            detail: format!("{e}"),
        }
    })?;

    let to_mailbox: lettre::message::Mailbox = email.parse().map_err(|e| {
        tracing::error!(
            name = "alerts.send_recovery_email.invalid_to_address",
            target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            alert_id = alert_id,
            message = "Invalid recipient email address"
        );
        EmailError::InvalidAddress {
            address: email.to_string(),
            detail: format!("{e}"),
        }
    })?;

    // Create multipart email with both HTML and plain text
    let email_msg = lettre::Message::builder()
        .from(from_mailbox)
        .to(to_mailbox)
        .subject(subject)
        .header(lettre::message::header::MIME_VERSION_1_0)
        .header(UnsubscribeHeader::from(unsubscribe_url))
        .message_id(None)
        .multipart(
            MultiPart::alternative()
                .singlepart(
                    SinglePart::builder()
                        .header(lettre::message::header::ContentType::TEXT_PLAIN)
                        .body(text_body),
                )
                .singlepart(
                    SinglePart::builder()
                        .header(lettre::message::header::ContentType::TEXT_HTML)
                        .body(html_body),
                ),
        )
        .map_err(EmailError::BuildFailed)?;

    mailer.send(email_msg).await.map_err(|e| {
        tracing::error!(
            name = "alerts.send_recovery_email.email_send_failed",
            target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            error = %e,
            server_name = %server_name,
            alert_id = alert_id,
            message = "Failed to send recovery email"
        );
        EmailError::SendFailed(e)
    })?;

    info!(
        "Sent recovery email to {} for server {}",
        email, server_name
    );

    // Log the email to database
    let email_log_entry = email_log::ActiveModel {
        id: ActiveValue::NotSet,
        alert_id: ActiveValue::Set(alert_id),
        email: ActiveValue::Set(email.to_string()),
        server_name: ActiveValue::Set(server_name.to_string()),
        email_type: ActiveValue::Set("recovery".to_string()),
        sent_at: ActiveValue::Set(OffsetDateTime::now_utc()),
        failure_count: ActiveValue::NotSet,
    };

    if let Err(e) = email_log_entry.insert(db.as_ref()).await {
        tracing::error!(
            name = "alerts.send_recovery_email.log_insert_failed",
            target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            error = %e,
            server_name = %server_name,
            alert_id = alert_id,
            message = "Failed to log recovery email to database"
        );
    }

    Ok(())
}

/// Send a server name change notification email.
#[allow(clippy::too_many_arguments)]
#[tracing::instrument(skip(mailer, config, db, email))]
pub async fn send_server_name_change_email(
    mailer: &Arc<lettre::AsyncSmtpTransport<lettre::Tokio1Executor>>,
    config: &Arc<crate::config::AppConfig>,
    db: &Arc<sea_orm::DatabaseConnection>,
    email: &str,
    server_name: &str,
    alert_id: i32,
    old_delegation_target: String,
    old_resolution_method: String,
    new_delegation_target: String,
    new_resolution_method: String,
    server_software: String,
    server_version: String,
    federation_status: String,
    detected_at: time::OffsetDateTime,
) -> Result<(), EmailError> {
    let check_url = format!(
        "{}results?serverName={}",
        frontend_base(&config.frontend_url),
        server_name
    );
    let unsubscribe_url = generate_list_unsubscribe_url(
        &config.magic_token_secret,
        email,
        server_name,
        alert_id,
        &config.frontend_url,
    );
    let manage_url = format!("{}alerts", frontend_base(&config.frontend_url));
    let sponsor_url = config
        .github_sponsors_url
        .clone()
        .or_else(|| config.liberapay_url.clone());
    let detected_at_str = format_email_datetime(detected_at);

    let template = ServerNameChangeEmailTemplate {
        server_name: server_name.to_string(),
        environment_name: config.environment_name.clone(),
        detected_at: detected_at_str,
        old_delegation_target,
        old_resolution_method,
        new_delegation_target,
        new_resolution_method,
        server_software,
        server_version,
        federation_status,
        check_url,
        unsubscribe_url: unsubscribe_url.clone(),
        manage_url,
        sponsor_url,
    };

    let subject = env_subject(
        &format!("Federation Alert: delegation changed for {server_name}"),
        config.environment_name.as_deref(),
    );

    send_change_email(
        mailer,
        config,
        db,
        email,
        server_name,
        alert_id,
        subject,
        &template,
    )
    .await
}

/// Send a version change notification email.
#[allow(clippy::too_many_arguments)]
#[tracing::instrument(skip(mailer, config, db, email, release_cache))]
pub async fn send_version_change_email(
    mailer: &Arc<lettre::AsyncSmtpTransport<lettre::Tokio1Executor>>,
    config: &Arc<crate::config::AppConfig>,
    db: &Arc<sea_orm::DatabaseConnection>,
    release_cache: &ReleaseCache,
    email: &str,
    server_name: &str,
    alert_id: i32,
    old_version_name: String,
    old_version_string: String,
    new_version_name: String,
    new_version_string: String,
    detected_at: time::OffsetDateTime,
) -> Result<(), EmailError> {
    let check_url = format!(
        "{}results?serverName={}",
        frontend_base(&config.frontend_url),
        server_name
    );
    let unsubscribe_url = generate_list_unsubscribe_url(
        &config.magic_token_secret,
        email,
        server_name,
        alert_id,
        &config.frontend_url,
    );

    let detected_at_str = format!(
        "{:04}-{:02}-{:02} {:02}:{:02} UTC",
        detected_at.year(),
        detected_at.month() as u8,
        detected_at.day(),
        detected_at.hour(),
        detected_at.minute(),
    );
    let manage_url = format!("{}/alerts", frontend_base(&config.frontend_url));
    let sponsor_url = config
        .github_sponsors_url
        .clone()
        .or_else(|| config.liberapay_url.clone());

    let (release_url, release_notes_excerpt) = get_release_info(
        config,
        release_cache,
        &new_version_name,
        &new_version_string,
    )
    .await;

    let template = VersionChangeEmailTemplate {
        server_name: server_name.to_string(),
        old_version_name,
        old_version_string,
        new_version_name,
        new_version_string,
        check_url,
        unsubscribe_url: unsubscribe_url.clone(),
        environment_name: config.environment_name.clone(),
        detected_at: Some(detected_at_str),
        manage_url,
        sponsor_url,
        release_url,
        release_notes_excerpt,
    };

    let subject = env_subject(
        &format!("Federation Alert: version updated for {server_name}"),
        config.environment_name.as_deref(),
    );

    send_change_email(
        mailer,
        config,
        db,
        email,
        server_name,
        alert_id,
        subject,
        &template,
    )
    .await
}

/// Send a TLS certificate change notification email.
#[allow(clippy::too_many_arguments)]
#[tracing::instrument(skip(mailer, config, db, email, new_cert))]
pub async fn send_tls_cert_change_email(
    mailer: &Arc<lettre::AsyncSmtpTransport<lettre::Tokio1Executor>>,
    config: &Arc<crate::config::AppConfig>,
    db: &Arc<sea_orm::DatabaseConnection>,
    email: &str,
    server_name: &str,
    alert_id: i32,
    added_fingerprints: Vec<String>,
    removed_fingerprints: Vec<String>,
    detected_at: time::OffsetDateTime,
    new_cert: Option<crate::response::Certificate>,
) -> Result<(), EmailError> {
    let check_url = format!(
        "{}results?serverName={}",
        frontend_base(&config.frontend_url),
        server_name
    );
    let unsubscribe_url = generate_list_unsubscribe_url(
        &config.magic_token_secret,
        email,
        server_name,
        alert_id,
        &config.frontend_url,
    );

    let detected_at_str = format!(
        "{:04}-{:02}-{:02} {:02}:{:02} UTC",
        detected_at.year(),
        detected_at.month() as u8,
        detected_at.day(),
        detected_at.hour(),
        detected_at.minute(),
    );

    let month_abbr = |m: time::Month| match m {
        time::Month::January => "Jan",
        time::Month::February => "Feb",
        time::Month::March => "Mar",
        time::Month::April => "Apr",
        time::Month::May => "May",
        time::Month::June => "Jun",
        time::Month::July => "Jul",
        time::Month::August => "Aug",
        time::Month::September => "Sep",
        time::Month::October => "Oct",
        time::Month::November => "Nov",
        time::Month::December => "Dec",
    };

    let format_dt = |dt: time::OffsetDateTime| {
        format!("{} {}, {}", month_abbr(dt.month()), dt.day(), dt.year(),)
    };

    let alert_url = format!(
        "{}/alerts/edit/{}",
        frontend_base(&config.frontend_url).trim_end_matches('/'),
        alert_id
    );
    let manage_url = format!("{}/alerts", frontend_base(&config.frontend_url));
    let sponsor_url = config
        .github_sponsors_url
        .clone()
        .or_else(|| config.liberapay_url.clone());

    let old_fingerprint = removed_fingerprints.first().cloned();
    let new_fingerprint = new_cert
        .as_ref()
        .map(|c| c.sha256fingerprint.clone())
        .or_else(|| added_fingerprints.first().cloned());
    let new_issuer = new_cert.as_ref().map(|c| c.issuer_common_name.clone());
    let new_expires = new_cert.as_ref().and_then(|c| c.not_after).map(format_dt);

    let template = TlsCertChangeEmailTemplate {
        server_name: server_name.to_string(),
        added_fingerprints,
        removed_fingerprints,
        check_url,
        unsubscribe_url: unsubscribe_url.clone(),
        environment_name: config.environment_name.clone(),
        detected_at: Some(detected_at_str),
        old_fingerprint,
        old_issuer: None,
        old_expires: None,
        new_fingerprint,
        new_issuer,
        new_expires,
        alert_url,
        manage_url,
        sponsor_url,
    };

    let subject = env_subject(
        &format!("Federation Alert: TLS certificates changed for {server_name}"),
        config.environment_name.as_deref(),
    );

    send_change_email(
        mailer,
        config,
        db,
        email,
        server_name,
        alert_id,
        subject,
        &template,
    )
    .await
}

/// Send a TLS certificate expiry warning email.
#[allow(clippy::too_many_arguments)]
#[tracing::instrument(skip(mailer, config, db, email, cert_info))]
pub async fn send_tls_expiry_email(
    mailer: &Arc<lettre::AsyncSmtpTransport<lettre::Tokio1Executor>>,
    config: &Arc<crate::config::AppConfig>,
    db: &Arc<sea_orm::DatabaseConnection>,
    email: &str,
    server_name: &str,
    alert_id: i32,
    expires_at: time::OffsetDateTime,
    days_remaining: i64,
    cert_info: Option<&crate::response::Certificate>,
) -> Result<(), EmailError> {
    let check_url = format!(
        "{}results?serverName={}",
        frontend_base(&config.frontend_url),
        server_name
    );
    let unsubscribe_url = generate_list_unsubscribe_url(
        &config.magic_token_secret,
        email,
        server_name,
        alert_id,
        &config.frontend_url,
    );

    let expires_at_str = format!(
        "{:04}-{:02}-{:02} {:02}:{:02} UTC",
        expires_at.year(),
        expires_at.month() as u8,
        expires_at.day(),
        expires_at.hour(),
        expires_at.minute(),
    );

    let month_abbr = |m: time::Month| match m {
        time::Month::January => "Jan",
        time::Month::February => "Feb",
        time::Month::March => "Mar",
        time::Month::April => "Apr",
        time::Month::May => "May",
        time::Month::June => "Jun",
        time::Month::July => "Jul",
        time::Month::August => "Aug",
        time::Month::September => "Sep",
        time::Month::October => "Oct",
        time::Month::November => "Nov",
        time::Month::December => "Dec",
    };
    let expires_human = format!(
        "{} {}, {}",
        month_abbr(expires_at.month()),
        expires_at.day(),
        expires_at.year(),
    );

    let manage_url = format!("{}/alerts", frontend_base(&config.frontend_url));
    let sponsor_url = config
        .github_sponsors_url
        .clone()
        .or_else(|| config.liberapay_url.clone());

    let template = TlsExpiryEmailTemplate {
        server_name: server_name.to_string(),
        expires_at: expires_at_str,
        expires_human,
        days_remaining,
        check_url,
        unsubscribe_url: unsubscribe_url.clone(),
        environment_name: config.environment_name.clone(),
        issued_human: None,
        cert_cn: cert_info.map(|c| c.subject_common_name.clone()),
        cert_san: cert_info.and_then(|c| c.dnsnames.as_ref().map(|dns| dns.join(", "))),
        cert_issuer: cert_info.map(|c| c.issuer_common_name.clone()),
        cert_fingerprint: cert_info.map(|c| c.sha256fingerprint.clone()),
        manage_url,
        sponsor_url,
        renewal_guide_url: None,
    };

    let subject = env_subject(
        &format!(
            "Federation Alert: TLS certificate for {server_name} expires in {days_remaining} day{}",
            if days_remaining == 1 { "" } else { "s" }
        ),
        config.environment_name.as_deref(),
    );

    send_change_email(
        mailer,
        config,
        db,
        email,
        server_name,
        alert_id,
        subject,
        &template,
    )
    .await
}

/// Shared email-sending helper for all change-notification types.
///
/// Renders the template, builds the MIME message, sends via SMTP, and logs
/// the send to the `email_log` table. The `email_type` recorded in the log
/// is derived from the template's `email_type()` method.
#[allow(clippy::too_many_arguments)]
async fn send_change_email<T>(
    mailer: &Arc<lettre::AsyncSmtpTransport<lettre::Tokio1Executor>>,
    config: &Arc<crate::config::AppConfig>,
    db: &Arc<sea_orm::DatabaseConnection>,
    email: &str,
    server_name: &str,
    alert_id: i32,
    subject: String,
    template: &T,
) -> Result<(), EmailError>
where
    T: ChangeEmailTemplate,
{
    use lettre::message::{MultiPart, SinglePart};

    let html_body = template.render_html_change().map_err(|e| {
        tracing::error!(
            name = "alerts.send_change_email.template_render_failed",
            target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            error = %e,
            server_name = %server_name,
            alert_id = alert_id,
            email_type = template.email_type(),
            message = "Failed to render HTML email template"
        );
        EmailError::TemplateFailed(e.to_string())
    })?;
    let text_body = template.render_text_change();
    let unsubscribe_url = template.unsubscribe_url();

    let from_mailbox: lettre::message::Mailbox =
        config
            .smtp
            .from
            .parse()
            .map_err(|e| EmailError::InvalidAddress {
                address: config.smtp.from.clone(),
                detail: format!("{e}"),
            })?;
    let to_mailbox: lettre::message::Mailbox =
        email.parse().map_err(|e| EmailError::InvalidAddress {
            address: email.to_string(),
            detail: format!("{e}"),
        })?;

    let email_msg = lettre::Message::builder()
        .from(from_mailbox)
        .to(to_mailbox)
        .subject(subject)
        .header(lettre::message::header::MIME_VERSION_1_0)
        .header(UnsubscribeHeader::from(unsubscribe_url))
        .message_id(None)
        .multipart(
            MultiPart::alternative()
                .singlepart(
                    SinglePart::builder()
                        .header(lettre::message::header::ContentType::TEXT_PLAIN)
                        .body(text_body),
                )
                .singlepart(
                    SinglePart::builder()
                        .header(lettre::message::header::ContentType::TEXT_HTML)
                        .body(html_body),
                ),
        )
        .map_err(EmailError::BuildFailed)?;

    mailer.send(email_msg).await.map_err(|e| {
        tracing::error!(
            name = "alerts.send_change_email.send_failed",
            target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            error = %e,
            server_name = %server_name,
            alert_id = alert_id,
            email_type = template.email_type(),
            message = "Failed to send change alert email"
        );
        EmailError::SendFailed(e)
    })?;

    tracing::info!(
        target: "rust-federation-tester",
        email_type = template.email_type(),
        server_name = %server_name,
        alert_id = alert_id,
        "Sent change alert email"
    );

    let email_log_entry = email_log::ActiveModel {
        id: ActiveValue::NotSet,
        alert_id: ActiveValue::Set(alert_id),
        email: ActiveValue::Set(email.to_string()),
        server_name: ActiveValue::Set(server_name.to_string()),
        email_type: ActiveValue::Set(template.email_type().to_string()),
        sent_at: ActiveValue::Set(time::OffsetDateTime::now_utc()),
        failure_count: ActiveValue::NotSet,
    };
    if let Err(e) = email_log_entry.insert(db.as_ref()).await {
        tracing::error!(
            name = "alerts.send_change_email.log_insert_failed",
            target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            error = %e,
            message = "Failed to log change email to database"
        );
    }

    Ok(())
}

/// Trait implemented by all change-notification email templates.
trait ChangeEmailTemplate {
    fn render_html_change(&self) -> Result<String, askama::Error>;
    fn render_text_change(&self) -> String;
    fn unsubscribe_url(&self) -> String;
    fn email_type(&self) -> &'static str;
}

impl ChangeEmailTemplate for ServerNameChangeEmailTemplate {
    fn render_html_change(&self) -> Result<String, askama::Error> {
        self.render_html()
    }
    fn render_text_change(&self) -> String {
        self.render_text()
    }
    fn unsubscribe_url(&self) -> String {
        self.unsubscribe_url.clone()
    }
    fn email_type(&self) -> &'static str {
        "server_name_change"
    }
}

impl ChangeEmailTemplate for VersionChangeEmailTemplate {
    fn render_html_change(&self) -> Result<String, askama::Error> {
        self.render_html()
    }
    fn render_text_change(&self) -> String {
        self.render_text()
    }
    fn unsubscribe_url(&self) -> String {
        self.unsubscribe_url.clone()
    }
    fn email_type(&self) -> &'static str {
        "version_change"
    }
}

impl ChangeEmailTemplate for TlsCertChangeEmailTemplate {
    fn render_html_change(&self) -> Result<String, askama::Error> {
        self.render_html()
    }
    fn render_text_change(&self) -> String {
        self.render_text()
    }
    fn unsubscribe_url(&self) -> String {
        self.unsubscribe_url.clone()
    }
    fn email_type(&self) -> &'static str {
        "tls_cert_change"
    }
}

impl ChangeEmailTemplate for TlsExpiryEmailTemplate {
    fn render_html_change(&self) -> Result<String, askama::Error> {
        self.render_html()
    }
    fn render_text_change(&self) -> String {
        self.render_text()
    }
    fn unsubscribe_url(&self) -> String {
        self.unsubscribe_url.clone()
    }
    fn email_type(&self) -> &'static str {
        "tls_expiry_warning"
    }
}

/// Generates a List-Unsubscribe URL for the given alert.
#[tracing::instrument(skip_all)]
pub fn generate_list_unsubscribe_url(
    magic_token_secret: &str,
    email: &str,
    server_name: &str,
    alert_id: i32,
    frontend_url: &str,
) -> String {
    let exp = (OffsetDateTime::now_utc() + time::Duration::hours(1)).unix_timestamp() as usize;
    let claims = MagicClaims {
        exp,
        email: email.to_string(),
        server_name: Some(server_name.to_string()),
        action: "delete".to_string(),
        alert_id: Some(alert_id.to_string()),
    };
    let secret = magic_token_secret.as_bytes();
    let token = encode(
        &JwtHeader::default(),
        &claims,
        &EncodingKey::from_secret(secret),
    )
    .unwrap_or_default();
    format!("{}verify?token={token}", frontend_base(frontend_url))
}

/// Custom List-Unsubscribe header for email messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsubscribeHeader(String);

impl Header for UnsubscribeHeader {
    fn name() -> HeaderName {
        HeaderName::new_from_ascii_str("List-Unsubscribe")
    }

    fn parse(s: &str) -> Result<Self, Box<dyn core::error::Error + Send + Sync>> {
        Ok(Self(s.into()))
    }

    fn display(&self) -> HeaderValue {
        HeaderValue::new(Self::name(), self.0.clone())
    }
}

impl From<String> for UnsubscribeHeader {
    fn from(content: String) -> Self {
        Self(content)
    }
}

impl AsRef<str> for UnsubscribeHeader {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── frontend_base ──────────────────────────────────────────────────────

    #[test]
    fn frontend_base_adds_slash_when_missing() {
        assert_eq!(frontend_base("https://example.com"), "https://example.com/");
    }

    #[test]
    fn frontend_base_keeps_single_slash() {
        assert_eq!(
            frontend_base("https://example.com/"),
            "https://example.com/"
        );
    }

    #[test]
    fn frontend_base_collapses_multiple_trailing_slashes() {
        assert_eq!(
            frontend_base("https://example.com///"),
            "https://example.com/"
        );
    }

    // ── format_downtime ────────────────────────────────────────────────────

    #[test]
    fn format_downtime_under_an_hour() {
        assert_eq!(format_downtime(0), "0 min");
        assert_eq!(format_downtime(1), "1 min");
        assert_eq!(format_downtime(59), "59 min");
    }

    #[test]
    fn format_downtime_whole_hours() {
        assert_eq!(format_downtime(60), "1h");
        assert_eq!(format_downtime(120), "2h");
        assert_eq!(format_downtime(180), "3h");
    }

    #[test]
    fn format_downtime_hours_and_minutes() {
        assert_eq!(format_downtime(61), "1h 1m");
        assert_eq!(format_downtime(90), "1h 30m");
        assert_eq!(format_downtime(125), "2h 5m");
    }

    // ── format_email_datetime ──────────────────────────────────────────────

    #[test]
    fn format_email_datetime_utc() {
        let dt = time::Date::from_calendar_date(2026, time::Month::May, 19)
            .unwrap()
            .with_hms(9, 59, 0)
            .unwrap()
            .assume_utc();
        assert_eq!(format_email_datetime(dt), "2026-05-19 09:59 UTC");
    }

    #[test]
    fn format_email_datetime_zero_padded() {
        let dt = time::Date::from_calendar_date(2026, time::Month::January, 3)
            .unwrap()
            .with_hms(7, 5, 0)
            .unwrap()
            .assume_utc();
        assert_eq!(format_email_datetime(dt), "2026-01-03 07:05 UTC");
    }

    // ── generate_list_unsubscribe_url ──────────────────────────────────────

    #[test]
    fn generate_list_unsubscribe_url_contains_token_and_base() {
        let url = generate_list_unsubscribe_url(
            "secret-32-chars-xxxxxxxxxxxxxxxxxxxx",
            "user@example.com",
            "matrix.example.com",
            42,
            "https://frontend.example.com",
        );
        assert!(url.starts_with("https://frontend.example.com/verify?token="));
    }

    #[test]
    fn generate_list_unsubscribe_url_adds_trailing_slash_to_base() {
        // frontend_url without trailing slash
        let url = generate_list_unsubscribe_url(
            "secret-32-chars-xxxxxxxxxxxxxxxxxxxx",
            "user@example.com",
            "matrix.example.com",
            1,
            "https://frontend.example.com",
        );
        // The path segment starts immediately after the base URL
        assert!(!url.contains("//verify"), "double-slash should not appear");
    }

    #[test]
    fn generate_list_unsubscribe_url_token_is_jwt() {
        let url = generate_list_unsubscribe_url(
            "secret-32-chars-xxxxxxxxxxxxxxxxxxxx",
            "user@example.com",
            "matrix.example.com",
            1,
            "https://frontend.example.com",
        );
        let token = url.split("token=").nth(1).unwrap_or("");
        // JWTs have exactly 2 dots separating the 3 base64url segments
        assert_eq!(
            token.matches('.').count(),
            2,
            "expected JWT format: header.payload.sig"
        );
    }

    // ── UnsubscribeHeader ──────────────────────────────────────────────────────

    #[test]
    fn unsubscribe_header_from_string() {
        let h = UnsubscribeHeader::from("<https://example.com/unsub>".to_string());
        assert_eq!(h.as_ref(), "<https://example.com/unsub>");
    }

    #[test]
    fn unsubscribe_header_parse_roundtrip() {
        let raw = "<https://example.com/unsub>, <mailto:unsub@example.com>";
        let h = UnsubscribeHeader::parse(raw).unwrap();
        assert_eq!(h.as_ref(), raw);
    }

    #[test]
    fn unsubscribe_header_name_is_list_unsubscribe() {
        let name = UnsubscribeHeader::name();
        // HeaderName implements Debug — check it contains the expected name
        assert!(format!("{name:?}").contains("List-Unsubscribe"));
    }

    #[test]
    fn unsubscribe_header_display_does_not_panic() {
        let h = UnsubscribeHeader::from("<https://example.com/unsub>".to_string());
        let _hv = h.display();
    }
}
