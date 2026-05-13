//! Email sending for alert notifications.
//!
//! Handles sending failure and recovery notification emails.

use crate::api::alerts::MagicClaims;
use crate::email_templates::{
    FailureEmailTemplate, RecoveryEmailTemplate, ServerNameChangeEmailTemplate,
    TlsCertChangeEmailTemplate, TlsExpiryEmailTemplate, VersionChangeEmailTemplate, env_subject,
};
use crate::entity::email_log;
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
) -> Result<(), EmailError> {
    let check_url = format!(
        "{}results?serverName={}",
        frontend_base(&config.frontend_url),
        server_name
    );

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
#[tracing::instrument(skip(mailer, config, db, email))]
pub async fn send_recovery_email(
    mailer: &Arc<lettre::AsyncSmtpTransport<lettre::Tokio1Executor>>,
    config: &Arc<crate::config::AppConfig>,
    db: &Arc<sea_orm::DatabaseConnection>,
    email: &str,
    server_name: &str,
    alert_id: i32,
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

    let template = RecoveryEmailTemplate {
        server_name: server_name.to_string(),
        check_url: check_url.clone(),
        unsubscribe_url: unsubscribe_url.clone(),
        environment_name: config.environment_name.clone(),
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
    old_server_name: Option<String>,
    new_server_name: Option<String>,
    old_well_known: Vec<String>,
    new_well_known: Vec<String>,
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

    let template = ServerNameChangeEmailTemplate {
        server_name: server_name.to_string(),
        old_server_name,
        new_server_name,
        old_well_known,
        new_well_known,
        check_url,
        unsubscribe_url: unsubscribe_url.clone(),
        environment_name: config.environment_name.clone(),
    };

    let subject = env_subject(
        &format!("Federation Alert: server name changed for {server_name}"),
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
#[tracing::instrument(skip(mailer, config, db, email))]
pub async fn send_version_change_email(
    mailer: &Arc<lettre::AsyncSmtpTransport<lettre::Tokio1Executor>>,
    config: &Arc<crate::config::AppConfig>,
    db: &Arc<sea_orm::DatabaseConnection>,
    email: &str,
    server_name: &str,
    alert_id: i32,
    old_version_name: String,
    old_version_string: String,
    new_version_name: String,
    new_version_string: String,
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

    let template = VersionChangeEmailTemplate {
        server_name: server_name.to_string(),
        old_version_name,
        old_version_string,
        new_version_name,
        new_version_string,
        check_url,
        unsubscribe_url: unsubscribe_url.clone(),
        environment_name: config.environment_name.clone(),
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
#[tracing::instrument(skip(mailer, config, db, email))]
pub async fn send_tls_cert_change_email(
    mailer: &Arc<lettre::AsyncSmtpTransport<lettre::Tokio1Executor>>,
    config: &Arc<crate::config::AppConfig>,
    db: &Arc<sea_orm::DatabaseConnection>,
    email: &str,
    server_name: &str,
    alert_id: i32,
    added_fingerprints: Vec<String>,
    removed_fingerprints: Vec<String>,
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

    let template = TlsCertChangeEmailTemplate {
        server_name: server_name.to_string(),
        added_fingerprints,
        removed_fingerprints,
        check_url,
        unsubscribe_url: unsubscribe_url.clone(),
        environment_name: config.environment_name.clone(),
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
#[tracing::instrument(skip(mailer, config, db, email))]
pub async fn send_tls_expiry_email(
    mailer: &Arc<lettre::AsyncSmtpTransport<lettre::Tokio1Executor>>,
    config: &Arc<crate::config::AppConfig>,
    db: &Arc<sea_orm::DatabaseConnection>,
    email: &str,
    server_name: &str,
    alert_id: i32,
    expires_at: time::OffsetDateTime,
    days_remaining: i64,
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

    let template = TlsExpiryEmailTemplate {
        server_name: server_name.to_string(),
        expires_at: expires_at_str,
        days_remaining,
        check_url,
        unsubscribe_url: unsubscribe_url.clone(),
        environment_name: config.environment_name.clone(),
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
