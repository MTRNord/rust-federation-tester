//! Email sending for alert notifications.
//!
//! Handles sending failure and recovery notification emails.

use crate::api::alerts::MagicClaims;
use crate::email_templates::{FailureEmailTemplate, RecoveryEmailTemplate};
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
) {
    let check_url = format!("{}results?serverName={}", config.frontend_url, server_name);

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
        is_reminder: failure_count > 1,
        failure_count,
        reminder_interval: reminder_interval_text,
        unsubscribe_url: unsubscribe_url.clone(),
        failure_reason,
    };

    let subject = format!("Federation Alert: {server_name} is not healthy");

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
            return;
        }
    };
    let text_body = template.render_text();

    // Create multipart email with both HTML and plain text
    let email_msg = lettre::Message::builder()
        .from(config.smtp.from.parse().unwrap())
        .to(email.parse().unwrap())
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
        .unwrap();

    if let Err(e) = mailer.send(email_msg).await {
        tracing::error!(
            name = "alerts.send_failure_email.email_send_failed",
            target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            error = %e,
            server_name = %server_name,
            alert_id = alert_id,
            message = "Failed to send failure alert email"
        );
    } else {
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
    }
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
) {
    let check_url = format!("{}?serverName={}", config.frontend_url, server_name);

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
    };

    let subject = format!("Federation Alert: {server_name} has recovered!");

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
            return;
        }
    };
    let text_body = template.render_text();

    // Create multipart email with both HTML and plain text
    let email_msg = lettre::Message::builder()
        .from(config.smtp.from.parse().unwrap())
        .to(email.parse().unwrap())
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
        .unwrap();

    if let Err(e) = mailer.send(email_msg).await {
        tracing::error!(
            name = "alerts.send_recovery_email.email_send_failed",
            target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            error = %e,
            server_name = %server_name,
            alert_id = alert_id,
            message = "Failed to send recovery email"
        );
    } else {
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
    format!("{frontend_url}/verify?token={token}")
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
