use crate::AppResources;
use crate::api::alert_api::MagicClaims;
use crate::connection_pool::ConnectionPool;
use crate::email_templates::{FailureEmailTemplate, RecoveryEmailTemplate};
use crate::entity::alert;
use crate::response::generate_json_report;
use hickory_resolver::Resolver;
use hickory_resolver::name_server::ConnectionProvider;
use jsonwebtoken::{EncodingKey, Header as JwtHeader, encode};
use lettre::AsyncTransport;
use lettre::message::header::HeaderName;
use lettre::message::header::{Header, HeaderValue};
use lettre::message::{MultiPart, SinglePart};
use sea_orm::{ActiveModelTrait, ActiveValue, ColumnTrait, EntityTrait, QueryFilter};
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use time::OffsetDateTime;
use tokio::sync::RwLock;
use tokio::time::Duration;
use tracing::{error, info};

type AlertCheckTask = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Email sending policy configuration
const REMINDER_EMAIL_INTERVAL: Duration = Duration::from_secs(12 * 3600); // 12 hours
const CHECK_INTERVAL: Duration = Duration::from_secs(5 * 60); // 5 minutes - check frequently

pub struct AlertTaskManager {
    running: RwLock<HashMap<i32, Arc<AtomicBool>>>,
}

impl Default for AlertTaskManager {
    fn default() -> Self {
        Self::new()
    }
}

impl AlertTaskManager {
    pub fn new() -> Self {
        Self {
            running: RwLock::new(HashMap::new()),
        }
    }

    #[tracing::instrument(name = "alert_manager_start_task", skip(self, f), fields(alert_id = %alert_id))]
    pub async fn start_or_restart_task<F>(&self, alert_id: i32, f: F)
    where
        F: FnOnce(Arc<AtomicBool>) -> AlertCheckTask + Send + 'static,
    {
        let mut running = self.running.write().await;
        if let Some(flag) = running.get(&alert_id) {
            flag.store(false, Ordering::SeqCst); // stop old
        }
        let flag = Arc::new(AtomicBool::new(true));
        running.insert(alert_id, flag.clone());
        let task = f(flag.clone());
        tokio::spawn(task);
    }

    /// Check if a task is already running for this alert
    pub async fn is_running(&self, alert_id: i32) -> bool {
        let running = self.running.read().await;
        running.contains_key(&alert_id)
    }

    #[tracing::instrument(name = "alert_manager_stop_task", skip(self), fields(alert_id = %alert_id))]
    pub async fn stop_task(&self, alert_id: i32) {
        let mut running = self.running.write().await;
        if let Some(flag) = running.remove(&alert_id) {
            flag.store(false, Ordering::SeqCst);
        }
    }

    pub async fn stop_all(&self) {
        let mut running = self.running.write().await;
        for flag in running.values() {
            flag.store(false, Ordering::SeqCst);
        }
        running.clear();
    }
}

/// Determine if we should send a failure email based on alert state and timing
fn should_send_failure_email(alert: &alert::Model, now: OffsetDateTime) -> bool {
    // If server just started failing, send immediately
    if !alert.is_currently_failing {
        return true;
    }

    // If we've never sent an email, send now
    let Some(last_email) = alert.last_email_sent_at else {
        return true;
    };

    // Send reminder emails every REMINDER_EMAIL_INTERVAL
    let time_since_last_email = now - last_email;
    let reminder_threshold: time::Duration = REMINDER_EMAIL_INTERVAL.try_into().unwrap();
    time_since_last_email >= reminder_threshold
}

/// Send a failure notification email
async fn send_failure_email(
    mailer: &Arc<lettre::AsyncSmtpTransport<lettre::Tokio1Executor>>,
    config: &Arc<crate::config::AppConfig>,
    email: &str,
    server_name: &str,
    alert_id: i32,
    failure_count: i32,
) {
    let check_url = format!("{}?serverName={}", config.frontend_url, server_name);

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
    };

    let subject = format!("Federation Alert: {server_name} is not healthy");

    // Render both HTML and plain text versions
    let html_body = match template.render_html() {
        Ok(html) => html,
        Err(e) => {
            error!("Failed to render HTML email template: {}", e);
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
        error!("Failed to send failure alert email to {}: {}", email, e);
    } else {
        info!(
            "Sent failure alert email #{} to {} for server {}",
            failure_count, email, server_name
        );
    }
}

/// Send a recovery notification email
async fn send_recovery_email(
    mailer: &Arc<lettre::AsyncSmtpTransport<lettre::Tokio1Executor>>,
    config: &Arc<crate::config::AppConfig>,
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
            error!("Failed to render HTML email template: {}", e);
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
        error!("Failed to send recovery email to {}: {}", email, e);
    } else {
        info!(
            "Sent recovery email to {} for server {}",
            email, server_name
        );
    }
}

#[tracing::instrument(
    name = "recurring_alert_checks",
    skip(resources, task_manager, resolver, connection_pool)
)]
pub async fn recurring_alert_checks<P: ConnectionProvider + Send + Sync + 'static>(
    resources: Arc<AppResources>,
    task_manager: Arc<AlertTaskManager>,
    resolver: Arc<Resolver<P>>,
    connection_pool: ConnectionPool,
) {
    loop {
        // 1. Load all verified alerts
        let alerts = alert::Entity::find()
            .filter(alert::Column::Verified.eq(true))
            .all(resources.db.as_ref())
            .await
            .unwrap_or_default();

        // 2. Start or restart a task for each verified alert
        // Distribute the checks over the CHECK_INTERVAL to avoid all checking at once
        let total_alerts = alerts.len();
        let stagger_interval = if total_alerts > 1 {
            CHECK_INTERVAL.as_secs() / total_alerts as u64
        } else {
            0
        };

        for (index, a) in alerts.iter().enumerate() {
            let alert_id = a.id;

            // Skip if task is already running for this alert
            if task_manager.is_running(alert_id).await {
                continue;
            }

            let email = a.email.clone();
            let server_name = a.server_name.clone();
            let resolver = resolver.clone();
            let connection_pool = connection_pool.clone();
            let mailer = resources.mailer.clone();
            let config = resources.config.clone();
            let db = resources.db.clone();
            let initial_delay = Duration::from_secs(stagger_interval * index as u64);

            task_manager
                .start_or_restart_task(alert_id, move |flag| {
                    Box::pin(async move {
                        // Stagger the initial start time to distribute load (only on first start)
                        if initial_delay.as_secs() > 0 {
                            info!(
                                "Alert check for {} ({}) will start in {} seconds",
                                server_name,
                                email,
                                initial_delay.as_secs()
                            );
                            tokio::time::sleep(initial_delay).await;
                        }

                        while flag.load(Ordering::SeqCst) {
                            info!("Running recurring check for {} ({})", server_name, email);

                            // Perform the federation check
                            let report =
                                generate_json_report(&server_name, &resolver, &connection_pool)
                                    .await;

                            let now = OffsetDateTime::now_utc();

                            match report {
                                Ok(report) => {
                                    // Update alert state in database
                                    if let Ok(Some(alert_model)) =
                                        alert::Entity::find_by_id(alert_id).one(db.as_ref()).await
                                    {
                                        let mut alert_active: alert::ActiveModel =
                                            alert_model.clone().into();
                                        alert_active.last_check_at = ActiveValue::Set(Some(now));

                                        if !report.federation_ok {
                                            // Server is failing
                                            let should_send_email =
                                                should_send_failure_email(&alert_model, now);

                                            // Update failure state
                                            if !alert_model.is_currently_failing {
                                                // Transition from OK to FAILING
                                                alert_active.is_currently_failing =
                                                    ActiveValue::Set(true);
                                                alert_active.failure_count = ActiveValue::Set(1);
                                                alert_active.last_failure_at =
                                                    ActiveValue::Set(Some(now));
                                                info!(
                                                    "Server {} transitioned to failing state",
                                                    server_name
                                                );
                                            } else {
                                                // Still failing, increment counter
                                                alert_active.failure_count =
                                                    ActiveValue::Set(alert_model.failure_count + 1);
                                                alert_active.last_failure_at =
                                                    ActiveValue::Set(Some(now));
                                            }

                                            // Save state before potentially sending email
                                            if let Ok(updated_alert) =
                                                alert_active.update(db.as_ref()).await
                                                && should_send_email
                                            {
                                                send_failure_email(
                                                    &mailer,
                                                    &config,
                                                    &email,
                                                    &server_name,
                                                    alert_id,
                                                    updated_alert.failure_count,
                                                )
                                                .await;

                                                // Update last_email_sent_at
                                                let mut email_update: alert::ActiveModel =
                                                    updated_alert.into();
                                                email_update.last_email_sent_at =
                                                    ActiveValue::Set(Some(now));
                                                let _ = email_update.update(db.as_ref()).await;
                                            }
                                        } else {
                                            // Server is OK
                                            if alert_model.is_currently_failing {
                                                // Transition from FAILING to OK - send recovery email
                                                alert_active.is_currently_failing =
                                                    ActiveValue::Set(false);
                                                alert_active.failure_count = ActiveValue::Set(0);
                                                alert_active.last_success_at =
                                                    ActiveValue::Set(Some(now));

                                                if alert_active.update(db.as_ref()).await.is_ok() {
                                                    send_recovery_email(
                                                        &mailer,
                                                        &config,
                                                        &email,
                                                        &server_name,
                                                        alert_id,
                                                    )
                                                    .await;

                                                    // Update last_email_sent_at
                                                    if let Ok(Some(alert_for_update)) =
                                                        alert::Entity::find_by_id(alert_id)
                                                            .one(db.as_ref())
                                                            .await
                                                    {
                                                        let mut email_update: alert::ActiveModel =
                                                            alert_for_update.into();
                                                        email_update.last_email_sent_at =
                                                            ActiveValue::Set(Some(now));
                                                        let _ =
                                                            email_update.update(db.as_ref()).await;
                                                    }
                                                }
                                                info!(
                                                    "Server {} recovered to healthy state",
                                                    server_name
                                                );
                                            } else {
                                                // Still OK, just update check time and success time
                                                alert_active.last_success_at =
                                                    ActiveValue::Set(Some(now));
                                                let _ = alert_active.update(db.as_ref()).await;
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    error!(
                                        "Federation check error for {} ({}): {:?}",
                                        server_name, email, e
                                    );
                                }
                            }

                            // Check every 5 minutes
                            tokio::time::sleep(CHECK_INTERVAL).await;
                        }
                        info!("Stopped recurring check for {} ({})", server_name, email);
                    })
                })
                .await;
        }

        // 3. Remove tasks for alerts that no longer exist or are unverified
        let running = task_manager.running.write().await;
        let mut to_remove = Vec::new();
        for (alert_id, _) in running.iter() {
            if !alerts.iter().any(|a| &a.id == alert_id) {
                to_remove.push(*alert_id);
            }
        }
        drop(running);
        for alert_id in to_remove {
            task_manager.stop_task(alert_id).await;
        }

        // 4. Clean up unverified alerts older than 1 day
        let cutoff = OffsetDateTime::now_utc() - time::Duration::days(1);
        let _ = alert::Entity::delete_many()
            .filter(alert::Column::Verified.eq(false))
            .filter(alert::Column::CreatedAt.lt(cutoff))
            .exec(resources.db.as_ref())
            .await;

        // 5. Wait for a while before next full scan
        tokio::time::sleep(Duration::from_secs(300)).await; // 5 min
    }
}

fn generate_list_unsubscribe_url(
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct UnsubscribeHeader(String);

impl Header for UnsubscribeHeader {
    fn name() -> lettre::message::header::HeaderName {
        HeaderName::new_from_ascii_str("List-Unsubscribe")
    }

    fn parse(s: &str) -> Result<Self, Box<dyn core::error::Error + Send + Sync>> {
        Ok(Self(s.into()))
    }

    fn display(&self) -> lettre::message::header::HeaderValue {
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
