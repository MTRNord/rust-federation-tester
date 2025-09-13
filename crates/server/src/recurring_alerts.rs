use crate::AppResources;
use crate::api::alert_api::MagicClaims;
use crate::cache::{DnsCache, VersionCache, WellKnownCache};
use crate::connection_pool::ConnectionPool;
use crate::entity::alert;
use crate::response::generate_json_report;
use hickory_resolver::Resolver;
use hickory_resolver::name_server::ConnectionProvider;
use jsonwebtoken::{EncodingKey, Header as JwtHeader, encode};
use lettre::message::header::{ContentType, HeaderName};
use lettre::message::header::{Header, HeaderValue};
use lettre::{AsyncTransport, Message};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use time::OffsetDateTime;
use tokio::sync::RwLock;
use tokio::time::Duration;
use tracing::{error, info};

type AlertCheckTask = Pin<Box<dyn Future<Output = ()> + Send>>;

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

pub async fn recurring_alert_checks<P: ConnectionProvider + Send + Sync + 'static>(
    resources: Arc<AppResources>,
    task_manager: Arc<AlertTaskManager>,
    resolver: Arc<Resolver<P>>,
    connection_pool: ConnectionPool,
    dns_cache: DnsCache,
    well_known_cache: WellKnownCache,
    version_cache: VersionCache,
) {
    loop {
        // 1. Load all verified alerts
        let alerts = alert::Entity::find()
            .filter(alert::Column::Verified.eq(true))
            .all(resources.db.as_ref())
            .await
            .unwrap_or_default();

        // 2. Start or restart a task for each verified alert
        for a in &alerts {
            let alert_id = a.id;
            let email = a.email.clone();
            let server_name = a.server_name.clone();
            let resolver = resolver.clone();
            let connection_pool = connection_pool.clone();
            let dns_cache = dns_cache.clone();
            let well_known_cache = well_known_cache.clone();
            let version_cache = version_cache.clone();
            let mailer = resources.mailer.clone();
            let config = resources.config.clone();
            task_manager
                .start_or_restart_task(alert_id, move |flag| {
                    Box::pin(async move {
                        while flag.load(Ordering::SeqCst) {
                            info!("Running recurring check for {} ({})", server_name, email);
                            let report = generate_json_report(
                                &server_name,
                                &resolver,
                                &connection_pool,
                                &dns_cache,
                                &well_known_cache,
                                &version_cache,
                                true,
                            )
                            .await;
                            match report {
                                Ok(report) => {
                                    if !report.federation_ok {
                                        // Send alert email
                                        let subject = format!(
                                            "Federation Alert: {server_name} is not healthy"
                                        );
                                        let check_url = format!(
                                            "{}?server_name={}",
                                            config.frontend_url, server_name
                                        );
                                        let body = format!(
                                            r#"Hello,

Your server '{server_name}' failed the federation health check.

Please review the latest report at {check_url} and take action if needed.

Best regards,
The Federation Tester Team"#
                                        );

                                        // --- List-Unsubscribe header generation ---
                                        let unsubscribe_url = generate_list_unsubscribe_url(
                                            &config.magic_token_secret,
                                            &email,
                                            &server_name,
                                            alert_id,
                                            &config.frontend_url,
                                        );

                                        let email_msg = Message::builder()
                                            .from(config.smtp.from.parse().unwrap())
                                            .to(email.parse().unwrap())
                                            .subject(subject)
                                            .header(ContentType::TEXT_PLAIN)
                                            .header(lettre::message::header::MIME_VERSION_1_0)
                                            .header(UnsubscribeHeader::from(unsubscribe_url))
                                            .message_id(None)
                                            .body(body)
                                            .unwrap();
                                        if let Err(e) = mailer.send(email_msg).await {
                                            error!(
                                                "Failed to send alert email to {}: {}",
                                                email, e
                                            );
                                        } else {
                                            info!(
                                                "Sent alert email to {} for server {}",
                                                email, server_name
                                            );
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
                            tokio::time::sleep(Duration::from_secs(3600)).await;
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
