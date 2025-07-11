use crate::AppResources;
use crate::cache::{DnsCache, VersionCache, WellKnownCache};
use crate::connection_pool::ConnectionPool;
use crate::entity::alert;
use crate::response::generate_json_report;
use hickory_resolver::Resolver;
use hickory_resolver::name_server::ConnectionProvider;
use lettre::message::header::ContentType;
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
    running: RwLock<HashMap<uuid::Uuid, Arc<AtomicBool>>>,
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

    pub async fn start_or_restart_task<F>(&self, alert_id: uuid::Uuid, f: F)
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

    pub async fn stop_task(&self, alert_id: uuid::Uuid) {
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
                                        let email_msg = Message::builder()
                                            .from(config.smtp.from.parse().unwrap())
                                            .to(email.parse().unwrap())
                                            .subject(subject)
                                            .header(ContentType::TEXT_PLAIN)
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
