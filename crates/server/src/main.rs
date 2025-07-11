use hickory_resolver::Resolver;
use lettre::{AsyncSmtpTransport, Tokio1Executor, transport::smtp::authentication::Credentials};
use rust_federation_tester::AppResources;
use rust_federation_tester::api::alert_api::AlertAppState;
use rust_federation_tester::api::federation_tester_api::AppState;
use rust_federation_tester::api::start_webserver;
use rust_federation_tester::cache::{DnsCache, VersionCache, WellKnownCache};
use rust_federation_tester::config::load_config;
use rust_federation_tester::connection_pool::ConnectionPool;
use rust_federation_tester::recurring_alerts::AlertTaskManager;
use rust_federation_tester::recurring_alerts::recurring_alert_checks;
use rustls::crypto;
use rustls::crypto::CryptoProvider;
use sea_orm::Database;
use std::sync::Arc;
use tokio::time::{Duration, interval};

#[tokio::main]
async fn main() -> color_eyre::eyre::Result<()> {
    color_eyre::install().expect("Failed to install `color_eyre::install`");
    tracing_subscriber::fmt().init();

    // Load config
    let config = Arc::new(load_config());

    let ring_provider = crypto::ring::default_provider();
    CryptoProvider::install_default(ring_provider).expect("Failed to install crypto provider");

    // Set up SeaORM database connection
    let db = Arc::new(
        Database::connect(&config.database_url)
            .await
            .expect("Failed to connect to database"),
    );

    // Set up lettre SMTP client
    let creds = Credentials::new(config.smtp.username.clone(), config.smtp.password.clone());
    let mailer = Arc::new(
        AsyncSmtpTransport::<Tokio1Executor>::relay(&config.smtp.server)
            .unwrap()
            .port(config.smtp.port)
            .credentials(creds)
            .build(),
    );

    // Set up resolver and caches
    let resolver = Arc::new(Resolver::builder_tokio()?.build());
    let connection_pool = ConnectionPool::default();
    let dns_cache = DnsCache::default();
    let well_known_cache = WellKnownCache::default();
    let version_cache = VersionCache::default();
    let task_manager = Arc::new(AlertTaskManager::new());

    let state = AppState {
        resolver,
        connection_pool: connection_pool.clone(),
        dns_cache,
        well_known_cache,
        version_cache,
    };

    let alert_state = AlertAppState {
        task_manager: task_manager.clone(),
    };

    let resources = AppResources { db, mailer, config };

    // Start background cleanup task for connection pool
    {
        let pool = connection_pool.clone();
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(300)); // 5 minutes
            loop {
                interval.tick().await;
                pool.cleanup_dead_connections().await;
            }
        });
    }

    // Start recurring alert checks
    let resources_for_checks = resources.clone();
    let task_manager_for_checks = task_manager.clone();
    let resolver_for_checks = state.resolver.clone();
    let connection_pool_for_checks = state.connection_pool.clone();
    let dns_cache_for_checks = state.dns_cache.clone();
    let well_known_cache_for_checks = state.well_known_cache.clone();
    let version_cache_for_checks = state.version_cache.clone();
    tokio::spawn(async move {
        recurring_alert_checks(
            resources_for_checks.into(),
            task_manager_for_checks,
            resolver_for_checks,
            connection_pool_for_checks,
            dns_cache_for_checks,
            well_known_cache_for_checks,
            version_cache_for_checks,
        )
        .await;
    });

    start_webserver(state, alert_state, resources).await?;
    Ok(())
}
