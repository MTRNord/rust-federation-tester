use hickory_resolver::Resolver;
use lettre::{AsyncSmtpTransport, Tokio1Executor, transport::smtp::authentication::Credentials};
use rust_federation_tester::AppResources;
use rust_federation_tester::api::alert_api::AlertAppState;
use rust_federation_tester::api::federation_tester_api::AppState;
use rust_federation_tester::api::start_webserver;
use rust_federation_tester::config::load_config_or_panic;
use rust_federation_tester::connection_pool::ConnectionPool;
use rust_federation_tester::recurring_alerts::AlertTaskManager;
use rust_federation_tester::recurring_alerts::recurring_alert_checks;
use rustls::crypto;
use rustls::crypto::CryptoProvider;
use sea_orm::Database;
use std::env;
use std::sync::Arc;
use tokio::time::{Duration, interval};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

#[cfg(not(feature = "console"))]
fn initialize_standard_tracing() {
    let default_directives = "rust_federation_tester=info,hyper=warn,sea_orm=info";
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_directives));

    let registry = tracing_subscriber::registry().with(env_filter);
    let layer = fmt::layer().with_target(true).with_level(true);

    registry.with(layer).init();
}

#[cfg(feature = "console")]
fn initialize_layered_tracing() {
    let default_directives =
        "rust_federation_tester=info,hyper=warn,sea_orm=info,tokio=trace,runtime=trace";
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_directives));

    // Create console layer for tokio-console
    let console_layer = console_subscriber::spawn();

    // Create standard fmt layer for normal logging
    let fmt_layer = fmt::layer().with_target(true).with_level(true);

    // Combine both layers
    tracing_subscriber::registry()
        .with(env_filter)
        .with(console_layer)
        .with(fmt_layer)
        .init();
}

fn is_debug_mode() -> bool {
    env::var("RUST_LOG").unwrap_or_default().contains("debug")
        || env::var("RUST_LOG").unwrap_or_default().contains("trace")
}

#[tokio::main]
async fn main() -> color_eyre::eyre::Result<()> {
    color_eyre::install().expect("Failed to install `color_eyre::install`");

    // -------- Tracing Initialization --------
    // Initialize tracing with console support if enabled, otherwise standard logging
    #[cfg(feature = "console")]
    {
        initialize_layered_tracing();
        tracing::info!("Tokio Console enabled - connect with `tokio-console`");
    }
    #[cfg(not(feature = "console"))]
    {
        initialize_standard_tracing();
    }

    // Load config
    let config = Arc::new(load_config_or_panic());

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
    let task_manager = Arc::new(AlertTaskManager::new());

    let state = AppState {
        resolver,
        connection_pool: connection_pool.clone(),
    };

    let alert_state = AlertAppState {
        task_manager: task_manager.clone(),
    };

    let resources = std::sync::Arc::new(AppResources { db, mailer, config });
    tracing::info!(enabled=%resources.config.statistics.enabled, prometheus=%resources.config.statistics.prometheus_enabled, retention_days=%resources.config.statistics.raw_retention_days, salt_set=%!resources.config.statistics.anonymization_salt.is_empty(), "statistics configuration");
    // Start retention pruning task for federation stats (if enabled)
    rust_federation_tester::stats::spawn_retention_task(resources.clone());

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
    tokio::spawn(async move {
        recurring_alert_checks(
            resources_for_checks,
            task_manager_for_checks,
            resolver_for_checks,
            connection_pool_for_checks,
        )
        .await;
    });

    let debug_mode = is_debug_mode();

    // If debug mode, spawn periodic cache stats logging task
    if debug_mode {
        let pool_l = state.connection_pool.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                tracing::debug!(
                    target = "stats",
                    connection_pools = pool_l.len(),
                    "Periodic stats"
                );
            }
        });
    }

    start_webserver(state, alert_state, (*resources).clone(), debug_mode).await?;
    Ok(())
}
