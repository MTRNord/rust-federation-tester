use hickory_resolver::Resolver;
use lettre::{AsyncSmtpTransport, Tokio1Executor, transport::smtp::authentication::Credentials};
use rust_federation_tester::AppResources;
use rust_federation_tester::api::alert_api::AlertAppState;
use rust_federation_tester::api::federation_tester_api::AppState;
use rust_federation_tester::api::start_webserver;
use rust_federation_tester::cache::{DnsCache, VersionCache, WellKnownCache};
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
use tracing::{Level, info};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> color_eyre::eyre::Result<()> {
    color_eyre::install().expect("Failed to install `color_eyre::install`");

    // -------- Tracing Initialization --------
    // Environment variables controlling behavior:
    // RFT_DEBUG = "1" enables debug-level logging & extra spans.
    // RFT_LOG_FORMAT = "json" for structured JSON logs (default pretty text).
    // RFT_TRACE_SPANS = "close" to emit span close events for latency measurement.
    let debug_mode = env::var("RFT_DEBUG")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let log_format = env::var("RFT_LOG_FORMAT").unwrap_or_else(|_| "text".into());
    let span_mode = env::var("RFT_TRACE_SPANS").unwrap_or_default();

    let base_level = if debug_mode {
        Level::DEBUG
    } else {
        Level::INFO
    };
    let default_directives = format!("rust_federation_tester={base_level},hyper=warn,sea_orm=info");
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_directives));

    // Build registry + formatting layer (separate branches keep concrete types simple)
    #[cfg(feature = "json")]
    {
        let registry = tracing_subscriber::registry().with(env_filter);
        if log_format == "json" {
            let mut layer = fmt::layer()
                .with_target(true)
                .json()
                .with_current_span(true);
            if span_mode == "close" {
                layer = layer.with_span_events(fmt::format::FmtSpan::CLOSE);
            }
            registry.with(layer).init();
        } else {
            let mut layer = fmt::layer().with_target(true).with_level(true);
            if span_mode == "close" {
                layer = layer.with_span_events(fmt::format::FmtSpan::CLOSE);
            }
            registry.with(layer).init();
        }
    }
    #[cfg(not(feature = "json"))]
    {
        let registry = tracing_subscriber::registry().with(env_filter);
        if log_format == "json" {
            tracing::warn!(
                "'json' log format requested but 'json' feature not enabled; falling back to text"
            );
        }
        let mut layer = fmt::layer().with_target(true).with_level(true);
        if span_mode == "close" {
            layer = layer.with_span_events(fmt::format::FmtSpan::CLOSE);
        }
        registry.with(layer).init();
    }

    if debug_mode {
        info!("Debug mode enabled (RFT_DEBUG=1)");
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

    // If debug mode, spawn periodic cache stats logging task
    if debug_mode {
        let dns_l = state.dns_cache.clone();
        let wk_l = state.well_known_cache.clone();
        let ver_l = state.version_cache.clone();
        let pool_l = state.connection_pool.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                let d = dns_l.stats();
                let w = wk_l.stats();
                let v = ver_l.stats();
                tracing::debug!(
                    target = "cache_stats",
                    dns_hits = d.hits,
                    dns_misses = d.misses,
                    dns_evictions = d.evictions,
                    wk_hits = w.hits,
                    wk_misses = w.misses,
                    ver_hits = v.hits,
                    ver_misses = v.misses,
                    connection_pools = pool_l.len(),
                    "Periodic cache stats"
                );
            }
        });
    }

    start_webserver(state, alert_state, resources, debug_mode).await?;
    Ok(())
}
