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

// Logging guidelines due to otel:
// Use the correct log levels!
//
// name field: OpenTelemetry defines logs with name as Events, so every `tracing` Event is actually an OTel Event
// target field: Groups logs from the same module/crate. At recording time, `target` is stored in a top-level field. But exporters treat this information as OpenTelemetry `InstrumentationScope`
// level of an event: Maps directly to OpenTelemetry log severity levels
// Fields: Converted to OpenTelemetry log attributes
// Message: The main message of the log event, stored in the `body` field in OpenTelemetry
//
// This has to be followed to ensure proper mapping of tracing logs to OpenTelemetry logs.

#[cfg(all(not(feature = "console"), not(feature = "otel")))]
fn initialize_standard_tracing() {
    tracing_subscriber::fmt().init();
}

#[cfg(feature = "otel")]
fn initialize_otel_console_tracing() {
    use hyper_util::service;
    use opentelemetry::KeyValue;
    use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
    use opentelemetry_sdk::Resource;
    use opentelemetry_sdk::logs::SdkLoggerProvider;
    use tracing_subscriber::prelude::*;

    let service_name = std::env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| {
        // fallback to crate name
        env!("CARGO_PKG_NAME").to_string()
    });

    // Build a Resource that includes service.name
    let resource = Resource::builder()
        .with_service_name(service_name)
        .with_attribute(KeyValue::new(
            "service.version",
            env!("CARGO_PKG_VERSION").to_string(),
        ))
        .build();

    #[cfg(feature = "otlp")]
    let logging_provider = {
        use opentelemetry::global;
        use opentelemetry_otlp::LogExporter;
        use opentelemetry_otlp::Protocol;
        use opentelemetry_otlp::SpanExporter;
        use opentelemetry_otlp::WithExportConfig;

        let exporter = SpanExporter::builder()
            .with_http()
            .with_protocol(Protocol::HttpBinary)
            .build()
            .unwrap();

        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_batch_exporter(exporter)
            .with_resource(resource.clone())
            .build();
        global::set_tracer_provider(provider);

        let log_exporter = LogExporter::builder()
            .with_http()
            .with_protocol(Protocol::HttpBinary)
            .build()
            .unwrap();

        let logging_provider = SdkLoggerProvider::builder()
            .with_batch_exporter(log_exporter)
            .with_resource(resource.clone())
            .build();
        logging_provider
    };

    #[cfg(not(feature = "otlp"))]
    let logging_provider = {
        use opentelemetry_stdout::LogExporter;
        let exporter = LogExporter::default();

        let logging_provider = SdkLoggerProvider::builder()
            .with_simple_exporter(exporter)
            .with_resource(resource.clone())
            .build();
    };

    let otel_layer = OpenTelemetryTracingBridge::new(&logging_provider);

    tracing_subscriber::registry()
        .with(otel_layer)
        //.with(tracing_subscriber::fmt::layer())
        .init();
}

#[cfg(feature = "console")]
fn initialize_layered_tracing() {
    let default_directives = "rust_federation_tester=info,hyper=warn,sea_orm=info,tokio=trace,runtime=trace,tower_http=debug";
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
        tracing::info!(
            name = "startup.tracing_enabled",
            target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            message = "Tokio console tracing enabled"
        );
    }
    #[cfg(feature = "otel")]
    {
        initialize_otel_console_tracing();
        tracing::info!(
            name = "startup.tracing_enabled",
            target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            message = "OpenTelemetry tracing enabled"
        );
    }
    #[cfg(all(not(feature = "console"), not(feature = "otel")))]
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

    // Compute derived values for logging (explicit so fields are clear and type-safe)
    let stats_enabled = resources.config.statistics.enabled;
    let prometheus_enabled = resources.config.statistics.prometheus_enabled;
    let retention_days = resources.config.statistics.raw_retention_days;
    let salt_set = !resources.config.statistics.anonymization_salt.is_empty();

    // Emit a structured info event describing statistics config
    tracing::info!(
        name = "config.statistics",
        target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
        enabled = %stats_enabled,
        prometheus = %prometheus_enabled,
        retention_days = %retention_days,
        salt_set = %salt_set,
        message = "statistics configuration"
    );

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
                // Structured debug event for periodic stats
                tracing::debug!(
                    name = "stats.periodic",
                    target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                    connection_pools = pool_l.len(),
                    message = "Periodic stats"
                );
            }
        });
    }

    start_webserver(state, alert_state, (*resources).clone(), debug_mode).await?;
    Ok(())
}
