use hickory_resolver::Resolver;
use hickory_resolver::config::ResolverOpts;
use lettre::{AsyncSmtpTransport, Tokio1Executor, transport::smtp::authentication::Credentials};
use rust_federation_tester::AppResources;
use rust_federation_tester::alerts::{active_check_loop, healthy_check_loop};
use rust_federation_tester::api::federation_tester_api::AppState;
use rust_federation_tester::api::start_webserver;
use rust_federation_tester::config::load_config_or_panic;
use rust_federation_tester::connection_pool::ConnectionPool;
use rust_federation_tester::distributed;
use rust_federation_tester::federation::init_federation_config;

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
    use opentelemetry::KeyValue;
    use opentelemetry::global as otel_global;
    use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
    use opentelemetry_sdk::Resource;
    use opentelemetry_sdk::logs::SdkLoggerProvider;
    use opentelemetry_sdk::propagation::TraceContextPropagator;
    use tracing_subscriber::EnvFilter;
    use tracing_subscriber::fmt;
    use tracing_subscriber::prelude::*;

    let service_name =
        std::env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| env!("CARGO_PKG_NAME").to_string());

    let resource = Resource::builder()
        .with_service_name(service_name)
        .with_attribute(KeyValue::new(
            "service.version",
            env!("CARGO_PKG_VERSION").to_string(),
        ))
        .build();

    otel_global::set_text_map_propagator(TraceContextPropagator::new());

    // Only set up the OTel log bridge when an OTLP endpoint is explicitly configured.
    // When no endpoint is set the stdout OTel exporter produces verbose structured
    // output that replaces the normal fmt log format, which is not what we want.
    // In that case we skip the bridge and rely purely on tracing_subscriber::fmt.
    #[cfg(feature = "otlp")]
    let logging_provider: Option<SdkLoggerProvider> = {
        let otlp_endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
            .ok()
            .filter(|s| !s.is_empty());

        if let Some(_endpoint) = otlp_endpoint {
            use opentelemetry::global;
            use opentelemetry_otlp::{LogExporter, Protocol, SpanExporter, WithExportConfig};
            use opentelemetry_sdk::trace::Sampler;

            let exporter = SpanExporter::builder()
                .with_http()
                .with_protocol(Protocol::HttpBinary)
                .build()
                .unwrap();

            let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
                .with_batch_exporter(exporter)
                .with_resource(resource.clone())
                .with_sampler(Sampler::AlwaysOn)
                .build();
            global::set_tracer_provider(provider);

            let log_exporter = LogExporter::builder()
                .with_http()
                .with_protocol(Protocol::HttpBinary)
                .build()
                .unwrap();

            Some(
                SdkLoggerProvider::builder()
                    .with_batch_exporter(log_exporter)
                    .with_resource(resource.clone())
                    .build(),
            )
        } else {
            // No OTLP endpoint — skip OTel bridge, use plain fmt logging.
            None
        }
    };

    #[cfg(not(feature = "otlp"))]
    let logging_provider: Option<SdkLoggerProvider> = None;

    // Leak the provider so it lives for the entire process (required because the
    // global subscriber borrows it for the process lifetime).
    let otel_bridge_opt = logging_provider.map(|p| {
        let p: &'static SdkLoggerProvider = Box::leak(Box::new(p));
        OpenTelemetryTracingBridge::new(p)
    });

    let env_filter = EnvFilter::from_default_env();

    // When the `tracing-opentelemetry` feature is enabled, attach the tracing→OTel
    // span layer so spans are exported as typed OTel spans. The OTel logs bridge
    // (if any) and fmt layer are added on top.
    #[cfg(feature = "tracing-opentelemetry")]
    {
        let tracer = otel_global::tracer(concat!(env!("CARGO_PKG_NAME"), "::", module_path!()));
        let otel_trace_layer = tracing_opentelemetry::layer().with_tracer(tracer);
        tracing_subscriber::registry()
            .with(env_filter)
            .with(otel_trace_layer)
            .with(otel_bridge_opt)
            .with(fmt::layer().with_target(true).with_level(true))
            .init();
    }

    #[cfg(not(feature = "tracing-opentelemetry"))]
    {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(otel_bridge_opt)
            .with(fmt::layer().with_target(true).with_level(true))
            .init();
    }
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

#[tracing::instrument()]
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

    // Create an explicit application-level span early and enter it.
    // This span represents the lifetime of the whole process and is a natural place
    // to attach service-level fields that should appear on most telemetry.
    let service_name =
        std::env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| env!("CARGO_PKG_NAME").to_string());
    let app_span = tracing::info_span!(
        "app",
        target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
        service.name = %service_name,
        service.version = %env!("CARGO_PKG_VERSION")
    );
    let _app_enter = app_span.enter();

    // Load config
    let config = Arc::new(load_config_or_panic());

    tracing::debug!("Loading ring");
    let ring_provider = crypto::ring::default_provider();
    CryptoProvider::install_default(ring_provider).expect("Failed to install crypto provider");

    // Set up SeaORM database connection
    tracing::debug!("Loading database");
    let db = Arc::new(
        Database::connect(&config.database_url)
            .await
            .expect("Failed to connect to database"),
    );

    // Set up lettre SMTP client
    tracing::debug!("Loading SMTP client");
    let creds = Credentials::new(config.smtp.username.clone(), config.smtp.password.clone());
    let mailer = Arc::new(
        AsyncSmtpTransport::<Tokio1Executor>::relay(&config.smtp.server)
            .unwrap()
            .port(config.smtp.port)
            .credentials(creds)
            .timeout(Some(std::time::Duration::from_secs(
                config.smtp.timeout_secs,
            )))
            .build(),
    );

    // Apply federation configuration (timeout, private-target SSRF bypass) globally.
    // Must happen before the first request is handled.
    init_federation_config(config.federation_timeout_secs, config.allow_private_targets);
    tracing::info!(
        timeout_secs = config.federation_timeout_secs,
        allow_private_targets = config.allow_private_targets,
        "Federation configuration initialised"
    );

    // Set up resolver and caches.
    // Cap cached TTLs at 30 s so recent DNS changes are visible quickly while still
    // avoiding repeated lookups within a single test run.
    tracing::debug!("Loading resolver");
    let resolver = {
        let mut builder = Resolver::builder_tokio()?;
        let opts: &mut ResolverOpts = builder.options_mut();
        // Debug tool: cap TTL so DNS changes appear quickly.
        opts.positive_max_ttl = Some(Duration::from_secs(30));
        opts.negative_max_ttl = Some(Duration::from_secs(5));
        // Increase cache size from the default 32 to hold more concurrent server lookups.
        opts.cache_size = 256;
        Arc::new(builder.build())
    };
    let connection_pool = ConnectionPool::default();

    let state = AppState {
        resolver,
        connection_pool: connection_pool.clone(),
    };

    // Set up distributed coordination (Registry, Lock, EmailGuard).
    // When redis.url is configured, uses Redis/Valkey for multi-instance support.
    // Falls back to in-memory when url is empty or when the redis-backend feature
    // is not compiled in.
    let (registry, lock, email_guard) = if !config.redis.url.is_empty() {
        #[cfg(feature = "redis-backend")]
        {
            match distributed::redis_backed(&config.redis) {
                Ok(triplet) => {
                    tracing::info!(
                        url = %config.redis.url,
                        "Distributed coordination: Redis/Valkey connected"
                    );
                    triplet
                }
                Err(e) => {
                    tracing::error!(
                        url = %config.redis.url,
                        error = %e,
                        "Failed to create Redis/Valkey pool; falling back to in-memory single-instance mode"
                    );
                    distributed::in_memory()
                }
            }
        }
        #[cfg(not(feature = "redis-backend"))]
        {
            tracing::warn!(
                "redis.url is configured but binary was compiled without --features redis-backend; \
                 running in single-instance mode (rebuild with redis-backend to enable Valkey/Redis)"
            );
            distributed::in_memory()
        }
    } else {
        tracing::info!(
            "Distributed coordination: no redis.url configured, running in single-instance mode"
        );
        distributed::in_memory()
    };

    let resources = std::sync::Arc::new(AppResources {
        db,
        mailer,
        config,
        email_guard,
    });

    // Compute derived values for logging (explicit so fields are clear and type-safe)
    let stats_enabled = resources.config.statistics.enabled;
    let prometheus_enabled = resources.config.statistics.prometheus_enabled;
    let retention_days = resources.config.statistics.raw_retention_days;
    let salt_set = !resources.config.statistics.anonymization_salt.is_empty();

    tracing::debug_span!(
        "Checking statistics configuration",
        enabled = stats_enabled,
        prometheus = prometheus_enabled,
        retention_days = retention_days,
        salt_set = salt_set
    );

    // Start retention pruning task for federation stats (if enabled)
    rust_federation_tester::stats::spawn_retention_task(resources.clone());

    // Start background cleanup task for connection pool
    {
        let pool = connection_pool.clone();
        tracing::debug!("Starting background cleanup task for connection pool");
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(300)); // 5 minutes
            loop {
                interval.tick().await;
                pool.cleanup_dead_connections().await;
            }
        });
    }

    // Separate connection pool for background alert checks.
    // Per-client limits don't apply to internal batch work, so we use a pool
    // with no effective per-client cap (all background checks share "anonymous").
    let alert_pool = ConnectionPool::new_for_background_checks(5, 10);

    // Start the two-queue alert check loops
    tracing::debug!("Starting healthy alert check loop (5-min interval)");
    tokio::spawn(healthy_check_loop(
        resources.clone(),
        registry.clone(),
        lock.clone(),
        state.resolver.clone(),
        alert_pool.clone(),
    ));
    tracing::debug!("Starting active alert check loop (1-min interval)");
    tokio::spawn(active_check_loop(
        resources.clone(),
        registry,
        lock,
        state.resolver.clone(),
        alert_pool,
    ));

    let debug_mode = is_debug_mode();

    start_webserver(state, (*resources).clone(), debug_mode).await?;
    Ok(())
}
