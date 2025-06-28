use axum::extract::Query;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use hickory_resolver::Resolver;
use hickory_resolver::name_server::ConnectionProvider;
use rust_federation_tester::cache::{DnsCache, VersionCache, WellKnownCache};
use rust_federation_tester::connection_pool::ConnectionPool;
use rust_federation_tester::response::generate_json_report;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use tokio::time::{Duration, interval};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::{error, info};

#[derive(Deserialize)]
struct ApiParams {
    pub server_name: String,
    /// Skip cache and force fresh requests - useful for debugging
    #[serde(default)]
    pub no_cache: bool,
}

async fn get_report<P: ConnectionProvider>(
    State(state): State<AppState<P>>,
    Query(params): Query<ApiParams>,
) -> impl IntoResponse {
    if params.server_name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "server_name parameter is required" })),
        );
    }

    match generate_json_report(
        &params.server_name.to_lowercase(),
        state.resolver.as_ref(),
        &state.connection_pool,
        &state.dns_cache,
        &state.well_known_cache,
        &state.version_cache,
        !params.no_cache,
    )
    .await
    {
        Ok(report) => {
            // Convert the report to a Value for JSON serialization
            let report = serde_json::to_value(report)
                .unwrap_or_else(|_| json!({ "error": "Failed to serialize report" }));
            (StatusCode::OK, Json(report))
        }
        Err(e) => {
            error!("Error generating report: {e:?}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": format!("Failed to generate report: {}", e)
                })),
            )
        }
    }
}
async fn get_fed_ok<P: ConnectionProvider>(
    State(state): State<AppState<P>>,
    Query(params): Query<ApiParams>,
) -> impl IntoResponse {
    if params.server_name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            "server_name parameter is required".to_string(),
        );
    }

    match generate_json_report(
        &params.server_name.to_lowercase(),
        state.resolver.as_ref(),
        &state.connection_pool,
        &state.dns_cache,
        &state.well_known_cache,
        &state.version_cache,
        !params.no_cache,
    )
    .await
    {
        Ok(report) => (
            StatusCode::OK,
            if report.federation_ok {
                "GOOD".to_string()
            } else {
                "BAD".to_string()
            },
        ),
        Err(e) => {
            error!("Error generating report: {e:?}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to generate report: {e}"),
            )
        }
    }
}

#[derive(Clone)]
struct AppState<P: ConnectionProvider> {
    resolver: Arc<Resolver<P>>,
    connection_pool: ConnectionPool,
    dns_cache: DnsCache,
    well_known_cache: WellKnownCache,
    version_cache: VersionCache,
}

#[tokio::main]
async fn main() -> color_eyre::eyre::Result<()> {
    color_eyre::install().expect("Failed to install `color_eyre::install`");
    tracing_subscriber::fmt().init();
    let resolver = Arc::new(Resolver::builder_tokio()?.build());

    // Initialize performance components
    let connection_pool = ConnectionPool::default();
    let dns_cache = DnsCache::default();
    let well_known_cache = WellKnownCache::default();
    let version_cache = VersionCache::default();

    let state = AppState {
        resolver,
        connection_pool: connection_pool.clone(),
        dns_cache,
        well_known_cache,
        version_cache,
    };

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

    let app = Router::new()
        .route("/api/report", get(get_report))
        .route("/api/federation-ok", get(get_fed_ok))
        .with_state(state)
        .route("/healthz", get(|| async { "OK" }))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    info!("Server running on http://0.0.0:8080");
    axum::serve(listener, app).await?;
    Ok(())
}
