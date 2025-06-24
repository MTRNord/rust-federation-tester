use axum::extract::Query;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use hickory_resolver::name_server::ConnectionProvider;
use hickory_resolver::Resolver;
use rust_federation_tester::response::generate_json_report;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::{error, info};

#[derive(Deserialize)]
struct ApiParams {
    pub server_name: String,
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

    match generate_json_report(&params.server_name, state.resolver.as_ref()).await {
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

    match generate_json_report(&params.server_name, state.resolver.as_ref()).await {
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
}

#[tokio::main]
async fn main() -> color_eyre::eyre::Result<()> {
    color_eyre::install().expect("Failed to install `color_eyre::install`");
    tracing_subscriber::fmt().init();
    let resolver = Arc::new(Resolver::builder_tokio()?.build());
    let state = AppState { resolver };

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
