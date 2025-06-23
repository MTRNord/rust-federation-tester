use axum::extract::Query;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use tracing::{error, info};

mod response;
mod utils;

#[derive(Deserialize)]
struct ApiParams {
    pub server_name: String,
}

async fn get_report(Query(params): Query<ApiParams>) -> impl IntoResponse {
    match response::generate_json_report(&params.server_name).await {
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
async fn get_fed_ok(Query(params): Query<ApiParams>) -> impl IntoResponse {
    match response::generate_json_report(&params.server_name).await {
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
#[tokio::main]
async fn main() -> color_eyre::eyre::Result<()> {
    color_eyre::install().expect("Failed to install `color_eyre::install`");
    tracing_subscriber::fmt().init();

    let app = Router::new()
        .route("/api/report", get(get_report))
        .route("/api/federation-ok", get(get_fed_ok));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    info!("Server running on http://0.0.0:8080");
    axum::serve(listener, app).await?;
    Ok(())
}
