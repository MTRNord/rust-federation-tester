//! Federation tester API endpoints.
//!
//! Provides endpoints for testing Matrix federation compatibility:
//! - `/report` - Full JSON report of federation test
//! - `/federation-ok` - Simple GOOD/BAD status check
//! - `/debug/cache-stats` - Debug endpoint for connection pool stats (debug mode only)

use crate::{
    client::resolution::{fetch_client_server_versions, resolve_client_side_api},
    connection_pool::ConnectionPool,
    response::{Root, generate_json_report},
    stats::{self, StatEvent},
};
use axum::{
    Json,
    extract::{Query, State},
    response::IntoResponse,
};
use hickory_resolver::{Resolver, name_server::ConnectionProvider};
use hyper::{HeaderMap, StatusCode};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use utoipa::IntoParams;
use utoipa_axum::{router::OpenApiRouter, routes};

/// Tag for OpenAPI documentation.
pub const FEDERATION_TAG: &str = "Federation Tester API";

/// Query parameters for federation API endpoints.
#[derive(Deserialize, IntoParams, Debug)]
pub struct ApiParams {
    pub server_name: String,
    /// When true/1 this request consents to counting anonymized statistics.
    #[serde(default)]
    pub stats_opt_in: Option<bool>,
}

/// Shared state for federation tester endpoints.
#[derive(Clone)]
pub struct AppState<P: ConnectionProvider> {
    pub resolver: Arc<Resolver<P>>,
    pub connection_pool: ConnectionPool,
}

/// Creates the federation tester API router.
#[tracing::instrument(skip(state))]
pub fn router<P: ConnectionProvider>(state: AppState<P>, debug_mode: bool) -> OpenApiRouter {
    use axum::routing::get;
    let mut r = OpenApiRouter::new()
        .routes(routes!(get_report))
        .routes(routes!(get_fed_ok));

    if debug_mode {
        // Add non-documented debug route manually (not part of OpenAPI spec)
        r = r.route("/debug/cache-stats", get(cache_stats));
    }

    r.with_state(state)
}

#[tracing::instrument(skip(state, headers, resources))]
#[utoipa::path(
    get,
    path = "/report",
    params(ApiParams),
    tag = FEDERATION_TAG,
    operation_id = "Get Federation Report as JSON",
    responses(
        (status = 200, description = "JSON report of the federation test", body = Root, content_type = "application/json"),
        (status = 400, description = "Invalid request parameters", content_type = "application/json"),
        (status = 500, description = "Internal server error", content_type = "application/json")
    ),
)]
async fn get_report<P: ConnectionProvider>(
    Query(params): Query<ApiParams>,
    headers: HeaderMap,
    State(state): State<AppState<P>>,
    axum::Extension(resources): axum::Extension<crate::AppResources>,
) -> impl IntoResponse {
    let span = tracing::span!(
        tracing::Level::INFO,
        "Received request for federation report"
    );
    return span
        .in_scope(async move || {
            tracing::info!(
                "Received request for federation report with headers: {:?}",
                headers
            );
            if params.server_name.is_empty() {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": "server_name parameter is required" })),
                );
            }

            let server_name_lower = params.server_name.to_lowercase();

            match generate_json_report(
                &server_name_lower,
                state.resolver.as_ref(),
                &state.connection_pool,
            )
            .await
            {
                Ok(report) => {
                    if params.stats_opt_in.unwrap_or(false) && resources.config.statistics.enabled {
                        // Fetch client-server versions for unstable features tracking
                        let (unstable_enabled, unstable_announced) = if report.federation_ok {
                            let cs_address = resolve_client_side_api(&params.server_name).await;
                            let cs_versions = fetch_client_server_versions(&cs_address).await;

                            if let Some(features) = cs_versions.unstable_features {
                                let enabled: Vec<String> = features
                                    .iter()
                                    .filter_map(|(k, v)| if *v { Some(k.clone()) } else { None })
                                    .collect();
                                let announced: Vec<String> = features.keys().cloned().collect();
                                (Some(enabled), Some(announced))
                            } else {
                                (None, None)
                            }
                        } else {
                            (None, None)
                        };

                        stats::record_event(
                            &resources,
                            StatEvent {
                                server_name: &server_name_lower,
                                federation_ok: report.federation_ok,
                                version_name: Some(&report.version.name),
                                version_string: Some(&report.version.version),
                                unstable_features_enabled: unstable_enabled.as_deref(),
                                unstable_features_announced: unstable_announced.as_deref(),
                            },
                        )
                        .await;
                    }
                    // Convert the report to a Value for JSON serialization
                    let report = serde_json::to_value(report)
                        .unwrap_or_else(|_| json!({ "error": "Failed to serialize report" }));
                    (StatusCode::OK, Json(report))
                }
                Err(e) => {
                    tracing::error!(
                        name = "api.get_report.failed",
                        target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                        error = ?e,
                        message = "Error generating report"
                    );
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({
                            "error": format!("Failed to generate report: {}", e)
                        })),
                    )
                }
            }
        })
        .await;
}

#[tracing::instrument(skip(state))]
#[utoipa::path(
    get,
    path = "/federation-ok",
    params(ApiParams),
    tag = FEDERATION_TAG,
    operation_id = "Check Federation Status",
    responses(
        (status = 200, description = "Returns 'GOOD' if federation is ok, 'BAD' otherwise", body = inline(String), example = "GOOD"),
        (status = 400, description = "Invalid request parameters"),
        (status = 500, description = "Internal server error")
    ),
)]
async fn get_fed_ok<P: ConnectionProvider>(
    Query(params): Query<ApiParams>,
    State(state): State<AppState<P>>,
    axum::Extension(resources): axum::Extension<crate::AppResources>,
) -> impl IntoResponse {
    if params.server_name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            "server_name parameter is required".to_string(),
        );
    }

    let server_name_lower = params.server_name.to_lowercase();

    match generate_json_report(
        &server_name_lower,
        state.resolver.as_ref(),
        &state.connection_pool,
    )
    .await
    {
        Ok(report) => {
            if params.stats_opt_in.unwrap_or(false) && resources.config.statistics.enabled {
                // Fetch client-server versions for unstable features tracking
                let (unstable_enabled, unstable_announced) = if report.federation_ok {
                    let cs_address = resolve_client_side_api(&params.server_name).await;
                    let cs_versions = fetch_client_server_versions(&cs_address).await;

                    if let Some(features) = cs_versions.unstable_features {
                        let enabled: Vec<String> = features
                            .iter()
                            .filter_map(|(k, v)| if *v { Some(k.clone()) } else { None })
                            .collect();
                        let announced: Vec<String> = features.keys().cloned().collect();
                        (Some(enabled), Some(announced))
                    } else {
                        (None, None)
                    }
                } else {
                    (None, None)
                };

                stats::record_event(
                    &resources,
                    StatEvent {
                        server_name: &server_name_lower,
                        federation_ok: report.federation_ok,
                        version_name: Some(&report.version.name),
                        version_string: Some(&report.version.version),
                        unstable_features_enabled: unstable_enabled.as_deref(),
                        unstable_features_announced: unstable_announced.as_deref(),
                    },
                )
                .await;
            }
            (
                StatusCode::OK,
                if report.federation_ok {
                    "GOOD".to_string()
                } else {
                    "BAD".to_string()
                },
            )
        }
        Err(e) => {
            tracing::error!(
                name = "api.get_fed_ok.failed",
                target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                error = ?e,
                message = "Error generating report"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to generate report: {e}"),
            )
        }
    }
}

// Debug-only endpoint (conditionally added to router when debug_mode=true), therefore no OpenAPI doc.
#[tracing::instrument(skip(state))]
async fn cache_stats<P: ConnectionProvider>(
    State(state): State<AppState<P>>,
    axum::Extension(resources): axum::Extension<crate::AppResources>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
) -> impl IntoResponse {
    use serde::Serialize;
    if !is_allowed_ip(&addr, &resources.config.debug_allowed_nets) {
        return (
            hyper::StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({"error": "forbidden"})),
        );
    }

    #[derive(Serialize)]
    struct CombinedStats {
        connection_pools: usize,
    }
    let body = CombinedStats {
        connection_pools: state.connection_pool.len(),
    };
    let value = serde_json::to_value(body)
        .unwrap_or_else(|_| serde_json::json!({"error": "serialization failure"}));
    (hyper::StatusCode::OK, axum::Json(value))
}

#[tracing::instrument()]
fn is_allowed_ip(addr: &std::net::SocketAddr, nets: &[crate::config::IpNet]) -> bool {
    let ip = addr.ip();
    nets.iter().any(|net| net.contains(&ip))
}
