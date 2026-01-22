//! Prometheus metrics endpoint.

use crate::AppResources;
use crate::api::health::MISC_TAG;

/// Prometheus metrics endpoint.
#[tracing::instrument(skip(resources))]
#[utoipa::path(
    get,
    path = "/metrics",
    tag = MISC_TAG,
    operation_id = "Prometheus Metrics",
    responses(
        (status = 200, description = "Prometheus metrics in text exposition format", body = String, content_type = "text/plain"),
        (status = 404, description = "Metrics disabled via configuration")
    )
)]
pub async fn metrics(
    axum::Extension(resources): axum::Extension<AppResources>,
) -> (hyper::StatusCode, String) {
    if !resources.config.statistics.enabled || !resources.config.statistics.prometheus_enabled {
        return (hyper::StatusCode::NOT_FOUND, String::new());
    }
    let body = crate::stats::build_prometheus_metrics_cached(&resources).await;
    (hyper::StatusCode::OK, body)
}
