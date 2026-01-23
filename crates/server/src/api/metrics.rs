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
    summary = "Get Prometheus metrics",
    description = "Returns anonymized federation statistics in Prometheus text exposition format.\n\n\
                   **Available metrics:**\n\
                   - `federation_tester_checks_total`: Total federation checks performed\n\
                   - `federation_tester_success_rate`: Success rate by server (anonymized)\n\
                   - `federation_tester_features_enabled`: Count of servers with specific features\n\n\
                   **Configuration required:** Both `statistics.enabled` and `statistics.prometheus_enabled` \
                   must be `true` in the server configuration. Results are cached for performance.",
    responses(
        (status = 200, description = "Prometheus metrics in text exposition format", body = String, content_type = "text/plain; version=0.0.4"),
        (status = 404, description = "Metrics endpoint disabled (statistics.enabled or statistics.prometheus_enabled is false)")
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
