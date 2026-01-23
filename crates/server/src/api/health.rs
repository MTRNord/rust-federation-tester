//! Health check endpoint.

/// Tag for OpenAPI documentation.
pub const MISC_TAG: &str = "Miscellaneous";

/// Health check endpoint.
#[tracing::instrument()]
#[utoipa::path(
    method(get, head),
    path = "/healthz",
    tag = MISC_TAG,
    operation_id = "Health Check",
    summary = "Service health check",
    description = "Returns a simple health status indicating the service is running and accepting requests.\n\n\
                   **Use cases:**\n\
                   - Kubernetes liveness/readiness probes\n\
                   - Load balancer health checks\n\
                   - Monitoring systems\n\n\
                   Supports both GET and HEAD methods for compatibility with various health check systems.",
    responses(
        (status = 200, description = "Service is healthy", body = str, content_type = "text/plain", example = "ok")
    )
)]
pub async fn health() -> &'static str {
    "ok"
}
