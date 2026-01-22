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
    responses(
        (status = OK, description = "Ok", body = str, content_type = "text/plain", example = "ok")
    )
)]
pub async fn health() -> &'static str {
    "ok"
}
