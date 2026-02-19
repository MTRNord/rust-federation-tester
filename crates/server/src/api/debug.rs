//! Debug endpoints for internal use.
//!
//! These endpoints are only accessible from allowed networks (localhost/internal).

use crate::AppResources;
use crate::email_templates::{
    FailureEmailTemplate, RecoveryEmailTemplate, VerificationEmailTemplate,
};
use axum::{
    Extension,
    extract::ConnectInfo,
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
};
use std::net::{IpAddr, SocketAddr};
use utoipa_axum::{router::OpenApiRouter, routes};

pub const DEBUG_TAG: &str = "Debug";

/// Creates the debug router.
pub fn router() -> OpenApiRouter {
    OpenApiRouter::new()
        .routes(routes!(preview_verification_email))
        .routes(routes!(preview_failure_email))
        .routes(routes!(preview_recovery_email))
}

/// Check if the client IP is allowed to access debug endpoints.
fn is_allowed(resources: &AppResources, addr: &SocketAddr, headers: &HeaderMap) -> bool {
    // Get client IP from X-Forwarded-For or socket address
    let client_ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
        .unwrap_or(addr.ip());

    // Check if the client IP is in the allowed networks
    resources
        .config
        .debug_allowed_nets
        .iter()
        .any(|net| net.contains(&client_ip))
}

/// Preview the verification email template.
#[utoipa::path(
    get,
    path = "/email/verification",
    tag = DEBUG_TAG,
    operation_id = "Preview Verification Email",
    summary = "Preview verification email template",
    description = "Renders the email verification template with sample data for preview purposes.\n\n\
                   **Access control:** Only accessible from allowed networks (localhost, internal IPs). \
                   Configure allowed networks via `debug_allowed_nets` in the server configuration.",
    responses(
        (status = 200, description = "Rendered HTML email template", content_type = "text/html"),
        (status = 403, description = "Access denied - client IP not in allowed networks"),
        (status = 500, description = "Template rendering failed"),
    )
)]
pub async fn preview_verification_email(
    Extension(resources): Extension<AppResources>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if !is_allowed(&resources, &addr, &headers) {
        return (StatusCode::FORBIDDEN, "Access denied").into_response();
    }

    let template = VerificationEmailTemplate {
        server_name: "example.matrix.org".to_string(),
        verify_url: "https://example.com/verify?token=sample-token-12345".to_string(),
    };

    match template.render_html() {
        Ok(html) => Html(html).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to render template: {}", e),
        )
            .into_response(),
    }
}

/// Preview the failure email template.
#[utoipa::path(
    get,
    path = "/email/failure",
    tag = DEBUG_TAG,
    operation_id = "Preview Failure Email",
    summary = "Preview failure notification email template",
    description = "Renders the federation failure notification email template with sample data.\n\n\
                   Shows the email users receive when their monitored server has federation issues. \
                   Template includes reminder count and unsubscribe link.\n\n\
                   **Access control:** Only accessible from allowed networks.",
    responses(
        (status = 200, description = "Rendered HTML email template", content_type = "text/html"),
        (status = 403, description = "Access denied - client IP not in allowed networks"),
        (status = 500, description = "Template rendering failed"),
    )
)]
pub async fn preview_failure_email(
    Extension(resources): Extension<AppResources>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if !is_allowed(&resources, &addr, &headers) {
        return (StatusCode::FORBIDDEN, "Access denied").into_response();
    }

    let template = FailureEmailTemplate {
        server_name: "example.matrix.org".to_string(),
        check_url: "https://example.com/report/example.matrix.org".to_string(),
        unsubscribe_url: "https://example.com/unsubscribe?token=sample-token".to_string(),
        is_reminder: true,
        failure_count: 3,
        reminder_interval: "24 hours".to_string(),
        failure_reason: Some(
            "Error fetching server version from 1.2.3.4:8448: connection refused".to_string(),
        ),
    };

    match template.render_html() {
        Ok(html) => Html(html).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to render template: {}", e),
        )
            .into_response(),
    }
}

/// Preview the recovery email template.
#[utoipa::path(
    get,
    path = "/email/recovery",
    tag = DEBUG_TAG,
    operation_id = "Preview Recovery Email",
    summary = "Preview recovery notification email template",
    description = "Renders the federation recovery notification email template with sample data.\n\n\
                   Shows the email users receive when their monitored server recovers from federation issues.\n\n\
                   **Access control:** Only accessible from allowed networks.",
    responses(
        (status = 200, description = "Rendered HTML email template", content_type = "text/html"),
        (status = 403, description = "Access denied - client IP not in allowed networks"),
        (status = 500, description = "Template rendering failed"),
    )
)]
pub async fn preview_recovery_email(
    Extension(resources): Extension<AppResources>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if !is_allowed(&resources, &addr, &headers) {
        return (StatusCode::FORBIDDEN, "Access denied").into_response();
    }

    let template = RecoveryEmailTemplate {
        server_name: "example.matrix.org".to_string(),
        check_url: "https://example.com/report/example.matrix.org".to_string(),
        unsubscribe_url: "https://example.com/unsubscribe?token=sample-token".to_string(),
    };

    match template.render_html() {
        Ok(html) => Html(html).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to render template: {}", e),
        )
            .into_response(),
    }
}
