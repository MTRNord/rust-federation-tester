//! Debug endpoints for internal use.
//!
//! These endpoints are only accessible from allowed networks (localhost/internal).

use crate::AppResources;
use crate::email_templates::{
    AccountVerificationEmailTemplate, FailureEmailTemplate, MagicLinkEmailTemplate,
    PasswordResetEmailTemplate, RecoveryEmailTemplate, ServerNameChangeEmailTemplate,
    TlsCertChangeEmailTemplate, TlsExpiryEmailTemplate, VerificationEmailTemplate,
    VersionChangeEmailTemplate,
};
use crate::release_notes::{fetch_release_excerpt_direct, get_release_info};
use axum::{
    Extension,
    extract::{ConnectInfo, Query},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
};
use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};
use utoipa_axum::{router::OpenApiRouter, routes};

pub const DEBUG_TAG: &str = "Debug";

/// Creates the debug router.
pub fn router() -> OpenApiRouter {
    OpenApiRouter::new()
        .routes(routes!(preview_verification_email))
        .routes(routes!(preview_failure_email))
        .routes(routes!(preview_recovery_email))
        .routes(routes!(preview_magic_link_email))
        .routes(routes!(preview_password_reset_email))
        .routes(routes!(preview_tls_expiry_email))
        .routes(routes!(preview_tls_cert_change_email))
        .routes(routes!(preview_version_change_email))
        .routes(routes!(preview_version_change_email_live))
        .routes(routes!(preview_account_verification_email))
        .routes(routes!(preview_server_name_change_email))
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
        environment_name: resources.config.environment_name.clone(),
        recipient_email: "user@example.com".to_string(),
        manage_url: Some("https://example.com/alerts".to_string()),
        sponsor_url: resources
            .config
            .github_sponsors_url
            .clone()
            .or_else(|| resources.config.liberapay_url.clone()),
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
        check_url: "https://example.com/results?serverName=example.matrix.org".to_string(),
        unsubscribe_url: "https://example.com/alerts/unsubscribe?token=sample-token".to_string(),
        failure_count: 3,
        reminder_interval: "24 hours".to_string(),
        failure_reason: Some(
            "Error fetching server version from 1.2.3.4:8448: connection refused".to_string(),
        ),
        environment_name: resources.config.environment_name.clone(),
        quiet_hours_note: None,
        first_detected: Some("2024-01-15T14:32:00Z".to_string()),
        minutes_down: Some(42),
        last_healthy: Some("2024-01-15T13:45:00Z".to_string()),
        error_hint: None,
        reminder_total: None,
        alert_url: "https://example.com/alerts/edit/1".to_string(),
        manage_url: "https://example.com/alerts".to_string(),
        sponsor_url: resources
            .config
            .github_sponsors_url
            .clone()
            .or_else(|| resources.config.liberapay_url.clone()),
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
        check_url: "https://example.com/results?serverName=example.matrix.org".to_string(),
        unsubscribe_url: "https://example.com/alerts/unsubscribe?token=sample-token".to_string(),
        environment_name: resources.config.environment_name.clone(),
        recovered_at: Some("2024-01-15T16:47:00Z".to_string()),
        first_detected: Some("2024-01-15T14:32:00Z".to_string()),
        minutes_down: Some(135),
        downtime_human: Some("2h 15m".to_string()),
        recovery_signal: None,
        recovery_hint: None,
        manage_url: "https://example.com/alerts".to_string(),
        sponsor_url: resources
            .config
            .github_sponsors_url
            .clone()
            .or_else(|| resources.config.liberapay_url.clone()),
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

/// Preview the magic link sign-in email template.
#[utoipa::path(
    get,
    path = "/email/magic-link",
    tag = DEBUG_TAG,
    operation_id = "Preview Magic Link Email",
    summary = "Preview magic link sign-in email template",
    description = "Renders the magic link sign-in email template with sample data.\n\n\
                   **Access control:** Only accessible from allowed networks.",
    responses(
        (status = 200, description = "Rendered HTML email template", content_type = "text/html"),
        (status = 403, description = "Access denied - client IP not in allowed networks"),
        (status = 500, description = "Template rendering failed"),
    )
)]
pub async fn preview_magic_link_email(
    Extension(resources): Extension<AppResources>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if !is_allowed(&resources, &addr, &headers) {
        return (StatusCode::FORBIDDEN, "Access denied").into_response();
    }

    let template = MagicLinkEmailTemplate {
        verify_url: "https://example.com/oauth2/magic-link/verify?token=sample-token-12345"
            .to_string(),
        environment_name: resources.config.environment_name.clone(),
        recipient_email: "user@example.com".to_string(),
        manage_url: "https://example.com/account".to_string(),
        sponsor_url: resources
            .config
            .github_sponsors_url
            .clone()
            .or_else(|| resources.config.liberapay_url.clone()),
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

/// Preview the password reset email template.
#[utoipa::path(
    get,
    path = "/email/password-reset",
    tag = DEBUG_TAG,
    operation_id = "Preview Password Reset Email",
    summary = "Preview password reset email template",
    description = "Renders the password reset email template with sample data.\n\n\
                   **Access control:** Only accessible from allowed networks.",
    responses(
        (status = 200, description = "Rendered HTML email template", content_type = "text/html"),
        (status = 403, description = "Access denied - client IP not in allowed networks"),
        (status = 500, description = "Template rendering failed"),
    )
)]
pub async fn preview_password_reset_email(
    Extension(resources): Extension<AppResources>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if !is_allowed(&resources, &addr, &headers) {
        return (StatusCode::FORBIDDEN, "Access denied").into_response();
    }

    let template = PasswordResetEmailTemplate {
        reset_url: "https://example.com/oauth2/password-reset/confirm?token=sample-token-12345"
            .to_string(),
        environment_name: resources.config.environment_name.clone(),
        recipient_email: "user@example.com".to_string(),
        manage_url: "https://example.com/account".to_string(),
        support_url: None,
        sponsor_url: resources
            .config
            .github_sponsors_url
            .clone()
            .or_else(|| resources.config.liberapay_url.clone()),
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

/// Preview the TLS certificate expiry warning email template.
#[utoipa::path(
    get,
    path = "/email/tls-expiry",
    tag = DEBUG_TAG,
    operation_id = "Preview TLS Expiry Email",
    summary = "Preview TLS certificate expiry email template",
    description = "Renders the TLS certificate expiry warning email template with sample data.\n\n\
                   The sample uses `days_remaining = 5` which triggers the urgent red banner (≤7 days).\n\n\
                   **Access control:** Only accessible from allowed networks.",
    responses(
        (status = 200, description = "Rendered HTML email template", content_type = "text/html"),
        (status = 403, description = "Access denied - client IP not in allowed networks"),
        (status = 500, description = "Template rendering failed"),
    )
)]
pub async fn preview_tls_expiry_email(
    Extension(resources): Extension<AppResources>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if !is_allowed(&resources, &addr, &headers) {
        return (StatusCode::FORBIDDEN, "Access denied").into_response();
    }

    let template = TlsExpiryEmailTemplate {
        server_name: "example.matrix.org".to_string(),
        expires_at: "2024-01-22 14:32 UTC".to_string(),
        expires_human: "Jan 22, 2024".to_string(),
        days_remaining: 5,
        check_url: "https://example.com/results?serverName=example.matrix.org".to_string(),
        unsubscribe_url: "https://example.com/alerts/unsubscribe?token=sample-token".to_string(),
        environment_name: resources.config.environment_name.clone(),
        issued_human: Some("Dec 23, 2023".to_string()),
        cert_cn: Some("example.matrix.org".to_string()),
        cert_san: Some("DNS:example.matrix.org".to_string()),
        cert_issuer: Some("Let's Encrypt Authority X3".to_string()),
        cert_fingerprint: Some(
            "AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78".to_string(),
        ),
        manage_url: "https://example.com/alerts".to_string(),
        sponsor_url: resources
            .config
            .github_sponsors_url
            .clone()
            .or_else(|| resources.config.liberapay_url.clone()),
        renewal_guide_url: None,
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

/// Preview the TLS certificate change notification email template.
#[utoipa::path(
    get,
    path = "/email/tls-cert-change",
    tag = DEBUG_TAG,
    operation_id = "Preview TLS Cert Change Email",
    summary = "Preview TLS certificate change notification email template",
    description = "Renders the TLS certificate rotation notification email template with sample data.\n\n\
                   **Access control:** Only accessible from allowed networks.",
    responses(
        (status = 200, description = "Rendered HTML email template", content_type = "text/html"),
        (status = 403, description = "Access denied - client IP not in allowed networks"),
        (status = 500, description = "Template rendering failed"),
    )
)]
pub async fn preview_tls_cert_change_email(
    Extension(resources): Extension<AppResources>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if !is_allowed(&resources, &addr, &headers) {
        return (StatusCode::FORBIDDEN, "Access denied").into_response();
    }

    let template = TlsCertChangeEmailTemplate {
        server_name: "example.matrix.org".to_string(),
        added_fingerprints: vec![
            "AABBCCDD112233445566778899AABBCCDD112233445566778899AABBCCDD1122".to_string(),
        ],
        removed_fingerprints: vec![
            "112233445566778899AABBCCDD112233445566778899AABBCCDD112233445566".to_string(),
        ],
        check_url: "https://example.com/results?serverName=example.matrix.org".to_string(),
        unsubscribe_url: "https://example.com/alerts/unsubscribe?token=sample-token".to_string(),
        environment_name: resources.config.environment_name.clone(),
        detected_at: Some("2024-01-15 14:32 UTC".to_string()),
        old_fingerprint: Some(
            "112233445566778899AABBCCDD112233445566778899AABBCCDD112233445566".to_string(),
        ),
        old_issuer: None,
        old_expires: None,
        new_fingerprint: Some(
            "AABBCCDD112233445566778899AABBCCDD112233445566778899AABBCCDD1122".to_string(),
        ),
        new_issuer: Some("Let's Encrypt Authority X3".to_string()),
        new_expires: Some("Apr 15, 2024".to_string()),
        alert_url: "https://example.com/alerts/edit/1".to_string(),
        manage_url: "https://example.com/alerts".to_string(),
        sponsor_url: resources
            .config
            .github_sponsors_url
            .clone()
            .or_else(|| resources.config.liberapay_url.clone()),
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

/// Preview the server version change notification email template.
#[utoipa::path(
    get,
    path = "/email/version-change",
    tag = DEBUG_TAG,
    operation_id = "Preview Version Change Email",
    summary = "Preview server version change email template",
    description = "Renders the server version change notification email template with sample data.\n\n\
                   **Access control:** Only accessible from allowed networks.",
    responses(
        (status = 200, description = "Rendered HTML email template", content_type = "text/html"),
        (status = 403, description = "Access denied - client IP not in allowed networks"),
        (status = 500, description = "Template rendering failed"),
    )
)]
pub async fn preview_version_change_email(
    Extension(resources): Extension<AppResources>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if !is_allowed(&resources, &addr, &headers) {
        return (StatusCode::FORBIDDEN, "Access denied").into_response();
    }

    let template = VersionChangeEmailTemplate {
        server_name: "example.matrix.org".to_string(),
        old_version_name: "Synapse".to_string(),
        old_version_string: "1.98.0".to_string(),
        new_version_name: "Synapse".to_string(),
        new_version_string: "1.99.0".to_string(),
        check_url: "https://example.com/results?serverName=example.matrix.org".to_string(),
        unsubscribe_url: "https://example.com/alerts/unsubscribe?token=sample-token".to_string(),
        environment_name: resources.config.environment_name.clone(),
        detected_at: Some("2024-01-15 14:32 UTC".to_string()),
        manage_url: "https://example.com/alerts".to_string(),
        sponsor_url: resources
            .config
            .github_sponsors_url
            .clone()
            .or_else(|| resources.config.liberapay_url.clone()),
        release_url: Some(
            "https://github.com/element-hq/synapse/releases/tag/v1.99.0".to_string(),
        ),
        release_notes_excerpt: Some(
            "<p style=\"margin:0 0 8px;font-size:13px;color:#2F2A25;line-height:1.6;\"><strong>Security fixes</strong></p><ul style=\"margin:0 0 8px;padding-left:18px;\"><li style=\"margin-bottom:2px;font-size:13px;color:#2F2A25;line-height:1.5;\">Fixed a vulnerability in the push rules handling.</li></ul><p style=\"margin:0 0 8px;font-size:13px;color:#2F2A25;line-height:1.6;\"><strong>Bug fixes</strong></p><ul style=\"margin:0 0 8px;padding-left:18px;\"><li style=\"margin-bottom:2px;font-size:13px;color:#2F2A25;line-height:1.5;\">Fixed room state not being correctly persisted in some cases.</li></ul>".to_string(),
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

/// Query parameters for the live version-change preview endpoint.
#[derive(Debug, Deserialize, Default)]
pub struct LiveVersionParams {
    /// Software name as it appears in the Matrix version endpoint (e.g. `Synapse`).
    pub software: Option<String>,
    /// Version string (e.g. `1.99.0` — without the leading `v`).
    pub version: Option<String>,
    /// Override: API type (`github` or `forgejo`). Uses config when absent.
    pub api_type: Option<String>,
    /// Override: repository slug (`owner/repo`). Uses config when absent.
    pub api_repo: Option<String>,
    /// Override: base URL for Forgejo instances. Uses config when absent.
    pub api_base_url: Option<String>,
    /// Override: release page URL (replaces template expansion from config).
    pub release_url: Option<String>,
}

/// Preview the version change email with a live release-notes API fetch.
#[utoipa::path(
    get,
    path = "/email/version-change-live",
    tag = DEBUG_TAG,
    operation_id = "Preview Version Change Email (Live)",
    summary = "Preview version change email with live release-notes fetch",
    description = "Renders the version change email after fetching real release notes from the \
                   upstream API. When `api_type` and `api_repo` are supplied as query params they \
                   override the config, so you can test any repo without adding it to \
                   `release_sources` first.\n\n\
                   **Minimal:** `?software=Synapse&version=1.99.0` (uses config)\n\
                   **Full override:** `?software=Synapse&version=1.99.0&api_type=github&api_repo=element-hq/synapse&release_url=https://...`\n\n\
                   **Access control:** Only accessible from allowed networks.",
    params(
        ("software" = String, Query, description = "Software name (e.g. Synapse)"),
        ("version" = String, Query, description = "Version string without leading v (e.g. 1.99.0)"),
        ("api_type" = Option<String>, Query, description = "Override: github or forgejo"),
        ("api_repo" = Option<String>, Query, description = "Override: owner/repo slug"),
        ("api_base_url" = Option<String>, Query, description = "Override: Forgejo base URL"),
        ("release_url" = Option<String>, Query, description = "Override: release page URL"),
    ),
    responses(
        (status = 200, description = "Rendered HTML email with live release notes", content_type = "text/html"),
        (status = 400, description = "Missing query parameters"),
        (status = 403, description = "Access denied"),
        (status = 500, description = "Template rendering failed"),
    )
)]
pub async fn preview_version_change_email_live(
    Extension(resources): Extension<AppResources>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(params): Query<LiveVersionParams>,
) -> Response {
    if !is_allowed(&resources, &addr, &headers) {
        return (StatusCode::FORBIDDEN, "Access denied").into_response();
    }

    let (Some(software), Some(version)) = (params.software, params.version) else {
        return (
            StatusCode::BAD_REQUEST,
            "Usage: /debug/email/version-change-live?software=Synapse&version=1.99.0\n\
             Optional overrides: &api_type=github&api_repo=element-hq/synapse&release_url=https://...",
        )
            .into_response();
    };

    // If the caller supplied explicit API params, use them directly (bypasses config).
    // Otherwise fall through to the normal config-driven path.
    let (release_url, release_notes_excerpt) =
        if let (Some(api_type), Some(api_repo)) = (&params.api_type, &params.api_repo) {
            let excerpt = fetch_release_excerpt_direct(
                api_type,
                api_repo,
                params.api_base_url.as_deref(),
                &version,
            )
            .await;
            (params.release_url, excerpt)
        } else {
            get_release_info(
                &resources.config,
                &resources.release_cache,
                &software,
                &version,
            )
            .await
        };

    let sponsor_url = resources
        .config
        .github_sponsors_url
        .clone()
        .or_else(|| resources.config.liberapay_url.clone());

    let template = VersionChangeEmailTemplate {
        server_name: "example.matrix.org".to_string(),
        old_version_name: software.clone(),
        old_version_string: "previous".to_string(),
        new_version_name: software,
        new_version_string: version,
        check_url: "https://example.com/results?serverName=example.matrix.org".to_string(),
        unsubscribe_url: "https://example.com/alerts/unsubscribe?token=sample-token".to_string(),
        environment_name: resources.config.environment_name.clone(),
        detected_at: Some("2024-01-15 14:32 UTC".to_string()),
        manage_url: "https://example.com/alerts".to_string(),
        sponsor_url,
        release_url,
        release_notes_excerpt,
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

/// Preview the account verification email template.
#[utoipa::path(
    get,
    path = "/email/account-verification",
    tag = DEBUG_TAG,
    operation_id = "Preview Account Verification Email",
    summary = "Preview account verification email template",
    description = "Renders the account verification email template with sample data.\n\n\
                   **Access control:** Only accessible from allowed networks.",
    responses(
        (status = 200, description = "Rendered HTML email template", content_type = "text/html"),
        (status = 403, description = "Access denied - client IP not in allowed networks"),
        (status = 500, description = "Template rendering failed"),
    )
)]
pub async fn preview_account_verification_email(
    Extension(resources): Extension<AppResources>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if !is_allowed(&resources, &addr, &headers) {
        return (StatusCode::FORBIDDEN, "Access denied").into_response();
    }

    let template = AccountVerificationEmailTemplate {
        verify_url: "https://example.com/oauth2/verify-email?token=sample-token-12345".to_string(),
        environment_name: resources.config.environment_name.clone(),
        recipient_email: "user@example.com".to_string(),
        manage_url: Some(format!(
            "{}/account",
            resources.config.frontend_url.trim_end_matches('/')
        )),
        sponsor_url: resources
            .config
            .github_sponsors_url
            .clone()
            .or_else(|| resources.config.liberapay_url.clone()),
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

/// Preview the server name / federation delegation change email template.
#[utoipa::path(
    get,
    path = "/email/server-name-change",
    tag = DEBUG_TAG,
    operation_id = "Preview Server Name Change Email",
    summary = "Preview federation delegation change email template",
    description = "Renders the server federation delegation change notification email template with sample data.\n\n\
                   **Access control:** Only accessible from allowed networks.",
    responses(
        (status = 200, description = "Rendered HTML email template", content_type = "text/html"),
        (status = 403, description = "Access denied - client IP not in allowed networks"),
        (status = 500, description = "Template rendering failed"),
    )
)]
pub async fn preview_server_name_change_email(
    Extension(resources): Extension<AppResources>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if !is_allowed(&resources, &addr, &headers) {
        return (StatusCode::FORBIDDEN, "Access denied").into_response();
    }

    let template = ServerNameChangeEmailTemplate {
        server_name: "example.matrix.org".to_string(),
        environment_name: resources.config.environment_name.clone(),
        detected_at: "2024-01-15 14:32 UTC".to_string(),
        old_delegation_target: "matrix.example.org:8448".to_string(),
        old_resolution_method: "well-known".to_string(),
        new_delegation_target: "matrix2.example.org:8448".to_string(),
        new_resolution_method: "well-known".to_string(),
        server_software: "Synapse".to_string(),
        server_version: "1.99.0".to_string(),
        federation_status: "healthy".to_string(),
        check_url: "https://example.com/results?serverName=example.matrix.org".to_string(),
        unsubscribe_url: "https://example.com/alerts/unsubscribe?token=sample-token".to_string(),
        manage_url: "https://example.com/alerts".to_string(),
        sponsor_url: resources
            .config
            .github_sponsors_url
            .clone()
            .or_else(|| resources.config.liberapay_url.clone()),
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
