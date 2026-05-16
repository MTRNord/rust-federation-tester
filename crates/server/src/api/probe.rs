//! Proxy endpoints that fetch well-known Matrix URLs on behalf of the browser.
//!
//! Browsers cannot distinguish a CORS failure from a network error, so these
//! endpoints fetch specific, allowlisted URLs server-side and return the HTTP
//! status code, relevant response headers, and body.
//!
//! No authentication is required — the same information is publicly accessible
//! to any HTTP client; this is purely a CORS workaround.
//!
//! SSRF protection: only HTTPS URLs on non-private hosts are allowed.

use axum::{Json, extract::Query, response::IntoResponse};
use hyper::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};

const TAG: &str = "Probe API";

/// Creates the probe router.
pub fn router() -> OpenApiRouter {
    OpenApiRouter::new()
        .routes(routes!(probe_well_known))
        .routes(routes!(probe_client_api))
}

/// Query parameters for the well-known probe endpoint.
#[derive(Deserialize, IntoParams, Debug)]
struct ProbeWellKnownParams {
    /// Matrix homeserver domain (e.g. `matrix.example.com`).  Port suffixes
    /// are accepted (`example.com:8448`).
    server_name: String,
    /// Which well-known endpoint to probe.  Currently only `support` is accepted.
    endpoint: String,
}

/// Result of a server-side well-known probe.
#[derive(Serialize, ToSchema)]
struct ProbeWellKnownResponse {
    /// HTTP status code returned by the remote server.
    /// `0` means the server was unreachable (network / TLS error).
    status_code: u16,
    /// Value of the `Access-Control-Allow-Origin` response header,
    /// or `null` if the header was absent.
    cors_origin: Option<String>,
    /// Parsed JSON body (present only on 2xx responses).
    body: Option<serde_json::Value>,
}

#[tracing::instrument(skip(resources))]
#[utoipa::path(
    get,
    path = "/well-known",
    params(ProbeWellKnownParams),
    tag = TAG,
    operation_id = "Probe Well-Known Endpoint",
    summary = "Fetch a Matrix well-known URL server-side",
    description = "Fetches a specific Matrix well-known URL on behalf of the browser and \
                   returns the HTTP status code, CORS headers, and response body.  \
                   This allows the UI to distinguish CORS failures from network errors \
                   and 404 responses — information the browser deliberately hides from \
                   JavaScript for security reasons.\n\n\
                   **Allowed endpoints:**\n\
                   - `support` → `/.well-known/matrix/support`\n\
                   - `client` → `/.well-known/matrix/client`",
    responses(
        (status = 200, description = "Probe result (status_code=0 when the server is unreachable)", body = ProbeWellKnownResponse),
        (status = 400, description = "Invalid parameters"),
    ),
)]
async fn probe_well_known(
    Query(params): Query<ProbeWellKnownParams>,
    axum::Extension(resources): axum::Extension<crate::AppResources>,
) -> axum::response::Response {
    // ── Allowlist: only specific well-known paths may be probed ──────────────
    let path = match params.endpoint.as_str() {
        "support" => "/.well-known/matrix/support",
        "client" => "/.well-known/matrix/client",
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "endpoint must be one of: support, client" })),
            )
                .into_response();
        }
    };

    if params.server_name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "server_name is required" })),
        )
            .into_response();
    }

    // ── Build and validate the target URL ────────────────────────────────────
    let raw_url = format!("https://{}{}", params.server_name, path);
    let parsed = match url::Url::parse(&raw_url) {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "server_name produces an invalid URL" })),
            )
                .into_response();
        }
    };

    // Reject obvious SSRF targets.  Domain names are not DNS-resolved here;
    // we only block literal IP addresses that are known-private.
    let host = parsed.host_str().unwrap_or("");
    if host.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "server_name must not be empty" })),
        )
            .into_response();
    }
    if is_private_or_local(host) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "server_name must not be a private or local address" })),
        )
            .into_response();
    }

    // ── Perform the request ───────────────────────────────────────────────────
    fetch_and_respond(&resources.http_client, &raw_url, 10).await
}

// ── /api/probe/client-api ─────────────────────────────────────────────────────

/// Query parameters for the client-server API probe endpoint.
#[derive(Deserialize, IntoParams, Debug)]
struct ProbeClientApiParams {
    /// Absolute HTTPS base URL of the homeserver client-server API
    /// (e.g. `https://matrix.example.com`).  Must use HTTPS and must not
    /// resolve to a private address.
    base_url: String,
    /// Which client-server API path to probe (allowlist):
    /// `versions`, `rtc-transports-v1`, `rtc-transports-msc`,
    /// `room-summary-v1`, `room-summary-nheko`.
    path: String,
    /// Room ID for room-summary paths (e.g. `!probe:example.com`).
    /// Required when `path` is `room-summary-v1` or `room-summary-nheko`.
    room_id: Option<String>,
    /// `via` query parameter for room-summary paths.
    via: Option<String>,
}

#[tracing::instrument(skip(resources))]
#[utoipa::path(
    get,
    path = "/client-api",
    params(ProbeClientApiParams),
    tag = TAG,
    operation_id = "Probe Client-Server API Endpoint",
    summary = "Fetch a Matrix client-server API URL server-side",
    description = "Fetches a specific Matrix client-server API URL on behalf of the browser \
                   and returns the HTTP status code, CORS headers, and response body.  \
                   Used to distinguish CORS failures from real network errors when browser \
                   fetches silently fail.\n\n\
                   **Allowed paths:**\n\
                   - `versions` → `/_matrix/client/versions`\n\
                   - `rtc-transports-v1` → `/_matrix/client/v1/rtc/transports`\n\
                   - `rtc-transports-msc` → `/_matrix/client/unstable/org.matrix.msc4143/rtc/transports`\n\
                   - `room-summary-v1` → `/_matrix/client/v1/room_summary/{room_id}?via={via}` (requires `room_id`)\n\
                   - `room-summary-nheko` → `/_matrix/client/unstable/im.nheko.summary/summary/{room_id}?via={via}` (requires `room_id`)",
    responses(
        (status = 200, description = "Probe result (status_code=0 when the server is unreachable)", body = ProbeWellKnownResponse),
        (status = 400, description = "Invalid parameters"),
    ),
)]
async fn probe_client_api(
    Query(params): Query<ProbeClientApiParams>,
    axum::Extension(resources): axum::Extension<crate::AppResources>,
) -> axum::response::Response {
    // ── Allowlist ─────────────────────────────────────────────────────────────
    // Build the URL suffix; room-summary paths need the room_id baked in.
    let suffix_owned: String;
    let suffix: &str = match params.path.as_str() {
        "versions" => "/_matrix/client/versions",
        "rtc-transports-v1" => "/_matrix/client/v1/rtc/transports",
        "rtc-transports-msc" => "/_matrix/client/unstable/org.matrix.msc4143/rtc/transports",
        p @ ("room-summary-v1" | "room-summary-nheko") => {
            let room_id = match &params.room_id {
                Some(r) if !r.is_empty() => r.as_str(),
                _ => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({ "error": "room_id is required for room-summary paths" })),
                    )
                        .into_response()
                }
            };
            let via = params.via.as_deref().unwrap_or("");
            let encoded_id = urlencoding::encode(room_id);
            let encoded_via = urlencoding::encode(via);
            let api_path = if p == "room-summary-v1" {
                format!(
                    "/_matrix/client/v1/room_summary/{}?via={}",
                    encoded_id, encoded_via
                )
            } else {
                format!(
                    "/_matrix/client/unstable/im.nheko.summary/summary/{}?via={}",
                    encoded_id, encoded_via
                )
            };
            suffix_owned = api_path;
            &suffix_owned
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "path must be one of: versions, rtc-transports-v1, rtc-transports-msc, room-summary-v1, room-summary-nheko" })),
            )
                .into_response()
        }
    };

    if params.base_url.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "base_url is required" })),
        )
            .into_response();
    }

    // ── Validate base_url (SSRF prevention) ───────────────────────────────────
    let parsed = match url::Url::parse(&params.base_url) {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "base_url is not a valid URL" })),
            )
                .into_response();
        }
    };
    if parsed.scheme() != "https" {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "base_url must use HTTPS" })),
        )
            .into_response();
    }
    let host = parsed.host_str().unwrap_or("");
    if host.is_empty() || is_private_or_local(host) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "base_url must not point to a private or local address" })),
        )
            .into_response();
    }

    // ── Build target URL ──────────────────────────────────────────────────────
    let base = params.base_url.trim_end_matches('/');
    let target_url = format!("{}{}", base, suffix);

    // ── Perform the request ───────────────────────────────────────────────────
    fetch_and_respond(&resources.http_client, &target_url, 10).await
}

/// Fetch `url` with a timeout and return a JSON probe response.
async fn fetch_and_respond(
    client: &reqwest::Client,
    url: &str,
    timeout_secs: u64,
) -> axum::response::Response {
    let result = client
        .get(url)
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .send()
        .await;

    match result {
        Ok(resp) => {
            let status_code = resp.status().as_u16();
            let cors_origin = resp
                .headers()
                .get("access-control-allow-origin")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            let body = if resp.status().is_success() {
                resp.json::<serde_json::Value>().await.ok()
            } else {
                None
            };
            (
                StatusCode::OK,
                Json(ProbeWellKnownResponse {
                    status_code,
                    cors_origin,
                    body,
                }),
            )
                .into_response()
        }
        Err(_) => (
            StatusCode::OK,
            Json(ProbeWellKnownResponse {
                status_code: 0,
                cors_origin: None,
                body: None,
            }),
        )
            .into_response(),
    }
}

/// Returns `true` for hosts that must not be probed (SSRF prevention).
///
/// Blocks localhost strings and IP literals that fall in RFC 1918 / loopback /
/// link-local ranges.  Domain names are NOT DNS-resolved; callers relying solely
/// on this check accept that a domain could resolve to a private IP.
fn is_private_or_local(host: &str) -> bool {
    // String-based checks for well-known local names
    if host == "localhost" || host.ends_with(".local") || host.ends_with(".internal") {
        return true;
    }

    // IP literal checks
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => {
                v4.is_loopback()
                    || v4.is_private()
                    || v4.is_link_local()
                    || v4.is_broadcast()
                    || v4.is_unspecified()
            }
            std::net::IpAddr::V6(v6) => {
                v6.is_loopback()
                    || v6.is_unspecified()
                    // Unique-local (fc00::/7)
                    || (v6.segments()[0] & 0xfe00) == 0xfc00
                    // Link-local (fe80::/10)
                    || (v6.segments()[0] & 0xffc0) == 0xfe80
            }
        };
    }

    false
}
