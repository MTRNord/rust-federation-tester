use crate::federation::network::fetch_url_custom_sni_host;
use crate::response::{Error, ErrorCode, InvalidServerNameErrorCode, WellKnownResult};
use crate::validation::server_name::parse_and_validate_server_name;
use ::time as time_crate;
use futures::{StreamExt, stream::FuturesUnordered};
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::{Resolver, name_server::ConnectionProvider};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tokio::time::{Duration, timeout};
use url::Url;

/// Default network timeout; overridden at startup by `init_federation_config`.
const DEFAULT_TIMEOUT_SECS: u64 = 3;

static FEDERATION_TIMEOUT_SECS: AtomicU64 = AtomicU64::new(DEFAULT_TIMEOUT_SECS);

/// When true, the SSRF check that rejects private/internal IPs is skipped.
/// Only set this to true for closed-federation / intranet deployments.
/// Enabling this on a public-facing instance allows users to probe internal network resources.
static ALLOW_PRIVATE_TARGETS: AtomicBool = AtomicBool::new(false);

/// Initialise federation-wide settings from the loaded config.
/// Must be called once at startup, before any requests are handled.
pub fn init_federation_config(timeout_secs: u64, allow_private_targets: bool) {
    FEDERATION_TIMEOUT_SECS.store(timeout_secs, Ordering::Relaxed);
    ALLOW_PRIVATE_TARGETS.store(allow_private_targets, Ordering::Relaxed);
}

/// Returns the configured federation network timeout as a `Duration`.
pub fn network_timeout() -> Duration {
    Duration::from_secs(FEDERATION_TIMEOUT_SECS.load(Ordering::Relaxed))
}

/// Kept for callers that still expect a raw `u64`.
#[deprecated(since = "0.2.0", note = "use `network_timeout()` instead")]
pub fn network_timeout_secs() -> u64 {
    FEDERATION_TIMEOUT_SECS.load(Ordering::Relaxed)
}

/// Validate well-known response for security issues
#[tracing::instrument()]
fn validate_well_known_security(original_server: &str, m_server: &str) -> Result<(), Error> {
    // 1. Prevent empty server names
    if m_server.is_empty() {
        return Err(Error {
            error: "Empty m.server value in well-known response".to_string(),
            error_code: ErrorCode::InvalidServerName(InvalidServerNameErrorCode::EmptyString),
        });
    }

    // 2. Length limits to prevent resource exhaustion
    if m_server.len() > 255 {
        return Err(Error {
            error: "m.server value too long (max 255 characters)".to_string(),
            error_code: ErrorCode::InvalidServerName(InvalidServerNameErrorCode::NotValidDNS),
        });
    }

    // 3. Prevent infinite redirect loops
    if m_server == original_server {
        tracing::warn!(
            name = "federation.lookup_server_well_known",
            target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            message = "Self-referential delegation detected",
            original_server = %original_server,
            m_server = %m_server
        );
        // Allow but warn - this might be intentional
    }

    // 4. Validate against localhost/internal addresses to prevent SSRF.
    //    This check is skipped when allow_private_targets is enabled (intranet deployments).
    if !ALLOW_PRIVATE_TARGETS.load(Ordering::Relaxed) {
        let server_host = m_server.split(':').next().unwrap_or(m_server);
        if let Ok(ip) = server_host.parse::<IpAddr>()
            && is_private_or_internal_ip(&ip)
        {
            return Err(Error {
                error: format!("m.server points to private/internal address: {}", m_server),
                error_code: ErrorCode::InvalidServerName(InvalidServerNameErrorCode::NotValidDNS),
            });
        }

        // 5. Check for suspicious patterns (only when SSRF guard is active)
        if server_host.contains("localhost")
            || server_host.contains("127.0.0.1")
            || server_host.contains("::1")
        {
            return Err(Error {
                error: format!("m.server points to localhost: {}", m_server),
                error_code: ErrorCode::InvalidServerName(InvalidServerNameErrorCode::NotValidDNS),
            });
        }
    }

    Ok(())
}

/// Check if an IP address is private or internal to prevent SSRF
#[tracing::instrument()]
fn is_private_or_internal_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private() ||
            v4.is_loopback() ||
            v4.is_link_local() ||
            // AWS metadata service
            (v4.octets()[0] == 169 && v4.octets()[1] == 254) ||
            // RFC 5737 test addresses
            (v4.octets()[0] == 192 && v4.octets()[1] == 0 && v4.octets()[2] == 2) ||
            (v4.octets()[0] == 198 && v4.octets()[1] == 51 && v4.octets()[2] == 100) ||
            (v4.octets()[0] == 203 && v4.octets()[1] == 0 && v4.octets()[2] == 113)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback() ||
            // Unique local addresses (fc00::/7)
            (v6.segments()[0] & 0xfe00) == 0xfc00 ||
            // Link local addresses (fe80::/10)
            (v6.segments()[0] & 0xffc0) == 0xfe80 ||
            // Documentation addresses (2001:db8::/32)
            (v6.segments()[0] == 0x2001 && v6.segments()[1] == 0x0db8)
        }
    }
}

#[derive(Debug, Clone)]
pub struct WellKnownPhaseResult {
    pub well_known_result: Vec<(String, WellKnownResult)>,
    /// The single globally-found server (from the first IP that succeeded), kept for
    /// backwards-compatible use in the SRV / no-well-known path.
    pub found_server: Option<String>,
    /// Per-IP outcome: for each IP that was probed, either `Some(delegated_server)` if
    /// well-known succeeded on that IP, or `None` if it failed (timeout, error, non-200, …).
    /// This lets callers apply the spec fallback (port 8448) on a per-IP basis.
    pub per_ip_found_server: std::collections::HashMap<String, Option<String>>,
    pub error: Option<Error>,
}

/// Returns true if server_name is an IPv4 literal or starts with `[` (IPv6 in brackets).
/// When true, well-known lookup must be skipped per the Matrix spec.
fn is_ip_literal(server_name: &str) -> bool {
    if server_name.starts_with('[') {
        return true;
    }
    // IPv4: the entire hostname (before any port) is a valid IPv4 address.
    let host = server_name.split(':').next().unwrap_or(server_name);
    host.parse::<std::net::Ipv4Addr>().is_ok()
}

#[tracing::instrument(skip(resolver))]
pub async fn lookup_server_well_known<P: ConnectionProvider>(
    server_name: &str,
    resolver: &Resolver<P>,
) -> WellKnownPhaseResult {
    // Spec step 1: IP literals skip well-known entirely.
    // Spec step 2: explicit port also skips well-known.
    if server_name.contains(':') || is_ip_literal(server_name) {
        tracing::info!(
            name = "federation.lookup_server_well_known",
            target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            message = "Skipping well-known lookup (IP literal or explicit port)",
            server_name = %server_name
        );
        return WellKnownPhaseResult {
            well_known_result: vec![],
            found_server: None,
            per_ip_found_server: std::collections::HashMap::new(),
            error: None,
        };
    }

    let server_lookup = format!("{server_name}.");
    let (ipv4_result, ipv6_result) = tokio::join!(
        resolver.lookup(&server_lookup, RecordType::A),
        resolver.lookup(&server_lookup, RecordType::AAAA)
    );

    let mut addrs: Vec<String> = vec![];
    if let Ok(lookup) = ipv4_result {
        for record in lookup.record_iter() {
            if let Some(ip) = record.data().as_a() {
                addrs.push(format!("{}:443", ip.0));
            }
        }
    }
    if let Ok(lookup) = ipv6_result {
        for record in lookup.record_iter() {
            if let Some(ip) = record.data().as_aaaa() {
                addrs.push(format!("[{}]:443", ip.0));
            }
        }
    }

    if addrs.is_empty() {
        return WellKnownPhaseResult {
            well_known_result: vec![],
            found_server: None,
            per_ip_found_server: std::collections::HashMap::new(),
            error: Some(Error {
                error: format!("No A/AAAA-Records for {server_name} found"),
                error_code: ErrorCode::NoRecordsFound,
            }),
        };
    }

    let mut found_server: Option<String> = None;
    let mut well_known_result: Vec<(String, WellKnownResult)> = vec![];
    let mut futures = FuturesUnordered::new();
    for addr in &addrs {
        let addr = addr.clone();
        let server_name = server_name.to_string();
        futures.push(async move {
            let timeout_duration = network_timeout();
            let (_resp_opt, result, server_candidate) =
                fetch_url_with_redirects(&addr, &server_name, &server_name, 10, timeout_duration)
                    .await;
            (addr, result, server_candidate)
        });
    }

    let mut per_ip_found_server: std::collections::HashMap<String, Option<String>> =
        std::collections::HashMap::new();

    while let Some((addr, result, server_candidate)) = futures.next().await {
        well_known_result.push((addr.clone(), result.clone()));
        match &server_candidate {
            Some(server_str) => {
                // Validate before accepting
                let mut temp_data = crate::response::Root::default();
                parse_and_validate_server_name(&mut temp_data, server_str);
                if temp_data.error.is_none() {
                    if found_server.is_none() {
                        found_server = Some(server_str.clone());
                        // Don't break — we still want to collect all per-IP results.
                    }
                    per_ip_found_server.insert(addr, Some(server_str.clone()));
                } else {
                    per_ip_found_server.insert(addr, None);
                }
            }
            None => {
                // Well-known failed or returned no m.server for this IP.
                per_ip_found_server.insert(addr, None);
            }
        }
    }
    WellKnownPhaseResult {
        well_known_result,
        found_server,
        per_ip_found_server,
        error: None,
    }
}

#[tracing::instrument()]
async fn fetch_url_with_redirects(
    addr: &str,
    host: &str,
    sni: &str,
    max_redirects: usize,
    timeout_duration: Duration,
) -> (
    Option<hyper::Response<hyper::body::Incoming>>,
    WellKnownResult,
    Option<String>,
) {
    use http_body_util::BodyExt;

    let mut redirects = 0;
    let mut current_addr = addr.to_string();
    let mut current_host = host.to_string();
    let mut current_sni = sni.to_string();
    let mut current_path = "/.well-known/matrix/server".to_string();
    let mut result = WellKnownResult::default();
    loop {
        let response = timeout(
            timeout_duration,
            fetch_url_custom_sni_host(&current_path, &current_addr, &current_host, &current_sni),
        )
        .await;
        match response {
            Ok(Ok(resp)) => {
                if let Some(resp) = resp.response {
                    let status = resp.status();
                    let headers = resp.headers().clone();
                    if status.is_success() {
                        if let Some(expires_header) = headers.get("Expires") {
                            if let Ok(expires_str) = expires_header.to_str()
                                && let Ok(expires_time) = time_crate::OffsetDateTime::parse(
                                    expires_str,
                                    &time_crate::format_description::well_known::Rfc2822,
                                )
                            {
                                result.cache_expires_at = expires_time.unix_timestamp();
                            }
                        } else if let Some(cache_control) = headers.get("Cache-Control")
                            && let Ok(cache_control_str) = cache_control.to_str()
                            && let Some(max_age) = cache_control_str
                                .split(',')
                                .find_map(|s| s.trim().strip_prefix("max-age="))
                            && let Ok(max_age_secs) = max_age.parse::<u64>()
                        {
                            result.cache_expires_at = time_crate::OffsetDateTime::now_utc()
                                .unix_timestamp()
                                + max_age_secs as i64;
                        }
                        if let Ok(body) = resp.into_body().collect().await {
                            let body = body.to_bytes();
                            // Use secure JSON parsing to prevent JSON bombs
                            match crate::security::secure_parse_json_slice(&body) {
                                Ok(json) => {
                                    if let Some(m_server) = json.get("m.server")
                                        && let Some(server_str) = m_server.as_str()
                                    {
                                        // Apply security validation before accepting the m.server value
                                        if let Err(security_error) =
                                            validate_well_known_security(&current_host, server_str)
                                        {
                                            result.error = Some(security_error);
                                            return (None, result, None);
                                        }

                                        result.m_server = server_str.to_string();
                                        return (None, result, Some(server_str.to_string()));
                                    }
                                }
                                Err(e) => {
                                    result.error = Some(Error {
                                        error: format!(
                                            "Invalid JSON in well-known response: {}",
                                            e
                                        ),
                                        error_code: ErrorCode::InvalidJson(e.to_string()),
                                    });
                                    return (None, result, None);
                                }
                            }
                        }
                        return (None, result, None);
                    } else if status.is_redirection() && redirects < max_redirects {
                        if let Some(location) = headers.get(hyper::header::LOCATION)
                            && let Ok(location_str) = location.to_str()
                        {
                            let new_url = if let Ok(url) = Url::parse(location_str) {
                                url
                            } else if let Ok(base) =
                                Url::parse(&format!("https://{current_host}{current_path}"))
                            {
                                base.join(location_str).unwrap_or(base)
                            } else {
                                let mut base = format!("https://{current_host}");
                                if !location_str.starts_with('/') {
                                    base.push('/');
                                }
                                Url::parse(&(base.clone() + location_str))
                                    .unwrap_or_else(|_| Url::parse(&base).unwrap())
                            };
                            if let Some(host_str) = new_url.host_str() {
                                let port = new_url.port().unwrap_or(443);
                                current_host = host_str.to_string();
                                current_addr = format!("{host_str}:{port}");
                                current_sni = host_str.to_string();
                            }
                            current_path = new_url.path().to_string();
                            redirects += 1;
                            continue;
                        }
                        result.error = Some(Error {
                            error: format!("Redirect ({status}) without valid Location header"),
                            error_code: ErrorCode::NotOk(status.to_string()),
                        });
                        return (None, result, None);
                    } else {
                        result.error = Some(Error {
                            error: format!("Error fetching well-known URL:  {status}"),
                            error_code: ErrorCode::NotOk(status.to_string()),
                        });
                        return (None, result, None);
                    }
                } else {
                    result.error = Some(Error {
                        error: "No response received from well-known URL".to_string(),
                        error_code: ErrorCode::NoResponse,
                    });
                    return (None, result, None);
                }
            }
            Ok(Err(e)) => {
                result.error = Some(Error {
                    error: format!("Error fetching well-known URL: {e}"),
                    error_code: ErrorCode::Unknown,
                });
                return (None, result, None);
            }
            Err(e) => {
                result.error = Some(Error {
                    error: format!("Timeout while fetching well-known URL: {e:?}"),
                    error_code: ErrorCode::Timeout,
                });
                return (None, result, None);
            }
        }
    }
}
