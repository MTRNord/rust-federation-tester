use crate::federation::network::fetch_url_custom_sni_host;
use crate::response::{Error, ErrorCode, InvalidServerNameErrorCode, WellKnownResult};
use crate::validation::server_name::parse_and_validate_server_name;
use ::time as time_crate;
use futures::{StreamExt, stream::FuturesUnordered};
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::{Resolver, name_server::ConnectionProvider};
use std::net::IpAddr;
use tokio::time::{Duration, timeout};
use tracing::{info, warn};
use url::Url;

pub const NETWORK_TIMEOUT_SECS: u64 = 3;

/// Validate well-known response for security issues
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
        warn!(
            "Self-referential delegation detected: {} -> {}",
            original_server, m_server
        );
        // Allow but warn - this might be intentional
    }

    // 4. Validate against localhost/internal addresses to prevent SSRF
    let server_host = m_server.split(':').next().unwrap_or(m_server);
    if let Ok(ip) = server_host.parse::<IpAddr>() {
        if is_private_or_internal_ip(&ip) {
            return Err(Error {
                error: format!("m.server points to private/internal address: {}", m_server),
                error_code: ErrorCode::InvalidServerName(InvalidServerNameErrorCode::NotValidDNS),
            });
        }
    }

    // 5. Check for suspicious patterns
    if server_host.contains("localhost")
        || server_host.contains("127.0.0.1")
        || server_host.contains("::1")
    {
        return Err(Error {
            error: format!("m.server points to localhost: {}", m_server),
            error_code: ErrorCode::InvalidServerName(InvalidServerNameErrorCode::NotValidDNS),
        });
    }

    Ok(())
}

/// Check if an IP address is private or internal to prevent SSRF
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
    pub found_server: Option<String>,
    pub error: Option<Error>,
}

#[tracing::instrument(name = "lookup_server_well_known", skip(resolver), fields(server_name = %server_name))]
pub async fn lookup_server_well_known<P: ConnectionProvider>(
    server_name: &str,
    resolver: &Resolver<P>,
) -> WellKnownPhaseResult {
    if server_name.contains(':') {
        info!(
            "[check_well_known_pure] Skipping well-known lookup for {server_name} as it contains a port"
        );
        return WellKnownPhaseResult {
            well_known_result: vec![],
            found_server: None,
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
            let timeout_duration = Duration::from_secs(NETWORK_TIMEOUT_SECS);
            let (_resp_opt, result, server_candidate) =
                fetch_url_with_redirects(&addr, &server_name, &server_name, 10, timeout_duration)
                    .await;
            (addr, result, server_candidate)
        });
    }

    while let Some((addr, result, server_candidate)) = futures.next().await {
        well_known_result.push((addr.clone(), result.clone()));
        if let Some(server_str) = server_candidate
            && found_server.is_none()
        {
            // Only accept if parse_and_validate_server_name would not set error
            let mut temp_data = crate::response::Root::default();
            parse_and_validate_server_name(&mut temp_data, &server_str);
            if temp_data.error.is_none() {
                found_server = Some(server_str);
                break;
            }
        }
    }
    while let Some((addr, result, _)) = futures.next().await {
        well_known_result.push((addr, result));
    }
    WellKnownPhaseResult {
        well_known_result,
        found_server,
        error: None,
    }
}

#[tracing::instrument(name = "federation_fetch_with_redirects", fields(addr = %addr, host = %host, sni = %sni, max_redirects = %max_redirects))]
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
                    error: format!("Error fetching well-known URL: {e:#?}"),
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
