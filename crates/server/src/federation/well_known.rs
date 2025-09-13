use crate::error::WellKnownError;
use crate::federation::network::fetch_url_custom_sni_host;
use crate::response::{Error, ErrorCode, Root, WellKnownResult};
use crate::validation::server_name::parse_and_validate_server_name;
use ::time as time_crate;
use futures::{StreamExt, stream::FuturesUnordered};
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::{Resolver, name_server::ConnectionProvider};
use tokio::time::{Duration, timeout};
use tracing::info;
use url::Url;

pub const NETWORK_TIMEOUT_SECS: u64 = 3;

#[tracing::instrument(name = "lookup_server_well_known", skip(data, resolver), fields(server_name = %server_name))]
pub async fn lookup_server_well_known<P: ConnectionProvider>(
    data: &mut Root,
    server_name: &str,
    resolver: &Resolver<P>,
) -> Result<Option<String>, WellKnownError> {
    if server_name.contains(':') {
        info!(
            "[lookup_server_well_known] Skipping well-known lookup for {server_name} as it contains a port"
        );
        return Ok(None);
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
        data.error = Some(Error {
            error: format!("No A/AAAA-Records for {server_name} found"),
            error_code: ErrorCode::NoRecordsFound,
        });
        return Err(WellKnownError::NoAddresses);
    }

    let mut found_server: Option<String> = None;
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
        data.well_known_result.insert(addr, result);
        if let Some(server_str) = server_candidate
            && found_server.is_none()
        {
            let mut temp_data = Root::default();
            parse_and_validate_server_name(&mut temp_data, &server_str);
            if temp_data.error.is_none() {
                found_server = Some(server_str);
                break;
            }
        }
    }
    while let Some((addr, result, _)) = futures.next().await {
        data.well_known_result.insert(addr, result);
    }
    Ok(found_server)
}

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
    use http_body_util::BodyExt; // for collect
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
                            if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&body)
                                && let Some(m_server) = json.get("m.server")
                                && let Some(server_str) = m_server.as_str()
                            {
                                result.m_server = server_str.to_string();
                                return (None, result, Some(server_str.to_string()));
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
                    error: format!("Timeout while fetching well-known URL: {e:#?}"),
                    error_code: ErrorCode::Timeout,
                });
                return (None, result, None);
            }
        }
    }
}
