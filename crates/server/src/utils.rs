use crate::cache::{DnsCache, VersionCache, WellKnownCache};
use crate::connection_pool::ConnectionPool;
use crate::response::{
    Certificate, ConnectionReportData, Ed25519Check, Error, ErrorCode, InvalidServerNameErrorCode,
    Keys, Root, SRVData, Version, WellKnownResult,
};
use ::time as time_crate;
use base64::Engine;
use base64::prelude::BASE64_STANDARD_NO_PAD;
use bytes::Bytes;
use ed25519::Signature;
use ed25519::signature::Verifier;
use ed25519_dalek::VerifyingKey;
use futures::StreamExt;
use futures::stream::FuturesUnordered;
use hickory_resolver::ResolveErrorKind::Proto;
use hickory_resolver::name_server::ConnectionProvider;
use hickory_resolver::proto::ProtoErrorKind;
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::{ResolveErrorKind, Resolver};
use http_body_util::BodyExt;
use http_body_util::Empty;
use hyper::Request;
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::ServerName;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};
use tokio_rustls::TlsConnector;
use tracing::{debug, error};
use tracing::{info, warn};
use url::Url;
use x509_parser::prelude::*;

const NETWORK_TIMEOUT_SECS: u64 = 3;

fn absolutize_srv_target(target: &str, base: &str) -> String {
    if target.ends_with('.') {
        target.to_string()
    } else {
        format!("{}.{}.", target, base.trim_end_matches('.'))
    }
}

pub fn parse_and_validate_server_name(data: &mut Root, server_name: &str) {
    if server_name.is_empty() {
        data.error = Some(Error {
            error: "Invalid server name: empty string".to_string(),
            error_code: ErrorCode::InvalidServerName(InvalidServerNameErrorCode::EmptyString),
        });
    }

    // Split off the port if it exists
    let parts: Vec<&str> = server_name.split(':').collect();
    let hostname = parts[0];

    // Check if host part is one of:
    // - a valid (ascii) dns name
    // - an IP literal (IPv4 or IPv6)

    if hostname.is_empty() {
        data.error = Some(Error {
            error: "Invalid server name: empty hostname".to_string(),
            error_code: ErrorCode::InvalidServerName(InvalidServerNameErrorCode::EmptyHostname),
        });
        return;
    }

    if hostname.parse::<std::net::IpAddr>().is_err() {
        // Check if it's a valid DNS name
        if !hostname.is_ascii() || hostname.len() > 255 || hostname.contains("..") {
            data.error = Some(Error {
                error: format!("Invalid server name: {server_name} (Not a valid DNS name)",),
                error_code: ErrorCode::InvalidServerName(InvalidServerNameErrorCode::NotValidDNS),
            });
            return;
        }

        // Check for invalid characters in the hostname
        for c in hostname.chars() {
            if !c.is_ascii_alphanumeric() && c != '-' && c != '.' {
                data.error = Some(Error {
                    error: format!("Invalid server name: {server_name} (Invalid character '{c}')",),
                    error_code: ErrorCode::InvalidServerName(
                        InvalidServerNameErrorCode::InvalidCharacter,
                    ),
                });
                return;
            }
        }
    }
}

pub async fn lookup_server_well_known<P: ConnectionProvider>(
    data: &mut Root,
    server_name: &str,
    resolver: &Resolver<P>,
) -> Option<String> {
    // If there is an port in the server name, we skip the well-known lookup
    if server_name.contains(':') {
        info!(
            "[lookup_server_well_known] Skipping well-known lookup for {server_name} as it contains a port"
        );
        return None;
    }

    // Parallelize IPv4 and IPv6 lookups
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
        return None;
    }

    let mut found_server: Option<String> = None;

    // Parallelize well-known requests to all addresses
    let mut futures = FuturesUnordered::new();
    for addr in &addrs {
        let addr = addr.clone();
        let server_name = server_name.to_string();
        let timeout_duration = Duration::from_secs(NETWORK_TIMEOUT_SECS);

        futures.push(async move {
            let (_resp_opt, result, server_candidate) =
                fetch_url_with_redirects(&addr, &server_name, &server_name, 10, timeout_duration)
                    .await;
            (addr, result, server_candidate)
        });
    }
    async fn fetch_url_with_redirects(
        addr: &str,
        host: &str,
        sni: &str,
        max_redirects: usize,
        timeout_duration: Duration,
    ) -> (
        Option<hyper::Response<Incoming>>,
        WellKnownResult,
        Option<String>,
    ) {
        let mut redirects = 0;
        let mut current_addr = addr.to_string();
        let mut current_host = host.to_string();
        let mut current_sni = sni.to_string();
        let mut current_path = "/.well-known/matrix/server".to_string();
        let mut result = WellKnownResult::default();
        loop {
            let response = timeout(
                timeout_duration,
                fetch_url_custom_sni_host(
                    &current_path,
                    &current_addr,
                    &current_host,
                    &current_sni,
                ),
            )
            .await;

            match response {
                Ok(Ok(resp)) => {
                    if let Some(resp) = resp.response {
                        let status = resp.status();
                        let headers = resp.headers().clone();
                        if status.is_success() {
                            // Handle cache headers
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

                            // Always try to parse the body regardless of cache headers
                            if let Ok(body) = resp.into_body().collect().await {
                                let body = body.to_bytes();
                                if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&body)
                                    && let Some(m_server) = json.get("m.server")
                                    && let Some(server_str) = m_server.as_str()
                                {
                                    result.m_server = server_str.to_string();
                                    // Return the server string for validation
                                    return (None, result, Some(server_str.to_string()));
                                }
                            }
                            // Not a valid body, return as is
                            return (None, result, None);
                        } else if status.is_redirection() && redirects < max_redirects {
                            // Follow redirect
                            if let Some(location) = headers.get(hyper::header::LOCATION)
                                && let Ok(location_str) = location.to_str()
                            {
                                // Try to parse as absolute or relative URL
                                let new_url = if let Ok(url) = Url::parse(location_str) {
                                    url
                                } else if let Ok(base) =
                                    Url::parse(&format!("https://{current_host}{current_path}"))
                                {
                                    base.join(location_str).unwrap_or(base)
                                } else {
                                    // fallback: treat as path
                                    let mut base = format!("https://{current_host}");
                                    if !location_str.starts_with('/') {
                                        base.push('/');
                                    }
                                    Url::parse(&(base.clone() + location_str))
                                        .unwrap_or_else(|_| Url::parse(&base).unwrap())
                                };
                                // Update host/addr/port if needed
                                if let Some(host_str) = new_url.host_str() {
                                    current_host = host_str.to_string();
                                    // If port is present, use it, else default to 443
                                    let port = new_url.port().unwrap_or(443);
                                    let addr_str = format!("{host_str}:{port}");
                                    current_addr = addr_str;
                                    current_sni = host_str.to_string();
                                }
                                current_path = new_url.path().to_string();
                                redirects += 1;
                                continue;
                            }
                            // No valid location header, treat as error
                            result.error = Some(Error {
                                error: format!("Redirect ({status}) without valid Location header"),
                                error_code: ErrorCode::NotOk(status.to_string()),
                            });
                            return (None, result, None);
                        } else {
                            // Not success, not redirect, treat as error
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

    // Process results as they come in
    while let Some((addr, result, server_candidate)) = futures.next().await {
        data.well_known_result.insert(addr, result);

        // If we found a valid server and haven't found one yet, validate and use it
        if let Some(server_str) = server_candidate
            && found_server.is_none()
        {
            let mut temp_data = Root::default();
            parse_and_validate_server_name(&mut temp_data, &server_str);
            if temp_data.error.is_none() {
                found_server = Some(server_str);
                // We can break early once we find the first valid server
                break;
            }
        }
    }

    // Process any remaining futures to complete the well-known results
    while let Some((addr, result, _)) = futures.next().await {
        data.well_known_result.insert(addr, result);
    }

    found_server
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VersionResp {
    pub server: Version,
}

pub async fn query_server_version(
    data: &mut ConnectionReportData,
    addr: &str,
    sni: &str,
    federation_address: &str,
) -> color_eyre::eyre::Result<()> {
    match fetch_url_custom_sni_host(
        "/_matrix/federation/v1/version",
        addr,
        sni,
        federation_address,
    )
    .await
    {
        Ok(response) => {
            let response = response.response.unwrap();
            let status = response.status();
            let headers = response.headers().clone();
            let body = response.into_body().collect().await?.to_bytes();
            if status.is_success() {
                if let Some(response_type) = headers.get("Content-Type") {
                    if !response_type
                        .to_str()
                        .unwrap_or("")
                        .contains("application/json")
                    {
                        error!(
                            "Unexpected Content-Type: {}. Expected application/json",
                            response_type.to_str().unwrap_or("")
                        );
                        data.error = Some(Error {
                            error: "Unexpected Content-Type in server version response".to_string(),
                            error_code: ErrorCode::UnexpectedContentType(
                                response_type.to_str().unwrap_or("Unknown").to_string(),
                            ),
                        });
                        data.checks.server_version_parses = false;
                        return Ok(());
                    }
                } else {
                    error!(
                        "No Content-Type header in server version response: {:#?}\nBody: {}",
                        headers,
                        String::from_utf8_lossy(&body).to_string()
                    );
                    data.error = Some(Error {
                        error: "No Content-Type header in server version response".to_string(),
                        error_code: ErrorCode::MissingContentType,
                    });
                    data.checks.server_version_parses = false;
                    return Ok(());
                }

                match serde_json::from_slice::<VersionResp>(&body) {
                    Ok(json) => {
                        data.version = json.server;
                    }
                    Err(e) => {
                        error!(
                            "Error parsing server version response: {e:#?}\nBody: {}",
                            String::from_utf8_lossy(&body)
                        );
                        data.error = Some(Error {
                            error: "Failed to parse server version response".to_string(),
                            error_code: ErrorCode::InvalidJson(e.to_string()),
                        });
                        data.checks.server_version_parses = false;
                        return Ok(());
                    }
                }
            } else {
                error!("Error querying server version: {}", status);
                data.error = Some(Error {
                    error: format!("Error querying server version: {status}"),
                    error_code: ErrorCode::NotOk(status.to_string()),
                });
                data.checks.server_version_parses = false;
                return Ok(());
            }
        }
        Err(e) => {
            error!("Error fetching server version: {e:#?}");
            data.error = Some(Error {
                error: format!("Error fetching server version: {e:#?}"),
                error_code: ErrorCode::Unknown,
            });
            data.checks.server_version_parses = false;
            return Ok(());
        }
    }

    data.checks.server_version_parses = true;

    Ok(())
}

pub async fn lookup_server<P: ConnectionProvider>(
    data: &mut Root,
    server_name: &str,
    resolver: &Resolver<P>,
) -> color_eyre::eyre::Result<()> {
    use futures::StreamExt;
    use futures::stream::FuturesUnordered;

    info!("[lookup_server] Looking up server {server_name}");

    if !server_name.contains(':') {
        // Try _matrix-fed._tcp first
        let mut found_srv_records = false;
        for srv_prefix in ["_matrix-fed._tcp", "_matrix._tcp"] {
            info!(
                "[lookup_server] Looking up srv {}",
                format!("{srv_prefix}.{server_name}.")
            );
            let srv_records = timeout(
                Duration::from_secs(NETWORK_TIMEOUT_SECS),
                resolver.srv_lookup(&format!("{srv_prefix}.{server_name}.")),
            )
            .await?;

            match srv_records {
                Ok(records) if !records.as_lookup().is_empty() => {
                    for record in records.iter() {
                        let srv = record.clone();
                        let target = absolutize_srv_target(&srv.target().to_utf8(), server_name);

                        info!("[lookup_server] Looking up {target}");
                        match timeout(
                            Duration::from_secs(NETWORK_TIMEOUT_SECS),
                            resolver.lookup(&target, RecordType::CNAME),
                        )
                        .await?
                        {
                            Ok(cname) => {
                                let cname_target = cname.record_iter().next().map(|c| {
                                    c.data()
                                        .as_cname()
                                        .expect("CNAME record expected")
                                        .to_utf8()
                                });
                                if cname_target.clone().is_some_and(|c| c != target) {
                                    let srv_data = SRVData {
                                        target: cname_target.unwrap(),
                                        srv_prefix: Some(srv_prefix.to_string()),
                                        addrs: vec![],
                                        error: Some(Error {
                                            error_code: ErrorCode::SRVPointsToCNAME,
                                            error: format!(
                                                "SRV record target {target} is a CNAME record, which is forbidden (as per RFC2782)"
                                            ),
                                        }),
                                        port: srv.port(),
                                        priority: Some(srv.priority()),
                                        weight: Some(srv.weight()),
                                    };

                                    let existing = data.dnsresult.srv_targets.get_mut(&target);
                                    if let Some(existing) = existing {
                                        existing.push(srv_data);
                                    } else {
                                        data.dnsresult
                                            .srv_targets
                                            .insert(target.clone(), vec![srv_data]);
                                    }

                                    continue;
                                }
                            }
                            Err(e) => {
                                if let ResolveErrorKind::Proto(proto_error) = e.kind()
                                    && let ProtoErrorKind::NoRecordsFound { .. } =
                                        proto_error.kind()
                                {
                                    let cname_target = target.clone();
                                    let srv_data = SRVData {
                                        target: cname_target,
                                        srv_prefix: Some(srv_prefix.to_string()),
                                        addrs: vec![],
                                        error: None,
                                        port: srv.port(),
                                        priority: Some(srv.priority()),
                                        weight: Some(srv.weight()),
                                    };

                                    let existing = data.dnsresult.srv_targets.get_mut(&target);
                                    if let Some(existing) = existing {
                                        existing.push(srv_data);
                                    } else {
                                        data.dnsresult
                                            .srv_targets
                                            .insert(target.clone(), vec![srv_data]);
                                    }
                                } else {
                                    let srv_data = SRVData {
                                        target: target.clone(),
                                        srv_prefix: Some(srv_prefix.to_string()),
                                        addrs: vec![],
                                        error: Some(Error {
                                            error_code: ErrorCode::Unknown,
                                            error: format!(
                                                "Unknown error during CNAME lookup for {target}"
                                            ),
                                        }),
                                        port: srv.port(),
                                        priority: Some(srv.priority()),
                                        weight: Some(srv.weight()),
                                    };

                                    let existing = data.dnsresult.srv_targets.get_mut(&target);
                                    if let Some(existing) = existing {
                                        existing.push(srv_data);
                                    } else {
                                        data.dnsresult
                                            .srv_targets
                                            .insert(target.clone(), vec![srv_data]);
                                    }
                                }
                            }
                        }
                        // A/AAAA lookups and rest of logic remain unchanged
                    }
                    found_srv_records = true;
                }
                Err(e) => {
                    if let Proto(proto_error) = e.kind()
                        && let ProtoErrorKind::Timeout = proto_error.kind()
                    {
                        return Err(color_eyre::eyre::eyre!(
                            "Timeout while looking up SRV records for {server_name}: {e}"
                        ));
                    }
                    // If not found, try next prefix
                }
                _ => {
                    // No records found, try next prefix
                }
            }
        }
        if !found_srv_records {
            // No SRV records found for either prefix, insert fallback
            data.dnsresult.srv_targets.insert(
                server_name.to_string(),
                vec![SRVData {
                    target: server_name.to_string(),
                    srv_prefix: None,
                    addrs: vec![],
                    // This is a fallthrough case. So no error is expected.
                    error: None,
                    priority: None,
                    weight: None,
                    port: 8448,
                }],
            );
        }
    } else {
        // TODO: Consider doing this anyway? Might make sense for debugging to still check if it exists anyway but warn about it not being used.
        info!("[lookup_server] No SRV lookup for {server_name} as it contains a port");
        data.dnsresult.srvskipped = true;
    }

    let mut lookup_tasks = FuturesUnordered::new();
    for (host, records) in data.dnsresult.srv_targets.clone() {
        let resolver = resolver.clone();
        let host = if host.ends_with('.') {
            host
        } else {
            format!("{host}.")
        };
        let records = records.clone();
        lookup_tasks.push(async move {
            // CNAME-Lookup (optional)
            let cname_resp = timeout(
                Duration::from_secs(NETWORK_TIMEOUT_SECS),
                resolver.lookup(&host, RecordType::CNAME),
            )
            .await;

            // A- und AAAA-Lookup parallel
            let a_lookup = timeout(
                Duration::from_secs(NETWORK_TIMEOUT_SECS),
                resolver.lookup(&host, RecordType::A),
            );
            let aaaa_lookup = timeout(
                Duration::from_secs(NETWORK_TIMEOUT_SECS),
                resolver.lookup(&host, RecordType::AAAA),
            );
            let (ipv4_records, ipv6_records) = tokio::try_join!(a_lookup, aaaa_lookup)?;

            Ok::<_, color_eyre::eyre::Error>((
                host,
                records,
                cname_resp,
                ipv4_records,
                ipv6_records,
            ))
        });
    }

    while let Some(result) = lookup_tasks.next().await {
        match result {
            Ok((host, mut records, cname_resp, ipv4_records, ipv6_records)) => {
                let cname_target = if let Ok(Ok(cname)) = &cname_resp {
                    cname.record_iter().next().map(|c| {
                        c.data()
                            .as_cname()
                            .expect("CNAME record expected")
                            .to_utf8()
                            .to_string()
                    })
                } else {
                    None
                };

                for record in records.iter_mut() {
                    let target = record.target.clone();
                    let port = record.port;
                    debug!(
                        "Found SRV record for {host} -> {target}:{port} (priority: {:?}, weight: {:?})",
                        record.priority, record.weight
                    );

                    let mut addrs: Vec<String> = vec![];
                    let mut addrs_with_port: Vec<String> = vec![];
                    match ipv4_records {
                        Ok(ref ipv4) => {
                            for addr in ipv4.record_iter() {
                                if let Some(ip) = addr.data().as_a() {
                                    addrs.push(ip.0.to_string());
                                    addrs_with_port.push(format!("{}:{}", ip.0, port));
                                }
                            }
                        }
                        Err(ref e) => {
                            warn!("Error looking up A records for {host}: {e:#?}");
                        }
                    }

                    match ipv6_records {
                        Ok(ref ipv6) => {
                            for addr in ipv6.record_iter() {
                                if let Some(ip) = addr.data().as_aaaa() {
                                    addrs.push(ip.0.to_string());
                                    addrs_with_port.push(format!("[{}]:{port}", ip.0));
                                }
                            }
                        }
                        Err(ref e) => {
                            warn!("Error looking up AAAA records for {host}: {e:#?}");
                        }
                    }

                    if addrs.is_empty() {
                        continue;
                    }

                    let canonical_target = cname_target.clone().unwrap_or(target.clone());
                    let dns_formatted_target = if canonical_target.ends_with('.') {
                        canonical_target
                    } else {
                        format!("{canonical_target}.")
                    };

                    info!(
                        "Resolved {host} to {dns_formatted_target} with {} addresses and server_name {server_name}",
                        addrs.len()
                    );

                    record.addrs.extend(addrs_with_port.clone());
                    data.dnsresult.addrs.extend(addrs_with_port.clone());
                }
                data.dnsresult.srv_targets.insert(host, records);
            }
            Err(e) => {
                error!("DNS-Lookup-Fehler: {e:#?}");
            }
        }
    }

    // Also look up the general A/AAAA records for the server name
    if data.dnsresult.srvskipped {
        let server_part = server_name.split(':').next().unwrap();
        let port = if server_name.contains(':') {
            server_name.split(':').nth(1).unwrap_or("8448")
        } else {
            "8448"
        };
        info!(
            "[lookup_server] Looking up A/AAAA records for {server_part} as SRV lookup was skipped"
        );
        let host_server_name = format!("{server_part}.");
        let a_lookup = timeout(
            Duration::from_secs(NETWORK_TIMEOUT_SECS),
            resolver.lookup(&host_server_name, RecordType::A),
        );
        let aaaa_lookup = timeout(
            Duration::from_secs(NETWORK_TIMEOUT_SECS),
            resolver.lookup(&host_server_name, RecordType::AAAA),
        );
        let (ipv4_records, ipv6_records) = tokio::try_join!(a_lookup, aaaa_lookup)?;
        let mut addrs: Vec<String> = vec![];
        let mut addrs_with_port: Vec<String> = vec![];
        match ipv4_records {
            Ok(ref ipv4) => {
                for addr in ipv4.record_iter() {
                    if let Some(ip) = addr.data().as_a() {
                        addrs.push(ip.0.to_string());
                        addrs_with_port.push(format!("{}:{port}", ip.0));
                    }
                }
            }
            Err(ref e) => {
                warn!("Error looking up A records for {server_part}: {e:#?}");
            }
        }
        match ipv6_records {
            Ok(ref ipv6) => {
                for addr in ipv6.record_iter() {
                    if let Some(ip) = addr.data().as_aaaa() {
                        addrs.push(ip.0.to_string());
                        addrs_with_port.push(format!("[{}]:{port}", ip.0));
                    }
                }
            }
            Err(ref e) => {
                warn!("Error looking up AAAA records for {server_part}: {e:#?}");
            }
        }
        if !addrs.is_empty() {
            info!(
                "Resolved {server_part} to {} addresses with server_name {server_name}",
                addrs.len()
            );
            data.dnsresult.addrs.extend(addrs_with_port);
        } else {
            warn!("No A/AAAA records found for {server_part}");
            // TODO: Pass to user?
        }
    }

    Ok(())
}

struct FullResponse {
    response: Option<hyper::Response<Incoming>>,
    protocol: String,
    cipher_suite: String,
    certificates: Vec<Certificate>,
}

async fn fetch_url_custom_sni_host(
    path: &str,
    addr: &str,
    host: &str,
    sni: &str,
) -> color_eyre::eyre::Result<FullResponse> {
    let sni_host = sni.split(':').next().unwrap();
    let host_host = host.split(':').next().unwrap();
    debug!(
        "[fetch_url_custom_sni_host] Fetching {path} from {addr} with SNI {sni_host} and host {host_host}"
    );
    let stream = timeout(
        Duration::from_secs(NETWORK_TIMEOUT_SECS),
        TcpStream::connect(addr),
    )
    .await??;

    // Create TLS configuration
    let mut root_cert_store = RootCertStore::empty();
    root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = ClientConfig::builder()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(std::sync::Arc::new(config));
    let domain = ServerName::try_from(sni_host.to_string())
        .map_err(|_| color_eyre::eyre::eyre!("Invalid domain name: {}", sni_host))?;

    let tls_stream = connector.connect(domain, stream).await?;

    // Extract connection info from the TLS stream
    let (_io, connection_info) = tls_stream.get_ref();
    let protocol_version = connection_info
        .protocol_version()
        .map(|v| format!("{v:?}"))
        .unwrap_or_default();
    let cipher_suite = connection_info
        .negotiated_cipher_suite()
        .map(|c| c.suite().as_str().unwrap_or("unknown"))
        .unwrap_or("unknown");

    // Extract certificates from the Rustls connection
    let certificates = if let Some(peer_certs) = connection_info.peer_certificates() {
        peer_certs
            .iter()
            .filter_map(extract_certificate_info)
            .collect()
    } else {
        Vec::new()
    };

    let stream = TokioIo::new(tls_stream);

    let mut response = FullResponse {
        response: None,
        protocol: protocol_version,
        cipher_suite: cipher_suite.to_string(),
        certificates,
    };

    let (mut sender, conn) = hyper::client::conn::http1::handshake(stream).await?;
    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            error!("Connection failed: {err:#?}");
        }
    });

    let req = Request::builder()
        .uri(path)
        .header(hyper::header::USER_AGENT, "matrix-federation-checker/0.1")
        .header(hyper::header::HOST, host_host)
        .body(Empty::<Bytes>::new())?;

    let res = sender.send_request(req).await?;
    response.response = Some(res);

    Ok(response)
}

struct FullKeysResponse {
    keys: Keys,
    protocol: String,
    cipher_suite: String,
    certificates: Vec<Certificate>,
    keys_string: String,
}

async fn fetch_keys(
    addr: &str,
    server_name: &str,
    sni: &str,
) -> color_eyre::eyre::Result<FullKeysResponse> {
    let timeout_duration = Duration::from_secs(NETWORK_TIMEOUT_SECS);
    let response = timeout(
        timeout_duration,
        fetch_url_custom_sni_host("/_matrix/key/v2/server", addr, server_name, sni),
    )
    .await??;

    let http_response = response.response.unwrap();

    if !http_response.status().is_success() {
        return Err(color_eyre::eyre::eyre!(
            "Non-200 response {} from remote server",
            http_response.status()
        ));
    }
    let body = http_response.into_body().collect().await?.to_bytes();
    let keys_string = String::from_utf8(body.to_vec())
        .map_err(|_| color_eyre::eyre::eyre!("Failed to parse response body as UTF-8"))?;
    let keys: Keys = serde_json::from_str(&keys_string)
        .map_err(|_| color_eyre::eyre::eyre!("Failed to parse keys response as JSON"))?;

    Ok(FullKeysResponse {
        keys,
        protocol: response.protocol,
        cipher_suite: response.cipher_suite,
        certificates: response.certificates,
        keys_string,
    })
}

fn verify_keys(
    server_name: &str,
    keys: &Keys,
    keys_string: &str,
) -> (
    bool,
    bool,
    bool,
    BTreeMap<String, Ed25519Check>,
    BTreeMap<String, String>,
    bool,
) {
    let matching_server_name = keys.server_name == server_name;
    let future_valid_until_ts =
        keys.valid_until_ts > time_crate::OffsetDateTime::now_utc().unix_timestamp();

    let (ed25519checks, has_ed25519key, all_ed25519checks_ok, ed25519_verify_keys) =
        check_verify_keys(server_name, keys, keys_string);

    (
        future_valid_until_ts,
        has_ed25519key,
        all_ed25519checks_ok,
        ed25519checks,
        ed25519_verify_keys,
        matching_server_name,
    )
}

fn check_verify_keys(
    server_name: &str,
    keys: &Keys,
    keys_string: &str,
) -> (
    BTreeMap<String, Ed25519Check>,
    bool,
    bool,
    BTreeMap<String, String>,
) {
    let mut all_ed25519checks_ok = true;
    let mut ed25519checks = BTreeMap::new();
    let mut ed25519_verify_keys = BTreeMap::new();
    let mut has_ed25519key = false;

    for (key_id, key_data) in keys.verify_keys.clone() {
        let algorithm = key_id.split(':').next().unwrap();
        debug!(
            "Checking key_id: {key_id}, algorithm: {algorithm}, public key: {}",
            key_data.key
        );
        if let Ok(public_key) = BASE64_STANDARD_NO_PAD.decode(key_data.key.clone()) {
            if algorithm == "ed25519" {
                has_ed25519key = true;

                let mut matching_signature = false;
                if public_key.len() == 32 {
                    // Validate the key (set matching_signature to true if the key is valid)
                    // Parse keys_string as a json value
                    if let Ok(json_keys) = serde_json::from_str::<serde_json::Value>(keys_string)
                        && let Some(signatures) = json_keys.get("signatures")
                        && let Some(server_signatures) = signatures.get(server_name)
                        && let Some(signature) = server_signatures.get(key_id.clone())
                        && let Ok(signature_bytes) =
                            BASE64_STANDARD_NO_PAD.decode(signature.as_str().unwrap_or_default())
                        && signature_bytes.len() == 64
                    {
                        // Remove the unsigned and signatures fields from the json_keys value
                        let mut json_keys_clone = json_keys.clone();
                        json_keys_clone.as_object_mut().unwrap().remove("unsigned");
                        json_keys_clone
                            .as_object_mut()
                            .unwrap()
                            .remove("signatures");

                        // Canonicalize the JSON keys using the matrix canonicalization algorithm o verify the ed25519 signature using it and the public key
                        let canonical_json = serde_json::to_string(&json_keys_clone)
                            .expect("Failed to serialize JSON keys for canonicalization");
                        if let Ok(ed25519_signature) = Signature::from_slice(&signature_bytes) {
                            let public_key: [u8; 32] = public_key
                                .clone()
                                .try_into()
                                .expect("Public key should be 32 bytes long");
                            let verify_key: VerifyingKey = VerifyingKey::from_bytes(&public_key)
                                .expect("Failed to create verifying key from public key");

                            if verify_key
                                .verify(canonical_json.as_bytes(), &ed25519_signature)
                                .is_ok()
                            {
                                matching_signature = true;
                            } else {
                                error!(
                                    "Signature verification failed for key_id: {key_id} with public key: {}",
                                    key_data.key
                                );
                            }
                        } else {
                            error!(
                                "Failed to create signature from bytes for key_id: {key_id} with public key: {}",
                                key_data.key
                            );
                        }
                    } else {
                        error!(
                            "Failed to parse keys_string or find signatures for key_id: {key_id} with public key: {}",
                            key_data.key
                        );
                    }
                } else {
                    error!(
                        "Invalid public key length for key_id: {key_id}, expected 32 bytes, got {} bytes",
                        public_key.len()
                    );
                }
                ed25519checks.insert(
                    key_id.clone(),
                    Ed25519Check {
                        valid_ed25519: public_key.len() == 32,
                        matching_signature,
                    },
                );
                if matching_signature {
                    ed25519_verify_keys.insert(key_id, key_data.key);
                } else {
                    all_ed25519checks_ok = false;
                }
            }
        } else {
            error!(
                "Failed to decode public key for key_id: {key_id}, algorithm: {algorithm}, public key: {}",
                key_data.key
            );
        }
    }

    (
        ed25519checks,
        has_ed25519key,
        all_ed25519checks_ok,
        ed25519_verify_keys,
    )
}

pub async fn lookup_server_well_known_cached<P: ConnectionProvider>(
    data: &mut Root,
    server_name: &str,
    resolver: &Resolver<P>,
    cache: &WellKnownCache,
    use_cache: bool,
) -> Option<String> {
    // Check cache first if enabled
    if use_cache && let Some(cached_result) = cache.get_cached(&server_name.to_string(), use_cache)
    {
        data.well_known_result
            .insert(server_name.to_string(), cached_result.clone());
        if !cached_result.m_server.is_empty() {
            return Some(cached_result.m_server);
        }
        return None;
    }

    // Fall back to original function and cache result
    let result = lookup_server_well_known(data, server_name, resolver).await;

    // Cache the well-known result if enabled
    if use_cache && let Some(well_known) = data.well_known_result.get(server_name) {
        cache.insert(server_name.to_string(), well_known.clone());
    }

    result
}

pub async fn lookup_server_cached<P: ConnectionProvider>(
    data: &mut Root,
    server_name: &str,
    resolver: &Resolver<P>,
    cache: &DnsCache,
    use_cache: bool,
) -> color_eyre::eyre::Result<()> {
    // Check cache first if enabled
    if use_cache && let Some(cached_addrs) = cache.get_cached(&server_name.to_string(), use_cache) {
        data.dnsresult.addrs = cached_addrs;
        return Ok(());
    }

    // Fall back to original function and cache result
    lookup_server(data, server_name, resolver).await?;

    // Cache the DNS result if enabled
    if use_cache && !data.dnsresult.addrs.is_empty() {
        cache.insert(server_name.to_string(), data.dnsresult.addrs.clone());
    }

    Ok(())
}

pub async fn connection_check(
    addr: &str,
    server_name: &str,
    server_host: &str,
    sni: &str,
    connection_pool: &ConnectionPool,
    version_cache: &VersionCache,
    use_cache: bool,
) -> Result<ConnectionReportData, Error> {
    let mut report = ConnectionReportData::default();

    // Check version cache first if enabled
    let version_cache_key = format!("{addr}:{server_host}");
    let cached_version = if use_cache {
        if let Some(cached_version_str) = version_cache.get_cached(&version_cache_key, use_cache) {
            serde_json::from_str::<Version>(&cached_version_str).ok()
        } else {
            None
        }
    } else {
        None
    };

    // Parallelize version query and key fetch if no cached version available
    let (version_result, key_result) = if let Some(cached_version) = cached_version {
        // Use cached version, only fetch keys
        report.version = cached_version;
        report.checks.server_version_parses = true;

        let key_resp = fetch_keys(addr, server_host, sni).await;
        (Ok(None), key_resp)
    } else {
        // Parallelize both operations
        let addr_clone = addr.to_string();
        let server_host_clone = server_host.to_string();
        let sni_clone = sni.to_string();
        let pool_clone = connection_pool.clone();

        tokio::join!(
            query_server_version_pooled(&addr_clone, &server_host_clone, &sni_clone, &pool_clone),
            fetch_keys(&addr_clone, &server_host_clone, &sni_clone)
        )
    };

    // Handle version result
    match version_result {
        Ok(version_data) => {
            if let Some((version, parses)) = version_data {
                report.version = version;
                report.checks.server_version_parses = parses;

                // Cache the version response if enabled and successful
                if use_cache
                    && report.checks.server_version_parses
                    && let Ok(version_json) = serde_json::to_string(&report.version)
                {
                    version_cache.insert(version_cache_key, version_json);
                }
            }
            // If None, then we used cached version (already set above)
        }
        Err(e) => {
            return Err(Error {
                error: format!("Error fetching server version from {addr}: {e}"),
                error_code: ErrorCode::Unknown,
            });
        }
    }

    // Handle key result
    let key_resp = match key_result {
        Ok(key_resp) => {
            report.keys = key_resp.keys.clone();
            report.cipher.version = key_resp.protocol.clone();
            report.cipher.cipher_suite = key_resp.cipher_suite.clone();
            report.certificates = key_resp.certificates.clone();
            report.checks.valid_certificates = !report.certificates.is_empty();
            key_resp
        }
        Err(e) => {
            error!("Error fetching keys from {addr}: {e:#?}");
            return Err(Error {
                error: format!("Error fetching keys from {addr}: {e}"),
                error_code: ErrorCode::Unknown,
            });
        }
    };

    let (
        future_valid_until_ts,
        has_ed25519_key,
        all_ed25519checks_ok,
        ed25519_checks,
        ed25519_verify_keys,
        matching_server_name,
    ) = verify_keys(server_name, &report.keys, &key_resp.keys_string);
    report.checks.future_valid_until_ts = future_valid_until_ts;
    report.checks.has_ed25519key = has_ed25519_key;
    report.checks.all_ed25519checks_ok = all_ed25519checks_ok;
    report.checks.matching_server_name = matching_server_name;
    report.checks.ed25519checks = ed25519_checks;
    report.checks.all_checks_ok = report.checks.has_ed25519key
        && report.checks.all_ed25519checks_ok
        && report.checks.valid_certificates
        && report.checks.matching_server_name
        && report.checks.future_valid_until_ts
        && report.checks.server_version_parses;
    report.ed25519verify_keys = ed25519_verify_keys;

    Ok(report)
}

// Version query using connection pool (no certificates needed)
async fn query_server_version_pooled(
    addr: &str,
    server_name: &str,
    sni: &str,
    connection_pool: &ConnectionPool,
) -> color_eyre::eyre::Result<Option<(Version, bool)>> {
    let timeout_duration = Duration::from_secs(NETWORK_TIMEOUT_SECS);

    let response = timeout(
        timeout_duration,
        fetch_url_pooled_simple(
            "/_matrix/federation/v1/version",
            addr,
            server_name,
            sni,
            connection_pool,
        ),
    )
    .await??;

    let http_response = response.unwrap();
    let status = http_response.status();
    let headers = http_response.headers().clone();
    let body = http_response.into_body().collect().await?.to_bytes();

    if status.is_success() {
        if let Some(response_type) = headers.get("Content-Type") {
            if !response_type
                .to_str()
                .unwrap_or("")
                .contains("application/json")
            {
                return Ok(Some((Version::default(), false)));
            }
        } else {
            return Ok(Some((Version::default(), false)));
        }

        match serde_json::from_slice::<VersionResp>(&body) {
            Ok(json) => Ok(Some((json.server, true))),
            Err(_) => Ok(Some((Version::default(), false))),
        }
    } else {
        Ok(Some((Version::default(), false)))
    }
}

// Simple pooled HTTP client for requests that don't need certificate info
async fn fetch_url_pooled_simple(
    path: &str,
    addr: &str,
    host: &str,
    sni: &str,
    connection_pool: &ConnectionPool,
) -> color_eyre::eyre::Result<Option<hyper::Response<Incoming>>> {
    let sni_host = sni.split(':').next().unwrap();
    let host_host = host.split(':').next().unwrap();

    debug!(
        "[fetch_url_pooled_simple] Fetching {path} from {addr} with SNI {sni_host} and host {host_host} using connection pool"
    );

    // Try to get a connection from the pool
    match connection_pool.get_connection(addr, sni).await {
        Ok(mut sender) => {
            let req = Request::builder()
                .uri(path)
                .header(hyper::header::USER_AGENT, "matrix-federation-checker/0.1")
                .header(hyper::header::HOST, host_host)
                .body(Empty::<Bytes>::new())?;

            match sender.send_request(req).await {
                Ok(response) => {
                    debug!("Successfully used pooled connection for {path}");
                    // Return the connection to the pool
                    connection_pool.return_connection(addr, sni, sender).await;
                    return Ok(Some(response));
                }
                Err(e) => {
                    debug!("Pooled connection failed for {path}: {e}, creating fresh connection");
                    // Don't return the failed connection to the pool
                }
            }
        }
        Err(e) => {
            debug!("Failed to get pooled connection for {path}: {e}, creating fresh connection");
        }
    }

    // Fall back to fresh connection if pool failed
    debug!("Creating fresh connection for {path}");
    let stream = timeout(
        Duration::from_secs(NETWORK_TIMEOUT_SECS),
        TcpStream::connect(addr),
    )
    .await??;

    // Create TLS configuration
    let mut root_cert_store = RootCertStore::empty();
    root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = ClientConfig::builder()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(std::sync::Arc::new(config));
    let domain = ServerName::try_from(sni_host.to_string())
        .map_err(|_| color_eyre::eyre::eyre!("Invalid domain name: {}", sni_host))?;

    let tls_stream = connector.connect(domain, stream).await?;
    let io = TokioIo::new(tls_stream);

    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;

    // Spawn connection handler
    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            debug!("Fresh connection task ended: {err:#?}");
        }
    });

    // Send the request
    let req = Request::builder()
        .uri(path)
        .header(hyper::header::USER_AGENT, "matrix-federation-checker/0.1")
        .header(hyper::header::HOST, host_host)
        .body(Empty::<Bytes>::new())?;

    let response = sender.send_request(req).await?;

    // Store the connection in the pool for reuse
    connection_pool.return_connection(addr, sni, sender).await;

    Ok(Some(response))
}

/// Extract certificate information from a CertificateDer for federation reporting
fn extract_certificate_info(
    cert_der: &rustls_pki_types::CertificateDer<'_>,
) -> Option<Certificate> {
    // Parse the certificate using x509-parser
    let cert_bytes = cert_der.as_ref();
    let (_, x509_cert) = X509Certificate::from_der(cert_bytes).ok()?;

    // Extract subject common name
    let subject_cn = x509_cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|attr| attr.as_str().ok())
        .unwrap_or("Unknown")
        .to_string();

    // Extract issuer common name
    let issuer_cn = x509_cert
        .issuer()
        .iter_common_name()
        .next()
        .and_then(|attr| attr.as_str().ok())
        .unwrap_or("Unknown")
        .to_string();

    // Calculate SHA256 fingerprint
    let mut hasher = Sha256::new();
    hasher.update(cert_bytes);
    let fingerprint = format!("{:X}", hasher.finalize());

    // Extract Subject Alternative Names (DNS names)
    let mut dns_names = Vec::new();
    if let Ok(extensions_map) = x509_cert.extensions_map()
        && let Some(san_ext) =
            extensions_map.get(&x509_parser::oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME)
        && let ParsedExtension::SubjectAlternativeName(san_general_names) =
            san_ext.parsed_extension()
    {
        for name in &san_general_names.general_names {
            if let GeneralName::DNSName(dns_name) = name {
                dns_names.push(dns_name.to_string());
            }
        }
    }

    Some(Certificate {
        subject_common_name: subject_cn,
        issuer_common_name: issuer_cn,
        sha256fingerprint: fingerprint,
        dnsnames: if dns_names.is_empty() {
            None
        } else {
            Some(dns_names)
        },
    })
}
