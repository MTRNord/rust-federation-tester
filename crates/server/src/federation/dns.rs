use crate::federation::well_known::network_timeout;
use crate::optimization::string_ops::{format_addr_port, format_ipv6_port};
use crate::response::{Error, ErrorCode, SRVData};
use futures::StreamExt;
use futures::stream::FuturesUnordered;

#[derive(Debug, Clone)]
pub struct DnsPhaseResult {
    pub srv_targets: std::collections::BTreeMap<String, Vec<SRVData>>,
    pub addrs: Vec<String>,
    pub srvskipped: bool,
    pub errors: Vec<Error>,
}

use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::{ConnectionProvider, Resolver};
use tokio::time::timeout;

#[tracing::instrument()]
pub fn absolutize_srv_target(target: &str, base: &str) -> String {
    if target.ends_with('.') {
        target.to_string()
    } else {
        format!("{}.{}.", target, base.trim_end_matches('.'))
    }
}

#[tracing::instrument(skip(resolver))]
pub async fn lookup_server<P: ConnectionProvider>(
    server_name: &str,
    resolver: &Resolver<P>,
) -> DnsPhaseResult {
    use std::collections::BTreeMap;

    // Spec step 1/2: If server_name is an IP literal, connect directly without any DNS.
    // Parse hostname and optional port, handling IPv6 brackets.
    let (ip_host, port_str) = if server_name.starts_with('[') {
        match server_name.find(']') {
            Some(end) => {
                let inner = &server_name[1..end];
                let rest = &server_name[end + 1..];
                let port = rest.strip_prefix(':').unwrap_or("");
                (inner, port)
            }
            None => ("", ""),
        }
    } else if let Some(colon) = server_name.find(':') {
        (&server_name[..colon], &server_name[colon + 1..])
    } else {
        (server_name, "")
    };

    if let Ok(ip) = ip_host.parse::<std::net::IpAddr>() {
        let port: u16 = port_str.parse().unwrap_or(8448);
        let addr = if ip.is_ipv6() {
            format!("[{ip}]:{port}")
        } else {
            format!("{ip}:{port}")
        };
        tracing::info!(
            name = "federation.dns.ip_literal",
            target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            message = "Server name is an IP literal, skipping DNS lookup",
            server_name = %server_name,
            addr = %addr
        );
        return DnsPhaseResult {
            srv_targets: BTreeMap::new(),
            addrs: vec![addr],
            srvskipped: true,
            errors: vec![],
        };
    }

    let mut srv_targets: BTreeMap<String, Vec<SRVData>> = BTreeMap::new();
    let mut addrs: Vec<String> = vec![];
    let mut srvskipped = false;
    let mut errors: Vec<Error> = vec![];

    if !server_name.contains(':') {
        // Fire both SRV lookups simultaneously — halves worst-case latency when either times out.
        let fed_name = format!("_matrix-fed._tcp.{server_name}.");
        let matrix_name = format!("_matrix._tcp.{server_name}.");
        let (fed_result, matrix_result) = tokio::join!(
            timeout(network_timeout(), resolver.srv_lookup(&fed_name)),
            timeout(network_timeout(), resolver.srv_lookup(&matrix_name)),
        );

        let mut found_srv_records = false;
        let mut srv_errors = vec![];
        for (srv_prefix, timeout_result) in [
            ("_matrix-fed._tcp", fed_result),
            ("_matrix._tcp", matrix_result),
        ] {
            let srv_records = match timeout_result {
                Ok(r) => r,
                Err(e) => {
                    srv_errors.push(Error {
                        error: format!(
                            "Timeout while looking up SRV records for {server_name}: {e}"
                        ),
                        error_code: ErrorCode::Timeout,
                    });
                    continue;
                }
            };
            match srv_records {
                Ok(records) if !records.answers().is_empty() => {
                    for record in records.answers().iter() {
                        let RData::SRV(srv) = &record.data else {
                            continue;
                        };
                        let target = absolutize_srv_target(&srv.target.to_utf8(), server_name);
                        let srv_port = srv.port;
                        let srv_priority = srv.priority;
                        let srv_weight = srv.weight;
                        match timeout(
                            network_timeout(),
                            resolver.lookup(&target, RecordType::CNAME),
                        )
                        .await
                        {
                            Ok(Ok(cname)) => {
                                let cname_target = cname.answers().iter().next().and_then(|c| {
                                    if let RData::CNAME(cname_rdata) = &c.data {
                                        Some(cname_rdata.to_utf8())
                                    } else {
                                        None
                                    }
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
                                        port: srv_port,
                                        priority: Some(srv_priority),
                                        weight: Some(srv_weight),
                                    };
                                    srv_targets
                                        .entry(target.clone())
                                        .or_default()
                                        .push(srv_data);
                                    continue;
                                }
                            }
                            Ok(Err(e)) => {
                                if e.is_no_records_found() {
                                    let srv_data = SRVData {
                                        target: target.clone(),
                                        srv_prefix: Some(srv_prefix.to_string()),
                                        addrs: vec![],
                                        error: None,
                                        port: srv_port,
                                        priority: Some(srv_priority),
                                        weight: Some(srv_weight),
                                    };
                                    srv_targets
                                        .entry(target.clone())
                                        .or_default()
                                        .push(srv_data);
                                } else {
                                    let err = Error {
                                        error: format!(
                                            "Unknown error during CNAME lookup for {target}: {e}"
                                        ),
                                        error_code: ErrorCode::Unknown,
                                    };
                                    let srv_data = SRVData {
                                        target: target.clone(),
                                        srv_prefix: Some(srv_prefix.to_string()),
                                        addrs: vec![],
                                        error: Some(err.clone()),
                                        port: srv_port,
                                        priority: Some(srv_priority),
                                        weight: Some(srv_weight),
                                    };
                                    srv_targets
                                        .entry(target.clone())
                                        .or_default()
                                        .push(srv_data);
                                    errors.push(err);
                                }
                            }
                            Err(e) => {
                                errors.push(Error {
                                    error: format!("Error during CNAME lookup for {target}: {e}"),
                                    error_code: ErrorCode::Unknown,
                                });
                            }
                        }
                    }
                    found_srv_records = true;
                }
                Err(e) => {
                    srv_errors.push(Error {
                        error: format!("SRV lookup error for {server_name}: {e}"),
                        error_code: ErrorCode::Unknown,
                    });
                }
                _ => {}
            }
        }

        // Only add SRV errors to the main error list if no SRV records were found at all
        // Note: Having no SRV records is valid - fallback to direct A/AAAA lookup (spec case 3e)
        if !found_srv_records {
            // Don't add SRV errors as they're expected when falling back to direct lookup
            srv_targets.insert(
                server_name.to_string(),
                vec![SRVData {
                    target: server_name.to_string(),
                    srv_prefix: None,
                    addrs: vec![],
                    error: None,
                    priority: None,
                    weight: None,
                    port: 8448,
                }],
            );
        }
    } else {
        srvskipped = true;
    }

    let pending: Vec<(String, Vec<SRVData>)> =
        std::mem::take(&mut srv_targets).into_iter().collect();
    let mut lookup_tasks = FuturesUnordered::new();
    for (host, records) in pending {
        let resolver = resolver.clone();
        let host = if host.ends_with('.') {
            host
        } else {
            format!("{host}.")
        };
        lookup_tasks.push(async move {
            // Run CNAME, A, and AAAA lookups in parallel so a CNAME timeout
            // does not delay the A/AAAA results.
            let (cname_resp, ipv4_result, ipv6_result) = tokio::join!(
                timeout(network_timeout(), resolver.lookup(&host, RecordType::CNAME),),
                timeout(network_timeout(), resolver.lookup(&host, RecordType::A),),
                timeout(network_timeout(), resolver.lookup(&host, RecordType::AAAA),),
            );
            let ipv4_records = match ipv4_result {
                Ok(r) => r,
                Err(_) => Err(hickory_resolver::net::NetError::Message(
                    "A lookup timed out",
                )),
            };
            let ipv6_records = match ipv6_result {
                Ok(r) => r,
                Err(_) => Err(hickory_resolver::net::NetError::Message(
                    "AAAA lookup timed out",
                )),
            };
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
                    cname.answers().iter().next().and_then(|c| {
                        if let RData::CNAME(cname_rdata) = &c.data {
                            Some(cname_rdata.to_utf8().to_string())
                        } else {
                            None
                        }
                    })
                } else {
                    None
                };
                for record in records.iter_mut() {
                    let target = record.target.clone();
                    let port = record.port;
                    let mut addrs_with_port: Vec<String> = vec![];
                    match ipv4_records {
                        Ok(ref ipv4) => {
                            for addr in ipv4.answers().iter() {
                                if let RData::A(ip) = &addr.data {
                                    addrs_with_port.push(format_addr_port(&ip.0.to_string(), port));
                                }
                            }
                        }
                        Err(ref e) => {
                            errors.push(Error {
                                error: format!("A record lookup error for {host}: {e}"),
                                error_code: ErrorCode::Unknown,
                            });
                        }
                    }
                    match ipv6_records {
                        Ok(ref ipv6) => {
                            for addr in ipv6.answers().iter() {
                                if let RData::AAAA(ip) = &addr.data {
                                    addrs_with_port.push(format_ipv6_port(&ip.0.to_string(), port));
                                }
                            }
                        }
                        Err(ref e) => {
                            errors.push(Error {
                                error: format!("AAAA record lookup error for {host}: {e}"),
                                error_code: ErrorCode::Unknown,
                            });
                        }
                    }
                    if addrs_with_port.is_empty() {
                        continue;
                    }
                    let canonical_target = cname_target.clone().unwrap_or(target.clone());
                    let dns_formatted_target = if canonical_target.ends_with('.') {
                        canonical_target
                    } else {
                        format!("{canonical_target}.")
                    };
                    tracing::info!(
                        name = "federation.dns.resolved",
                        target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                        message = "Resolved DNS target",
                        host = %host,
                        dns_target = %dns_formatted_target,
                        addr_count = addrs_with_port.len(),
                        server_name = %server_name
                    );
                    record.addrs.extend(addrs_with_port.clone());
                    addrs.extend(addrs_with_port);
                }
                srv_targets.insert(host, records);
            }
            Err(e) => {
                errors.push(Error {
                    error: format!("DNS lookup error: {e}"),
                    error_code: ErrorCode::Unknown,
                });
            }
        }
    }

    if srvskipped {
        let server_part = server_name.split(':').next().unwrap_or(server_name);
        let port = if server_name.contains(':') {
            server_name.split(':').nth(1).unwrap_or("8448")
        } else {
            "8448"
        };
        let host_server_name = format!("{server_part}.");
        let a_lookup = timeout(
            network_timeout(),
            resolver.lookup(&host_server_name, RecordType::A),
        );
        let aaaa_lookup = timeout(
            network_timeout(),
            resolver.lookup(&host_server_name, RecordType::AAAA),
        );
        let (ipv4_records, ipv6_records) = match tokio::try_join!(a_lookup, aaaa_lookup) {
            Ok(res) => res,
            Err(e) => {
                errors.push(Error {
                    error: format!("A/AAAA lookup error for {server_part}: {e}"),
                    error_code: ErrorCode::Unknown,
                });
                (
                    Err(hickory_resolver::net::NetError::Message("A lookup failed")),
                    Err(hickory_resolver::net::NetError::Message(
                        "AAAA lookup failed",
                    )),
                )
            }
        };
        let mut addrs_with_port: Vec<String> = vec![];
        match ipv4_records {
            Ok(ref ipv4) => {
                for addr in ipv4.answers().iter() {
                    if let RData::A(ip) = &addr.data {
                        addrs_with_port.push(format_addr_port(
                            &ip.0.to_string(),
                            port.parse().unwrap_or(8448),
                        ));
                    }
                }
            }
            Err(e) => {
                errors.push(Error {
                    error: format!("A record lookup error for {server_part}: {e}"),
                    error_code: ErrorCode::Unknown,
                });
            }
        }
        match ipv6_records {
            Ok(ref ipv6) => {
                for addr in ipv6.answers().iter() {
                    if let RData::AAAA(ip) = &addr.data {
                        addrs_with_port.push(format_ipv6_port(
                            &ip.0.to_string(),
                            port.parse().unwrap_or(8448),
                        ));
                    }
                }
            }
            Err(e) => {
                errors.push(Error {
                    error: format!("AAAA record lookup error for {server_part}: {e}"),
                    error_code: ErrorCode::Unknown,
                });
            }
        }
        if !addrs_with_port.is_empty() {
            addrs.extend(addrs_with_port);
        }
    }

    DnsPhaseResult {
        srv_targets,
        addrs,
        srvskipped,
        errors,
    }
}
