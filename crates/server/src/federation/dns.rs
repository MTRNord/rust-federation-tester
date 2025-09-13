use crate::federation::well_known::NETWORK_TIMEOUT_SECS;
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
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::{ResolveErrorKind, Resolver, name_server::ConnectionProvider};
use tokio::time::{Duration, timeout};

pub fn absolutize_srv_target(target: &str, base: &str) -> String {
    if target.ends_with('.') {
        target.to_string()
    } else {
        format!("{}.{}.", target, base.trim_end_matches('.'))
    }
}

#[tracing::instrument(name = "lookup_server", skip(resolver), fields(server_name = %server_name))]
pub async fn lookup_server<P: ConnectionProvider>(
    server_name: &str,
    resolver: &Resolver<P>,
) -> DnsPhaseResult {
    use std::collections::BTreeMap;
    let mut srv_targets: BTreeMap<String, Vec<SRVData>> = BTreeMap::new();
    let mut addrs: Vec<String> = vec![];
    let mut srvskipped = false;
    let mut errors: Vec<Error> = vec![];

    if !server_name.contains(':') {
        let mut found_srv_records = false;
        for srv_prefix in ["_matrix-fed._tcp", "_matrix._tcp"] {
            let srv_records = match timeout(
                Duration::from_secs(NETWORK_TIMEOUT_SECS),
                resolver.srv_lookup(&format!("{srv_prefix}.{server_name}.")),
            )
            .await
            {
                Ok(r) => r,
                Err(e) => {
                    errors.push(Error {
                        error: format!(
                            "Timeout while looking up SRV records for {server_name}: {e}"
                        ),
                        error_code: ErrorCode::Timeout,
                    });
                    continue;
                }
            };
            match srv_records {
                Ok(records) if !records.as_lookup().is_empty() => {
                    for record in records.iter() {
                        let srv = record.clone();
                        let target = absolutize_srv_target(&srv.target().to_utf8(), server_name);
                        match timeout(
                            Duration::from_secs(NETWORK_TIMEOUT_SECS),
                            resolver.lookup(&target, RecordType::CNAME),
                        )
                        .await
                        {
                            Ok(Ok(cname)) => {
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
                                    srv_targets
                                        .entry(target.clone())
                                        .or_default()
                                        .push(srv_data);
                                    continue;
                                }
                            }
                            Ok(Err(e)) => {
                                if let ResolveErrorKind::Proto(_proto_error) = e.kind() {
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
                                        port: srv.port(),
                                        priority: Some(srv.priority()),
                                        weight: Some(srv.weight()),
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
                    errors.push(Error {
                        error: format!("SRV lookup error for {server_name}: {e}"),
                        error_code: ErrorCode::Unknown,
                    });
                }
                _ => {}
            }
        }
        if !found_srv_records {
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

    let mut lookup_tasks = FuturesUnordered::new();
    for (host, records) in srv_targets.clone() {
        let resolver = resolver.clone();
        let host = if host.ends_with('.') {
            host
        } else {
            format!("{host}.")
        };
        let records = records.clone();
        lookup_tasks.push(async move {
            let cname_resp = timeout(
                Duration::from_secs(NETWORK_TIMEOUT_SECS),
                resolver.lookup(&host, RecordType::CNAME),
            )
            .await;
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
                    let mut addrs_with_port: Vec<String> = vec![];
                    match ipv4_records {
                        Ok(ref ipv4) => {
                            for addr in ipv4.record_iter() {
                                if let Some(ip) = addr.data().as_a() {
                                    addrs_with_port.push(format!("{}:{port}", ip.0));
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
                            for addr in ipv6.record_iter() {
                                if let Some(ip) = addr.data().as_aaaa() {
                                    addrs_with_port.push(format!("[{}]:{port}", ip.0));
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
                        "Resolved {host} to {dns_formatted_target} with {} addresses and server_name {server_name}",
                        addrs_with_port.len()
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
        let server_part = server_name.split(':').next().unwrap();
        let port = if server_name.contains(':') {
            server_name.split(':').nth(1).unwrap_or("8448")
        } else {
            "8448"
        };
        let host_server_name = format!("{server_part}.");
        let a_lookup = timeout(
            Duration::from_secs(NETWORK_TIMEOUT_SECS),
            resolver.lookup(&host_server_name, RecordType::A),
        );
        let aaaa_lookup = timeout(
            Duration::from_secs(NETWORK_TIMEOUT_SECS),
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
                    Err(hickory_resolver::ResolveErrorKind::Message("A lookup failed").into()),
                    Err(hickory_resolver::ResolveErrorKind::Message("AAAA lookup failed").into()),
                )
            }
        };
        let mut addrs_with_port: Vec<String> = vec![];
        match ipv4_records {
            Ok(ref ipv4) => {
                for addr in ipv4.record_iter() {
                    if let Some(ip) = addr.data().as_a() {
                        addrs_with_port.push(format!("{}:{port}", ip.0));
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
                for addr in ipv6.record_iter() {
                    if let Some(ip) = addr.data().as_aaaa() {
                        addrs_with_port.push(format!("[{}]:{port}", ip.0));
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
