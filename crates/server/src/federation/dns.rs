use crate::federation::well_known::NETWORK_TIMEOUT_SECS;
use crate::response::{Error, ErrorCode, Root, SRVData};
use futures::{StreamExt, stream::FuturesUnordered};
use hickory_resolver::ResolveErrorKind::Proto;
use hickory_resolver::proto::ProtoErrorKind;
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::{ResolveErrorKind, Resolver, name_server::ConnectionProvider};
use tokio::time::{Duration, timeout};
use tracing::{debug, error, info, warn}; // reuse constant

pub fn absolutize_srv_target(target: &str, base: &str) -> String {
    if target.ends_with('.') {
        target.to_string()
    } else {
        format!("{}.{}.", target, base.trim_end_matches('.'))
    }
}

#[tracing::instrument(name = "lookup_server", skip(data, resolver), fields(server_name = %server_name))]
pub async fn lookup_server<P: ConnectionProvider>(
    data: &mut Root,
    server_name: &str,
    resolver: &Resolver<P>,
) -> color_eyre::eyre::Result<()> {
    info!("[lookup_server] Looking up server {server_name}");
    if !server_name.contains(':') {
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
                }
                _ => {}
            }
        }
        if !found_srv_records {
            data.dnsresult.srv_targets.insert(
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
                                    addrs_with_port.push(format!("{}:{port}", ip.0));
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
                error!("DNS lookup error: {e:#?}");
            }
        }
    }

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
        }
    }
    Ok(())
}
