use crate::connection_pool::ConnectionPool;
use crate::federation::{connection_check, lookup_server, lookup_server_well_known};
use crate::validation::server_name::parse_and_validate_server_name;

use futures::StreamExt;
use futures::stream::FuturesUnordered;
use hickory_resolver::Resolver;
use hickory_resolver::name_server::ConnectionProvider;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use utoipa::ToSchema;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "PascalCase")]
pub struct Root {
    pub server_name: String,
    pub well_known_result: BTreeMap<String, WellKnownResult>,
    #[serde(rename = "DNSResult")]
    pub dnsresult: Dnsresult,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub connection_reports: BTreeMap<String, ConnectionReportData>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub connection_errors: BTreeMap<String, Error>,
    pub version: Version,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Error>,
    #[serde(rename = "FederationOK")]
    pub federation_ok: bool,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "PascalCase")]
pub struct WellKnownResult {
    #[serde(rename = "m.server")]
    pub m_server: String,
    pub cache_expires_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Error>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "PascalCase")]
pub struct Dnsresult {
    #[serde(rename = "SRVSkipped")]
    pub srvskipped: bool,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub srv_targets: BTreeMap<String, Vec<SRVData>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub addrs: Vec<String>,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "PascalCase")]
pub struct SrvErrorData {
    pub message: String,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "PascalCase")]
pub struct SRVData {
    pub target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub srv_prefix: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub addrs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Error>,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weight: Option<u16>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "PascalCase")]
pub struct ConnectionReportData {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub certificates: Vec<Certificate>,
    pub cipher: Cipher,
    pub checks: Checks,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Error>,
    #[serde(rename = "Ed25519VerifyKeys")]
    pub ed25519verify_keys: BTreeMap<String, String>,
    pub keys: Keys,
    pub version: Version,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "PascalCase")]
pub struct Certificate {
    pub subject_common_name: String,
    pub issuer_common_name: String,
    #[serde(rename = "SHA256Fingerprint")]
    pub sha256fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "DNSNames")]
    pub dnsnames: Option<Vec<String>>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "PascalCase")]
pub struct Cipher {
    pub version: String,
    pub cipher_suite: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "PascalCase")]
pub struct Checks {
    #[serde(rename = "AllChecksOK")]
    pub all_checks_ok: bool,
    pub matching_server_name: bool,
    #[serde(rename = "FutureValidUntilTS")]
    pub future_valid_until_ts: bool,
    #[serde(rename = "HasEd25519Key")]
    pub has_ed25519key: bool,
    #[serde(rename = "AllEd25519ChecksOK")]
    pub all_ed25519checks_ok: bool,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    #[serde(rename = "Ed25519Checks")]
    pub ed25519checks: BTreeMap<String, Ed25519Check>,
    pub valid_certificates: bool,
    pub server_version_parses: bool,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "PascalCase")]
pub struct Ed25519Check {
    pub valid_ed25519: bool,
    pub matching_signature: bool,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "PascalCase")]
pub struct Keys {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "old_verify_keys")]
    pub old_verify_keys: Option<BTreeMap<String, Ed25519VerifyKey>>,
    #[serde(rename = "server_name")]
    pub server_name: String,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    #[serde(rename = "signatures")]
    pub signatures: BTreeMap<String, BTreeMap<String, String>>,
    #[serde(rename = "valid_until_ts")]
    pub valid_until_ts: i64,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    #[serde(rename = "verify_keys")]
    pub verify_keys: BTreeMap<String, Ed25519VerifyKey>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct Ed25519VerifyKey {
    pub key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "expired_ts")]
    pub expired_ts: Option<i64>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct Version {
    pub name: String,
    pub version: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde[rename_all = "PascalCase"]]
pub enum InvalidServerNameErrorCode {
    #[default]
    Unknown,
    EmptyString,
    EmptyHostname,
    NotValidDNS,
    InvalidCharacter,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "PascalCase")]
pub enum ErrorCode {
    #[default]
    Unknown,
    NoAddressesFound,
    #[serde(rename = "SRVPointsToCNAME")]
    SRVPointsToCNAME,
    DNSLookupTimeout,
    SRVLookupTimeout,
    InvalidServerName(InvalidServerNameErrorCode),
    NoRecordsFound,
    UnexpectedContentType(String),
    MissingContentType,
    InvalidJson(String),
    NotOk(String),
    NoResponse,
    Timeout,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "PascalCase")]
pub struct Error {
    pub error: String,
    pub error_code: ErrorCode,
}

#[tracing::instrument(skip(resolver, connection_pool))]
pub async fn generate_json_report<P: ConnectionProvider>(
    server_name: &str,
    resolver: &Resolver<P>,
    connection_pool: &ConnectionPool,
) -> color_eyre::eyre::Result<Root> {
    // Validate server name
    let mut resp_data = Root {
        federation_ok: true,
        server_name: server_name.to_string(),
        ..Default::default()
    };
    parse_and_validate_server_name(&mut resp_data, server_name);
    if resp_data.error.is_some() {
        resp_data.federation_ok = false;
        return Ok(resp_data);
    }

    let server_name_lower = server_name.to_lowercase();

    // Well-known phase (pure)
    let well_known_phase = lookup_server_well_known(&server_name_lower, resolver).await;
    for (addr, wk_result) in well_known_phase.well_known_result.iter() {
        resp_data
            .well_known_result
            .insert(addr.clone(), wk_result.clone());
    }
    if let Some(err) = &well_known_phase.error {
        resp_data.error = Some(err.clone());
        resp_data.federation_ok = false;
    }

    // Build the per-IP connection list respecting the spec fallback rules:
    //
    // For each IP that was probed during the well-known phase:
    //   - If well-known SUCCEEDED on that IP → the delegated server from m.server gives us
    //     the host and port to use for that IP's connection check.  Because m.server may
    //     delegate to a *different* hostname we run a fresh DNS lookup for it (same as the
    //     old single-server DNS phase, but scoped to this IP's result).
    //   - If well-known FAILED on that IP (timeout, error, non-200 …) → per spec step 6 we
    //     fall back to port 8448 on the same IP, using the original server_name as the Host
    //     header / SNI.  We already have the IP so no extra DNS lookup is needed.
    //
    // If the well-known phase produced no per-IP results at all (server_name contained a
    // port, or DNS returned no A/AAAA records) we fall back to the original single DNS phase
    // so that SRV records etc. are still handled correctly.
    //
    // Each entry is (connect_addr, host_header, sni).
    let mut connection_targets: Vec<(String, String, String)> = Vec::new();

    if well_known_phase.per_ip_found_server.is_empty() {
        // No per-IP data (e.g. server_name had an explicit port, or no DNS records).
        // Fall through to the original single DNS phase.
        let resolved_server = well_known_phase
            .found_server
            .clone()
            .unwrap_or(server_name_lower.clone());

        let dns_phase = lookup_server(&resolved_server, resolver).await;
        resp_data.dnsresult.srv_targets = dns_phase.srv_targets.clone();
        resp_data.dnsresult.addrs = dns_phase.addrs.clone();
        resp_data.dnsresult.srvskipped = dns_phase.srvskipped;

        if resp_data.dnsresult.addrs.is_empty() {
            resp_data.federation_ok = false;
            if !dns_phase.errors.is_empty() {
                resp_data.error = Some(dns_phase.errors[0].clone());
            }
        } else if !dns_phase.errors.is_empty() {
            let critical_errors: Vec<_> = dns_phase
                .errors
                .iter()
                .filter(|err| !err.error.contains("AAAA record lookup error"))
                .collect();
            if !critical_errors.is_empty() {
                resp_data.error = Some(critical_errors[0].clone());
                resp_data.federation_ok = false;
            }
        }

        for addr in &resp_data.dnsresult.addrs {
            connection_targets.push((
                addr.clone(),
                resolved_server.clone(),
                resolved_server.clone(),
            ));
        }
    } else {
        // We have per-IP well-known outcomes — handle each IP individually.
        for (probed_ip, found_server_opt) in &well_known_phase.per_ip_found_server {
            match found_server_opt {
                Some(delegated_server) => {
                    // Well-known succeeded on this IP.  The delegated server may resolve to
                    // different IPs (or the same), so we run the normal DNS phase for it.
                    let dns_phase = lookup_server(delegated_server, resolver).await;

                    // Merge DNS results into resp_data for reporting (dedup addrs).
                    for addr in &dns_phase.addrs {
                        if !resp_data.dnsresult.addrs.contains(addr) {
                            resp_data.dnsresult.addrs.push(addr.clone());
                        }
                    }
                    for (k, v) in &dns_phase.srv_targets {
                        resp_data
                            .dnsresult
                            .srv_targets
                            .entry(k.clone())
                            .or_insert_with(|| v.clone());
                    }
                    if dns_phase.srvskipped {
                        resp_data.dnsresult.srvskipped = true;
                    }

                    for addr in &dns_phase.addrs {
                        connection_targets.push((
                            addr.clone(),
                            delegated_server.clone(),
                            delegated_server.clone(),
                        ));
                    }
                }
                None => {
                    // Well-known failed on this IP → spec step 6: use port 8448 directly.
                    // Strip the port from the probed IP (it was probed on :443) and reattach :8448.
                    let bare_ip = if probed_ip.starts_with('[') {
                        // IPv6 formatted as [addr]:port
                        probed_ip
                            .rfind(']')
                            .map(|i| &probed_ip[..=i])
                            .unwrap_or(probed_ip.as_str())
                    } else {
                        probed_ip
                            .rfind(':')
                            .map(|i| &probed_ip[..i])
                            .unwrap_or(probed_ip.as_str())
                    };
                    let fallback_addr = format!("{bare_ip}:8448");

                    if !resp_data.dnsresult.addrs.contains(&fallback_addr) {
                        resp_data.dnsresult.addrs.push(fallback_addr.clone());
                    }
                    resp_data.dnsresult.srvskipped = true;

                    connection_targets.push((
                        fallback_addr,
                        server_name_lower.clone(),
                        server_name_lower.clone(),
                    ));
                }
            }
        }

        if resp_data.dnsresult.addrs.is_empty() {
            resp_data.federation_ok = false;
        }
    }

    // Connection phase — try every target, federation is OK if at least one succeeds fully.
    if !connection_targets.is_empty() {
        tracing::debug!(
            "Starting connection checks for targets: {:?}",
            connection_targets
        );
        let mut futures = FuturesUnordered::new();
        for (addr, host, sni) in connection_targets {
            let server_name_c = server_name_lower.clone();
            let pool = connection_pool.clone();
            futures.push(async move {
                let result = connection_check(&addr, &server_name_c, &host, &sni, &pool).await;
                (addr, result)
            });
        }

        let mut any_success = false;
        while let Some((addr, result)) = futures.next().await {
            match result {
                Ok(report) => {
                    if report.checks.all_checks_ok {
                        any_success = true;
                        resp_data.version = report.version.clone();
                    }
                    resp_data.connection_reports.insert(addr, report);
                }
                Err(e) => {
                    resp_data.connection_errors.insert(addr, e);
                }
            }
        }

        if resp_data.federation_ok {
            resp_data.federation_ok = any_success;
        }
    }
    Ok(resp_data)
}
