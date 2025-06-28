use crate::cache::{DnsCache, VersionCache, WellKnownCache};
use crate::connection_pool::ConnectionPool;
use crate::utils::{
    connection_check, lookup_server, lookup_server_well_known, parse_and_validate_server_name,
};
use futures::StreamExt;
use futures::stream::FuturesUnordered;
use hickory_resolver::Resolver;
use hickory_resolver::name_server::ConnectionProvider;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Root {
    pub well_known_result: BTreeMap<String, WellKnownResult>,
    #[serde(rename = "DNSResult")]
    pub dnsresult: Dnsresult,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub connection_reports: BTreeMap<String, ConnectionReportData>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub connection_errors: BTreeMap<String, ConnectionError>,
    pub version: Version,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(rename = "FederationOK")]
    pub federation_ok: bool,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct WellKnownResult {
    #[serde(rename = "m.server")]
    pub m_server: String,
    pub cache_expires_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Dnsresult {
    #[serde(rename = "SRVSkipped")]
    pub srvskipped: bool,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub srv_targets: BTreeMap<String, Vec<SRVData>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub addrs: Vec<String>,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SrvErrorData {
    pub message: String,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SRVData {
    pub target: String,
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

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ConnectionReportData {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub certificates: Vec<Certificate>,
    pub cipher: Cipher,
    pub checks: Checks,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(rename = "Ed25519VerifyKeys")]
    pub ed25519verify_keys: BTreeMap<String, String>,
    pub keys: Keys,
    pub version: Version,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
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

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Cipher {
    pub version: String,
    pub cipher_suite: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
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

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Ed25519Check {
    pub valid_ed25519: bool,
    pub matching_signature: bool,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
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

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Ed25519VerifyKey {
    pub key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "expired_ts")]
    pub expired_ts: Option<i64>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ConnectionError {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Version {
    pub name: String,
    pub version: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ErrorCode {
    #[default]
    Unknown,
    NoAddressesFound,
    #[serde(rename = "SRVPointsToCNAME")]
    SRVPointsToCNAME,
    DNSLookupTimeout,
    SRVLookupTimeout,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Error {
    pub error: String,
    pub error_code: ErrorCode,
}

pub async fn generate_json_report<P: ConnectionProvider>(
    server_name: &str,
    resolver: &Resolver<P>,
    connection_pool: &ConnectionPool,
    dns_cache: &DnsCache,
    well_known_cache: &WellKnownCache,
    version_cache: &VersionCache,
    use_cache: bool,
) -> color_eyre::eyre::Result<Root> {
    let mut resp_data = Root {
        federation_ok: true,
        ..Default::default()
    };

    // Validate server name
    parse_and_validate_server_name(&mut resp_data, server_name);
    if resp_data.error.is_some() {
        resp_data.federation_ok = false;
        return Ok(resp_data);
    }

    let server_name_lower = server_name.to_lowercase();
    let cache_key = server_name_lower.clone();

    // Handle well-known lookup with caching
    let well_known_result = if use_cache {
        if let Some(cached_result) = well_known_cache.get(&cache_key) {
            // Use cached well-known result
            resp_data
                .well_known_result
                .insert(server_name_lower.clone(), cached_result.clone());
            if !cached_result.m_server.is_empty() {
                Some(cached_result.m_server)
            } else {
                None
            }
        } else {
            // Fetch well-known
            let result =
                lookup_server_well_known(&mut resp_data, &server_name_lower, resolver).await;
            // Cache the well-known result if we have one
            if let Some(well_known_result) = resp_data.well_known_result.get(&server_name_lower) {
                well_known_cache.insert(cache_key, well_known_result.clone());
            }
            result
        }
    } else {
        lookup_server_well_known(&mut resp_data, &server_name_lower, resolver).await
    };

    // Determine the server to resolve
    let resolved_server = if let Some(ref new_server) = well_known_result {
        new_server.clone()
    } else {
        server_name_lower.clone()
    };

    // DNS lookup with caching
    let dns_cache_key = resolved_server.clone();
    let lookup_error = if use_cache {
        if let Some(cached_addrs) = dns_cache.get(&dns_cache_key) {
            // Use cached DNS results
            resp_data.dnsresult.addrs = cached_addrs;
            tracing::debug!(
                "Using cached DNS results for {}: {:?}",
                dns_cache_key,
                resp_data.dnsresult.addrs
            );
            Ok(())
        } else {
            let error = lookup_server(&mut resp_data, &resolved_server, resolver).await;
            tracing::debug!(
                "After federation lookup, addrs: {:?}",
                resp_data.dnsresult.addrs
            );
            if error.is_ok() && !resp_data.dnsresult.addrs.is_empty() {
                dns_cache.insert(dns_cache_key, resp_data.dnsresult.addrs.clone());
            }
            error
        }
    } else {
        lookup_server(&mut resp_data, &resolved_server, resolver).await
    };

    // Mark federation as not ok if there are DNS errors or no addresses
    if lookup_error.is_err() || resp_data.dnsresult.addrs.is_empty() {
        resp_data.federation_ok = false;
    }

    // If we have addresses, run connection checks in parallel
    if !resp_data.dnsresult.addrs.is_empty() {
        tracing::debug!(
            "Starting connection checks for addresses: {:?}",
            resp_data.dnsresult.addrs
        );
        let mut futures = FuturesUnordered::new();

        for addr in &resp_data.dnsresult.addrs {
            let addr = addr.clone();
            let server_name = server_name_lower.clone();
            let resolved_server = resolved_server.clone();
            let pool = connection_pool.clone();
            let version_cache = version_cache.clone();

            futures.push(async move {
                let result = connection_check(
                    &addr,
                    &server_name,
                    &resolved_server,
                    &resolved_server,
                    &pool,
                    &version_cache,
                    use_cache,
                )
                .await;
                (addr, result)
            });
        }

        // Process all connection checks concurrently
        while let Some((addr, result)) = futures.next().await {
            match result {
                Ok(report) => {
                    // Update global checks
                    resp_data.federation_ok =
                        resp_data.federation_ok && report.checks.all_checks_ok;
                    resp_data.version = report.version.clone();
                    resp_data.connection_reports.insert(addr, report);
                }
                Err(e) => {
                    resp_data.connection_errors.insert(addr, e);
                    resp_data.federation_ok = false;
                }
            }
        }
    }

    Ok(resp_data)
}
