use crate::utils::{
    connection_check, lookup_server, lookup_server_well_known, parse_and_validate_server_name,
    query_server_version,
};
use futures::StreamExt;
use futures::stream::FuturesUnordered;
use hickory_resolver::Resolver;
use hickory_resolver::name_server::ConnectionProvider;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use tracing::error;

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
    #[serde(skip_serializing_if = "String::is_empty")]
    #[serde(rename = "SRVCName")]
    pub srvcname: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "SRVRecords")]
    pub srvrecords: Option<Vec<SrvRecord>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "SRVError")]
    pub srverror: Option<SrvErrorData>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub hosts: BTreeMap<String, HostData>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub addrs: Vec<String>,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SrvRecord {
    pub target: String,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weight: Option<u16>,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SrvErrorData {
    pub message: String,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct HostData {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "CName")]
    pub cname: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub addrs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ConnectionReportData {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub certificates: Vec<Certificate>,
    pub cipher: Cipher,
    pub checks: Checks,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<Value>,
    #[serde(rename = "Ed25519VerifyKeys")]
    pub ed25519verify_keys: BTreeMap<String, String>,
    pub keys: Keys,
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

pub async fn generate_json_report<P: ConnectionProvider>(
    server_name: &str,
    resolver: &Resolver<P>,
) -> color_eyre::eyre::Result<Root> {
    let mut resp_data = Root {
        federation_ok: true,
        ..Default::default()
    };
    let mut server_host = server_name;

    // Validate server name
    parse_and_validate_server_name(&mut resp_data, server_name);

    // Get well-known data
    let new_server = lookup_server_well_known(&mut resp_data, server_name, resolver).await;
    if let Some(ref new_server) = new_server {
        server_host = new_server;
    }

    let resolved_server = server_host;

    let lookup_error = lookup_server(&mut resp_data, resolved_server, resolver).await;

    // Mark federation as not ok if there are errors or if no addresses were found
    if lookup_error.is_err() || resp_data.dnsresult.addrs.is_empty() {
        resp_data.federation_ok = false;
    }

    for addr in resp_data.clone().dnsresult.addrs {
        resp_data = query_server_version(resp_data, &addr, server_host, server_host).await?;
    }

    // Iterate through the addresses and perform connection checks in parallel
    let server_name_clone = server_name.to_string();
    let mut tasks = FuturesUnordered::new();
    for addr in &resp_data.dnsresult.addrs {
        let addr_clone = addr.clone();
        let server_name_clone = server_name_clone.clone();
        let server_host_clone = server_host.to_string();
        tasks.push(tokio::spawn(async move {
            match connection_check(
                &addr_clone,
                &server_name_clone,
                &server_host_clone,
                &server_host_clone,
            )
            .await
            {
                Ok(report) => {
                    let mut map = BTreeMap::new();
                    map.insert(addr_clone, report);
                    Ok(map)
                }
                Err(e) => {
                    let mut map = BTreeMap::new();
                    map.insert(addr_clone, e);
                    Err(map)
                }
            }
        }));
    }
    while let Some(result) = tasks.next().await {
        match result {
            Ok(Ok(report)) => {
                for (addr, report_data) in report {
                    resp_data.federation_ok =
                        resp_data.federation_ok && report_data.checks.all_checks_ok;
                    resp_data.connection_reports.insert(addr, report_data);
                }
            }
            Ok(Err(e)) => {
                resp_data.federation_ok = false;
                resp_data.connection_errors.extend(e);
            }
            Err(e) => {
                error!("Task failed: {e:?}");
            }
        }
    }

    Ok(resp_data)
}
