use crate::response::{
    Certificate, ConnectionError, ConnectionReportData, Ed25519Check, HostData, Keys, Root,
    SrvRecord, Version, WellKnownResult,
};
use base64::engine::general_purpose::STANDARD;
use base64::prelude::BASE64_STANDARD_NO_PAD;
use base64::Engine;
use bytes::Bytes;
use ed25519::signature::Verifier;
use ed25519::Signature;
use ed25519_dalek::VerifyingKey;
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::proto::ProtoErrorKind;
use hickory_resolver::ResolveErrorKind::Proto;
use hickory_resolver::{ResolveErrorKind, Resolver};
use http_body_util::BodyExt;
use http_body_util::Empty;
use hyper::body::Incoming;
use hyper::Request;
use hyper_openssl::SslStream;
use hyper_util::rt::TokioIo;
use openssl::ssl::SslConnector;
use openssl::ssl::SslMethod;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::pin::Pin;
use tokio::net::TcpStream;
use tracing::{error, info};

pub fn parse_and_validate_server_name(data: &mut Root, server_name: &str) {
    if server_name.is_empty() {
        data.error = Some("Invalid server name: empty string".to_string());
    }

    // Split off the port if it exists
    let parts: Vec<&str> = server_name.split(':').collect();
    let hostname = parts[0];

    // Check if host part is one of:
    // - a valid (ascii) dns name
    // - an IP literal (IPv4 or IPv6)

    if hostname.is_empty() {
        data.error = Some("Invalid server name: empty hostname".to_string());
        return;
    }

    if hostname.parse::<std::net::IpAddr>().is_err() {
        // Check if it's a valid DNS name
        if !hostname.is_ascii() || hostname.len() > 255 || hostname.contains("..") {
            data.error = Some(format!(
                "Invalid server name: {server_name} (Not a valid DNS name)",
            ));
            return;
        }

        // Check for invalid characters in the hostname
        for c in hostname.chars() {
            if !c.is_ascii_alphanumeric() && c != '-' && c != '.' {
                data.error = Some(format!(
                    "Invalid server name: {server_name} (Invalid character '{c}')",
                ));
                return;
            }
        }
    }
}

pub async fn lookup_server_well_known(data: &mut Root, server_name: &str) -> Option<String> {
    let resolver = Resolver::builder_tokio().unwrap().build();
    let ipv4 = resolver
        .lookup(&format!("{server_name}."), RecordType::A)
        .await;
    let ipv6 = resolver
        .lookup(&format!("{server_name}."), RecordType::AAAA)
        .await;

    let mut found_server: Option<String> = None;

    let mut addrs: Vec<String> = vec![];

    if let Ok(lookup) = ipv4 {
        for record in lookup.record_iter() {
            if let Some(ip) = record.data().as_a() {
                addrs.push(format!("{}:443", ip.0));
            }
        }
    }
    if let Ok(lookup) = ipv6 {
        for record in lookup.record_iter() {
            if let Some(ip) = record.data().as_aaaa() {
                addrs.push(format!("[{}]:443", ip.0));
            }
        }
    }

    if addrs.is_empty() {
        data.error = Some(format!("No A/AAAA-Records for {server_name} found"));
        return None;
    }

    for addr in addrs {
        let response = fetch_url_custom_sni_host(
            "/.well-known/matrix/server",
            &addr,
            server_name,
            server_name,
        )
        .await;

        let mut result = WellKnownResult::default();

        match response {
            Ok(resp) => {
                if let Some(resp) = resp.response {
                    if resp.status().is_success() {
                        if let Some(expires_header) = resp.headers().get("Expires") {
                            if let Ok(expires_str) = expires_header.to_str()
                                && let Ok(expires_time) = time::OffsetDateTime::parse(
                                    expires_str,
                                    &time::format_description::well_known::Rfc2822,
                                )
                            {
                                result.cache_expires_at = expires_time.unix_timestamp();
                            }
                        } else if let Some(cache_control) = resp.headers().get("Cache-Control")
                            && let Ok(cache_control_str) = cache_control.to_str()
                            && let Some(max_age) = cache_control_str
                                .split(',')
                                .find_map(|s| s.trim().strip_prefix("max-age="))
                            && let Ok(max_age_secs) = max_age.parse::<u64>()
                        {
                            result.cache_expires_at = time::OffsetDateTime::now_utc()
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
                                parse_and_validate_server_name(data, server_str);
                                if data.error.is_none() && found_server.is_none() {
                                    found_server = Some(server_str.to_string());
                                }
                            }
                        }
                    } else {
                        result.error =
                            Some(format!("Error fetching well-known URL:  {}", resp.status()));
                    }
                } else {
                    result.error = Some("Error fetching well-known URL".to_string());
                }
            }
            Err(e) => {
                result.error = Some(format!("Error fetching well-known URL:  {e:#?}"));
            }
        }
        data.well_known_result.insert(addr, result);
    }

    found_server
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VersionResp {
    pub server: Version,
}

pub async fn query_server_version(
    data: &mut Root,
    federation_address: &str,
) -> color_eyre::eyre::Result<()> {
    // We ask the server via /_matrix/federation/v1/version
    let url = format!("https://{federation_address}/_matrix/federation/v1/version");
    info!("Fetching version for {url}");
    let client = reqwest::Client::new();
    let response = client
        .get(&url)
        .header("User-Agent", "Matrix Federation Report")
        .send()
        .await?;
    if response.status().is_success() {
        if let Some(response_type) = response.headers().get("Content-Type") {
            if !response_type
                .to_str()
                .unwrap_or("")
                .contains("application/json")
            {
                error!(
                    "Unexpected Content-Type: {}. Expected application/json",
                    response_type.to_str().unwrap_or("")
                );
                data.error = Some("Unexpected Content-Type in server version response".to_string());
                data.federation_ok = false;
                return Ok(());
            }
        } else {
            error!("No Content-Type header in server version response");
            data.error = Some("No Content-Type header in server version response".to_string());
            data.federation_ok = false;
            return Ok(());
        }

        match response.json::<VersionResp>().await {
            Ok(json) => {
                data.version = json.server;
            }
            Err(e) => {
                error!("Error parsing server version response: {e:?}");
                data.error = Some("Failed to parse server version response".to_string());
                data.federation_ok = false;
            }
        }
    } else {
        error!("Error querying server version: {}", response.status());
        data.error = Some("Failed to query server version".to_string());
        data.federation_ok = false;
    }

    Ok(())
}

pub async fn lookup_server(data: &mut Root, server_name: &str) -> color_eyre::eyre::Result<()> {
    let mut srv_responses: BTreeMap<String, Vec<SrvRecord>> = BTreeMap::new();
    let resolver = Resolver::builder_tokio()?.build();

    if !server_name.contains(':') {
        // If there isn't an explicit port set then try to look up the SRV record.
        let srv_records = resolver
            .srv_lookup(&format!("_matrix._tcp.{server_name}."))
            .await;

        match srv_records {
            Ok(records) => {
                for record in records.iter() {
                    let srv = record.clone();
                    let target = srv.target().to_utf8();
                    //  Check whether the target is a CNAME record
                    match resolver.lookup(&target, RecordType::CNAME).await {
                        Ok(cname) => {
                            let cname_target = cname.record_iter().next().map(|c| {
                                c.data()
                                    .as_cname()
                                    .expect("CNAME record expected")
                                    .to_utf8()
                            });
                            if cname_target.clone().is_some_and(|c| c != target) {
                                data.dnsresult.hosts.insert(target.clone(), HostData {
                                    cname: cname_target,
                                    error: Some(format!(
                                        "SRV record target {target} is a CNAME record, which is forbidden (as per RFC2782"
                                    )),
                                    addrs: vec![],
                                });
                                continue;
                            }
                            srv_responses.insert(
                                target,
                                vec![SrvRecord {
                                    priority: Some(srv.priority()),
                                    weight: Some(srv.weight()),
                                    port: srv.port(),
                                    target: cname_target.unwrap(),
                                }],
                            );
                        }
                        Err(e) => {
                            data.dnsresult.hosts.insert(
                                target.clone(),
                                HostData {
                                    cname: Some(target),
                                    error: Some(format!(
                                        "Failed to resolve CNAME for SRV record target: {e}"
                                    )),
                                    addrs: vec![],
                                },
                            );
                        }
                    }
                }
            }
            Err(e) => {
                // Check if timeout occurred
                if let Proto(proto_error) = e.kind()
                    && let ProtoErrorKind::Timeout = proto_error.kind()
                {
                    return Err(color_eyre::eyre::eyre!(
                        "Timeout while looking up SRV records for {server_name}: {e}"
                    ));
                }

                // If there is no SRV then fallback to "serverName:8448"
                srv_responses.insert(
                    server_name.to_string(),
                    vec![SrvRecord {
                        priority: None,
                        weight: None,
                        port: 8448,
                        target: server_name.to_string(),
                    }],
                );
            }
        }
    } else {
        // There is an explicit port set in the server name.
        // We don't need to look up any SRV records.

        let parts: Vec<&str> = server_name.split(':').collect();
        let target = parts[0].to_string();
        let port: u16 = parts.get(1).and_then(|p| p.parse().ok()).unwrap();
        srv_responses.insert(
            target.clone(),
            vec![SrvRecord {
                priority: None,
                weight: None,
                port,
                target,
            }],
        );
        data.dnsresult.srvskipped = true;
    }

    // Look up the A/AAAA records for each target
    for (host, records) in srv_responses {
        // Lookup CNAME but ignore any errors.
        let cname_resp = resolver
            .lookup(&format!("{host}."), RecordType::CNAME)
            .await;
        if let Err(e) = &cname_resp {
            if let ResolveErrorKind::Proto(proto_error) = e.kind()
                && let ProtoErrorKind::NoRecordsFound { .. } = proto_error.kind()
            {
                // Fall through if no CNAME records are found
            } else {
                error!("Error looking up CNAME for {host}: {e}");
                continue;
            }
        }
        let cname_target = if let Ok(cname) = cname_resp {
            let cname_target_res = cname.record_iter().next().map(|c| {
                c.data()
                    .as_cname()
                    .expect("CNAME record expected")
                    .to_utf8()
            });
            cname_target_res.map(|cname_target_inner| cname_target_inner.to_string())
        } else {
            None
        };

        // Lookup A AND AAAA records
        let ipv4_records = resolver.lookup(&format!("{host}."), RecordType::A).await;
        let ipv6_records = resolver.lookup(&format!("{host}."), RecordType::AAAA).await;

        // For each SRV record, for each IP address, convert it to `<ip>:<port>` before inserting
        for record in records.iter() {
            let target = record.target.clone();
            let port = record.port;
            info!(
                "Found SRV record for {host} -> {target}:{port} (priority: {:?}, weight: {:?})",
                record.priority, record.weight
            );

            // Collect all addresses for this target
            let mut addrs: Vec<String> = vec![];
            let mut addrs_with_port: Vec<String> = vec![];
            if let Ok(ref ipv4) = ipv4_records {
                for addr in ipv4.record_iter() {
                    if let Some(ip) = addr.data().as_a() {
                        addrs.push(ip.0.to_string());
                        addrs_with_port.push(format!("{}:{}", ip.0, port));
                    }
                }
            } else {
                error!("Error looking up A records for {host}: {ipv4_records:?}",);
            }
            if let Ok(ref ipv6) = ipv6_records {
                for addr in ipv6.record_iter() {
                    if let Some(ip) = addr.data().as_aaaa() {
                        addrs.push(ip.0.to_string());
                        addrs_with_port.push(format!("[{}]:{}", ip.0, port));
                    }
                }
            } else {
                error!("Error looking up AAAA records for {host}: {ipv6_records:?}",);
            }

            // If no addresses were found, log an error
            if addrs.is_empty() {
                continue;
            }

            // Insert the host data into the result
            let canonical_target = cname_target.clone().unwrap_or(target.clone());
            let dns_formatted_target = format!("{canonical_target}.");
            data.dnsresult.hosts.insert(
                target.clone(),
                HostData {
                    cname: Some(dns_formatted_target),
                    error: None,
                    addrs,
                },
            );
            data.dnsresult.addrs.extend(addrs_with_port);
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
    info!(
        "[fetch_url_custom_sni_host] Fetching {path} from {addr} with SNI {sni_host} and host {host_host}"
    );
    let stream = TcpStream::connect(addr).await?;
    let stream = TokioIo::new(stream);

    let builder = SslConnector::builder(SslMethod::tls_client())?;
    let ssl = builder
        .build()
        .configure()?
        .verify_hostname(true)
        .into_ssl(sni_host)?;
    let mut stream = SslStream::new(ssl, stream)?;
    Pin::new(&mut stream).connect().await?;
    let ssl_ref = stream.ssl();
    let protocol = ssl_ref.version_str();
    let cipher = ssl_ref.current_cipher();
    let chain = ssl_ref.peer_cert_chain();

    let mut response = FullResponse {
        response: None,
        protocol: protocol.to_string(),
        cipher_suite: cipher
            .map(|c| c.standard_name().unwrap().to_string())
            .unwrap(),
        certificates: chain
            .unwrap()
            .iter()
            .map(|cert| {
                let digest = cert.digest(openssl::hash::MessageDigest::sha256()).unwrap();
                let sha256fingerprint = digest.as_ref();
                let sha256fingerprint = STANDARD.encode(sha256fingerprint);

                Certificate {
                    subject_common_name: cert
                        .subject_name()
                        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
                        .next()
                        .map(|e| e.data().as_utf8().unwrap().to_string())
                        .unwrap_or_default(),
                    issuer_common_name: cert
                        .issuer_name()
                        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
                        .next()
                        .map(|e| e.data().as_utf8().unwrap().to_string())
                        .unwrap_or_default(),
                    sha256fingerprint,
                    dnsnames: cert.subject_alt_names().map(|stack| {
                        stack
                            .iter()
                            .map(|name| name.dnsname().map(ToString::to_string).unwrap_or_default())
                            .collect()
                    }),
                }
            })
            .collect(),
    };

    let (mut sender, conn) = hyper::client::conn::http1::handshake(stream).await?;
    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            info!("Connection failed: {err:?}");
        }
    });

    let req = Request::builder()
        .uri(path)
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
    let response =
        fetch_url_custom_sni_host("/_matrix/key/v2/server", addr, server_name, sni).await?;

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

pub async fn connection_check(
    addr: &str,
    server_name: &str,
    server_host: &str,
    sni: &str,
) -> Result<ConnectionReportData, ConnectionError> {
    let mut report = ConnectionReportData::default();
    let key_resp = fetch_keys(addr, server_host, sni).await;
    if let Err(e) = key_resp {
        error!("Error fetching keys from {addr}: {e:?}");
        return Err(ConnectionError {});
    }
    let key_resp = key_resp.unwrap();
    report.keys = key_resp.keys;
    report.cipher.version = key_resp.protocol;
    report.cipher.cipher_suite = key_resp.cipher_suite;
    report.certificates = key_resp.certificates;
    // It seems rust openssl already does the same as go validate is doing here. So as long as we have a chain we should be good.
    report.checks.valid_certificates = !report.certificates.is_empty();

    let (
        future_valid_until_ts,
        has_ed25519_key,
        all_ed25519checks_ok,
        ed25519_checks,
        ed25519_verify_keys,
        matching_server_name,
    ) = verify_keys(server_name, &report.keys, key_resp.keys_string);
    report.checks.future_valid_until_ts = future_valid_until_ts;
    report.checks.has_ed25519key = has_ed25519_key;
    report.checks.all_ed25519checks_ok = all_ed25519checks_ok;
    report.checks.matching_server_name = matching_server_name;
    report.checks.ed25519checks = ed25519_checks;
    report.checks.all_checks_ok = report.checks.has_ed25519key
        && report.checks.all_ed25519checks_ok
        && report.checks.valid_certificates
        && report.checks.matching_server_name
        && report.checks.future_valid_until_ts;
    report.ed25519verify_keys = ed25519_verify_keys;

    Ok(report)
}

fn verify_keys(
    server_name: &str,
    keys: &Keys,
    keys_string: String,
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
        keys.valid_until_ts > time::OffsetDateTime::now_utc().unix_timestamp();

    let (ed25519checks, has_ed25519key, all_ed25519checks_ok, ed25519_verify_keys) =
        check_verify_keys(server_name, &keys, keys_string);

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
    keys_string: String,
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
        info!(
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
                    if let Ok(json_keys) = serde_json::from_str::<serde_json::Value>(&keys_string)
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
