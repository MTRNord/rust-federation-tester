use crate::error::FetchError;
use crate::federation::network::fetch_url_custom_sni_host;
use crate::federation::well_known::NETWORK_TIMEOUT_SECS;
use crate::response::{Certificate, Ed25519Check, Keys};
use ::time as time_crate;
use base64::Engine;
use base64::prelude::BASE64_STANDARD_NO_PAD;
use ed25519::Signature;
use ed25519::signature::Verifier;
use ed25519_dalek::VerifyingKey;
use http_body_util::BodyExt;
use serde_json;
use std::collections::BTreeMap;
use tokio::time::{Duration, timeout};
use tracing::{debug, error};

#[derive(Debug, Clone)]
pub struct FullKeysResponse {
    pub keys: Keys,
    pub protocol: String,
    pub cipher_suite: String,
    pub certificates: Vec<Certificate>,
    pub keys_string: String,
}

#[tracing::instrument(name = "federation_fetch_keys", fields(addr = %addr, server_name = %server_name, sni = %sni))]
pub async fn fetch_keys(
    addr: &str,
    server_name: &str,
    sni: &str,
) -> color_eyre::eyre::Result<FullKeysResponse> {
    let timeout_duration = Duration::from_secs(NETWORK_TIMEOUT_SECS);
    let response = timeout(
        timeout_duration,
        fetch_url_custom_sni_host("/_matrix/key/v2/server", addr, server_name, sni),
    )
    .await
    .map_err(|_| color_eyre::eyre::eyre!("Timeout while fetching keys"))?
    .map_err(|e| color_eyre::eyre::eyre!(e.to_string()))?;

    let http_response = response.response.unwrap();
    if !http_response.status().is_success() {
        return Err(color_eyre::eyre::eyre!(
            FetchError::Http {
                status: http_response.status(),
                context: "fetch_keys".into()
            }
            .to_string()
        ));
    }

    let body = http_response
        .into_body()
        .collect()
        .await
        .map_err(|e| color_eyre::eyre::eyre!(FetchError::Network(e.to_string()).to_string()))?
        .to_bytes();
    let keys_string = String::from_utf8(body.to_vec()).map_err(|_| {
        color_eyre::eyre::eyre!(FetchError::UnexpectedContentType("non-utf8".into()).to_string())
    })?;
    let keys: Keys = serde_json::from_str(&keys_string)
        .map_err(|_| color_eyre::eyre::eyre!(FetchError::Json("keys parse".into()).to_string()))?;

    Ok(FullKeysResponse {
        keys,
        protocol: response.protocol,
        cipher_suite: response.cipher_suite,
        certificates: response.certificates,
        keys_string,
    })
}

pub fn verify_keys(
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
                    if let Ok(json_keys) =
                        crate::security::secure_parse_json_slice(keys_string.as_bytes())
                        && let Some(signatures) = json_keys.get("signatures")
                        && let Some(server_signatures) = signatures.get(server_name)
                        && let Some(signature) = server_signatures.get(key_id.clone())
                        && let Ok(signature_bytes) =
                            BASE64_STANDARD_NO_PAD.decode(signature.as_str().unwrap_or_default())
                        && signature_bytes.len() == 64
                    {
                        let mut json_keys_clone = json_keys.clone();
                        json_keys_clone.as_object_mut().unwrap().remove("unsigned");
                        json_keys_clone
                            .as_object_mut()
                            .unwrap()
                            .remove("signatures");
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
