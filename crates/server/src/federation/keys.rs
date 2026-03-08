use crate::error::FetchError;
use crate::federation::network::fetch_url_custom_sni_host;
use crate::federation::well_known::network_timeout;
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
use tokio::time::timeout;

#[derive(Debug, Clone)]
pub struct FullKeysResponse {
    pub keys: Keys,
    pub protocol: String,
    pub cipher_suite: String,
    pub certificates: Vec<Certificate>,
    pub keys_string: String,
}

#[tracing::instrument()]
pub async fn fetch_keys(
    addr: &str,
    server_name: &str,
    sni: &str,
) -> color_eyre::eyre::Result<FullKeysResponse> {
    let timeout_duration = network_timeout();
    let response = timeout(
        timeout_duration,
        fetch_url_custom_sni_host("/_matrix/key/v2/server", addr, server_name, sni),
    )
    .await
    .map_err(|_| color_eyre::eyre::eyre!("Timeout while fetching keys"))?
    .map_err(|e| color_eyre::eyre::eyre!(e.to_string()))?;

    let http_response = response.response.ok_or_else(|| {
        color_eyre::eyre::eyre!("No HTTP response received from /_matrix/key/v2/server")
    })?;
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

#[tracing::instrument()]
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

/// Verify one ed25519 signature.
///
/// Returns `true` when the signature in the key document matches the given public key.
/// All failure paths are handled gracefully — never panics.
#[tracing::instrument(skip(keys_string))]
fn verify_ed25519_signature(
    key_id: &str,
    public_key_bytes: &[u8],
    server_name: &str,
    keys_string: &str,
) -> bool {
    if public_key_bytes.len() != 32 {
        return false;
    }

    let Ok(json_keys) = crate::security::secure_parse_json_slice(keys_string.as_bytes()) else {
        tracing::error!(
            name = "federation.keys.json_parse_failed",
            target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            key_id = %key_id,
            message = "Failed to parse keys_string for signature verification"
        );
        return false;
    };

    // Locate the server's signature for this key_id
    let signature_b64 = json_keys
        .get("signatures")
        .and_then(|s| s.get(server_name))
        .and_then(|s| s.get(key_id))
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    let Ok(signature_bytes) = BASE64_STANDARD_NO_PAD.decode(signature_b64) else {
        tracing::error!(
            name = "federation.keys.signature_decode_failed",
            target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            key_id = %key_id,
            message = "Failed to base64-decode signature"
        );
        return false;
    };
    if signature_bytes.len() != 64 {
        tracing::error!(
            name = "federation.keys.signature_wrong_length",
            target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            key_id = %key_id,
            len = signature_bytes.len(),
            message = "Signature bytes have wrong length (expected 64)"
        );
        return false;
    }

    // Canonicalize: remove "unsigned" and "signatures" before verifying
    let mut json_keys_clone = json_keys.clone();
    if let Some(obj) = json_keys_clone.as_object_mut() {
        obj.remove("unsigned");
        obj.remove("signatures");
    }
    let Ok(canonical_json) = serde_json::to_string(&json_keys_clone) else {
        tracing::error!(
            name = "federation.keys.canonicalization_failed",
            target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            key_id = %key_id,
            message = "Failed to serialize canonical JSON for signature verification"
        );
        return false;
    };

    let Ok(ed25519_signature) = Signature::from_slice(&signature_bytes) else {
        tracing::error!(
            name = "federation.keys.signature_parse_failed",
            target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            key_id = %key_id,
            message = "Failed to parse ed25519 Signature from bytes"
        );
        return false;
    };

    // Safety: length already checked above (== 32)
    let key_array: [u8; 32] = match public_key_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };

    let Ok(verify_key) = VerifyingKey::from_bytes(&key_array) else {
        tracing::error!(
            name = "federation.keys.invalid_public_key_point",
            target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            key_id = %key_id,
            message = "Public key bytes are not a valid ed25519 curve point"
        );
        return false;
    };

    let ok = verify_key
        .verify(canonical_json.as_bytes(), &ed25519_signature)
        .is_ok();
    if !ok {
        tracing::error!(
            name = "federation.keys.signature_verification_failed",
            target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            key_id = %key_id,
            message = "Signature verification failed"
        );
    }
    ok
}

#[tracing::instrument()]
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
        // key_id format is "algorithm:identifier"; algorithm is the part before the first ':'
        let algorithm = key_id.split(':').next().unwrap_or_default();
        tracing::debug!(
            name = "federation.keys.check_key",
            target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            key_id = %key_id,
            algorithm = %algorithm,
            public_key = %key_data.key,
            message = "Checking key id and algorithm"
        );

        let Ok(public_key) = BASE64_STANDARD_NO_PAD.decode(key_data.key.clone()) else {
            tracing::error!(
                name = "federation.keys.decode_public_key_failed",
                target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                key_id = %key_id,
                algorithm = %algorithm,
                public_key = %key_data.key,
                message = "Failed to base64-decode public key"
            );
            continue;
        };

        if algorithm == "ed25519" {
            has_ed25519key = true;
            let valid_length = public_key.len() == 32;
            if !valid_length {
                tracing::error!(
                    name = "federation.keys.invalid_public_key_length",
                    target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                    key_id = %key_id,
                    public_key_len = public_key.len(),
                    message = "Invalid ed25519 public key length (expected 32 bytes)"
                );
            }
            let matching_signature = valid_length
                && verify_ed25519_signature(&key_id, &public_key, server_name, keys_string);

            ed25519checks.insert(
                key_id.clone(),
                Ed25519Check {
                    valid_ed25519: valid_length,
                    matching_signature,
                },
            );
            if matching_signature {
                ed25519_verify_keys.insert(key_id, key_data.key);
            } else {
                all_ed25519checks_ok = false;
            }
        }
    }
    (
        ed25519checks,
        has_ed25519key,
        all_ed25519checks_ok,
        ed25519_verify_keys,
    )
}
