use crate::connection_pool::ConnectionPool;
use crate::error::FetchError;
use crate::federation::config::FederationConfig;
use crate::federation::network::fetch_url_custom_sni_host;
use crate::response::{Certificate, Ed25519Check, Keys};

use ::time as time_crate;
use base64::Engine;
use base64::prelude::BASE64_STANDARD_NO_PAD;
use ed25519_dalek::VerifyingKey;
use ed25519_dalek::ed25519::Signature;
use ed25519_dalek::ed25519::signature::Verifier;
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
    /// Whether /_matrix/key/v2/server returned Content-Type: application/json.
    pub content_type_ok: bool,
}

#[tracing::instrument(skip(pool, config))]
pub async fn fetch_keys(
    addr: &str,
    server_name: &str,
    sni: &str,
    pool: &ConnectionPool,
    config: &FederationConfig,
) -> color_eyre::eyre::Result<FullKeysResponse> {
    let response = timeout(
        config.network_timeout,
        fetch_url_custom_sni_host(
            "/_matrix/key/v2/server",
            addr,
            server_name,
            sni,
            Some(pool),
            config,
        ),
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

    let content_type_ok = http_response
        .headers()
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("application/json"));

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
        content_type_ok,
    })
}

pub struct KeyVerificationResult {
    pub matching_server_name: bool,
    pub future_valid_until_ts: bool,
    /// Spec MUST: valid_until_ts ≤ now + 7 days.
    pub valid_until_ts_within_7_days: bool,
    /// Spec SHOULD: valid_until_ts ≥ now + 1 hour (useful for caching).
    pub valid_until_ts_not_expiring_soon: bool,
    pub has_ed25519key: bool,
    pub all_ed25519checks_ok: bool,
    pub ed25519checks: BTreeMap<String, Ed25519Check>,
    pub ed25519_verify_keys: BTreeMap<String, String>,
}

#[tracing::instrument()]
pub fn verify_keys(server_name: &str, keys: &Keys, keys_string: &str) -> KeyVerificationResult {
    let now_ms = time_crate::OffsetDateTime::now_utc().unix_timestamp() * 1000;
    let valid_until_ms = keys.valid_until_ts;

    let matching_server_name = keys.server_name == server_name;
    let future_valid_until_ts = valid_until_ms > now_ms;
    let seven_days_ms: i64 = 7 * 24 * 60 * 60 * 1000;
    let one_hour_ms: i64 = 60 * 60 * 1000;
    let valid_until_ts_within_7_days = valid_until_ms <= now_ms + seven_days_ms;
    let valid_until_ts_not_expiring_soon = valid_until_ms >= now_ms + one_hour_ms;

    let (ed25519checks, has_ed25519key, all_ed25519checks_ok, ed25519_verify_keys) =
        check_verify_keys(server_name, keys, keys_string);

    KeyVerificationResult {
        matching_server_name,
        future_valid_until_ts,
        valid_until_ts_within_7_days,
        valid_until_ts_not_expiring_soon,
        has_ed25519key,
        all_ed25519checks_ok,
        ed25519checks,
        ed25519_verify_keys,
    }
}

/// Errors that can occur while verifying an ed25519 signature.
#[derive(Debug)]
enum SigError {
    JsonParse,
    SigDecode,
    SigWrongLen(usize),
    Canonicalize,
    SigParse,
    BadKeyPoint,
    /// Signature parsed fine but failed cryptographic verification.
    Mismatch,
    /// JSON contains floats, -0, or integers outside [-(2^53)+1, (2^53)-1].
    NonCanonicalNumbers,
}

fn validate_canonical_numbers(value: &serde_json::Value) -> Result<(), SigError> {
    match value {
        serde_json::Value::Number(n) => {
            if n.is_f64() {
                return Err(SigError::NonCanonicalNumbers);
            }
            const MIN: i64 = -(1i64 << 53) + 1;
            const MAX: u64 = (1u64 << 53) - 1;
            if n.as_i64().is_some_and(|i| i < MIN) || n.as_u64().is_some_and(|u| u > MAX) {
                return Err(SigError::NonCanonicalNumbers);
            }
            Ok(())
        }
        serde_json::Value::Object(map) => map.values().try_for_each(validate_canonical_numbers),
        serde_json::Value::Array(arr) => arr.iter().try_for_each(validate_canonical_numbers),
        _ => Ok(()),
    }
}

/// Pure-logic inner helper: no logging, all errors propagated via `?`.
fn verify_ed25519_inner(
    key_array: &[u8; 32],
    server_name: &str,
    key_id: &str,
    keys_string: &str,
) -> Result<(), SigError> {
    let json_keys = crate::security::secure_parse_json_slice(keys_string.as_bytes())
        .map_err(|_| SigError::JsonParse)?;

    let signature_b64 = json_keys
        .get("signatures")
        .and_then(|s| s.get(server_name))
        .and_then(|s| s.get(key_id))
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    let signature_bytes = BASE64_STANDARD_NO_PAD
        .decode(signature_b64)
        .map_err(|_| SigError::SigDecode)?;
    if signature_bytes.len() != 64 {
        return Err(SigError::SigWrongLen(signature_bytes.len()));
    }

    validate_canonical_numbers(&json_keys)?;

    let mut json_clone = json_keys.clone();
    if let Some(obj) = json_clone.as_object_mut() {
        obj.remove("unsigned");
        obj.remove("signatures");
    }
    let canonical_json = serde_json::to_string(&json_clone).map_err(|_| SigError::Canonicalize)?;

    let ed25519_sig = Signature::from_slice(&signature_bytes).map_err(|_| SigError::SigParse)?;
    let verify_key = VerifyingKey::from_bytes(key_array).map_err(|_| SigError::BadKeyPoint)?;

    verify_key
        .verify(canonical_json.as_bytes(), &ed25519_sig)
        .map_err(|_| SigError::Mismatch)
}

/// Maps a `SigError` to a (tracing-event-name, human-message, is_non_canonical) tuple.
/// `SigWrongLen` must be handled by the caller before calling this.
fn sig_error_info(e: &SigError) -> (&'static str, &'static str, bool) {
    match e {
        SigError::JsonParse => (
            "federation.keys.json_parse_failed",
            "Failed to parse keys_string for signature verification",
            false,
        ),
        SigError::SigDecode => (
            "federation.keys.signature_decode_failed",
            "Failed to base64-decode signature",
            false,
        ),
        SigError::Canonicalize => (
            "federation.keys.canonicalization_failed",
            "Failed to serialize canonical JSON for signature verification",
            false,
        ),
        SigError::SigParse => (
            "federation.keys.signature_parse_failed",
            "Failed to parse ed25519 Signature from bytes",
            false,
        ),
        SigError::BadKeyPoint => (
            "federation.keys.invalid_public_key_point",
            "Public key bytes are not a valid ed25519 curve point",
            false,
        ),
        SigError::Mismatch => (
            "federation.keys.signature_verification_failed",
            "Signature verification failed",
            false,
        ),
        SigError::NonCanonicalNumbers => (
            "federation.keys.non_canonical_numbers",
            "Key response contains floats, -0, or out-of-range integers — not valid Matrix canonical JSON",
            true,
        ),
        SigError::SigWrongLen(_) => unreachable!("handled before sig_error_info"),
    }
}

fn log_sig_error(key_id: &str, err: SigError) -> crate::response::SignatureCheckError {
    if let SigError::SigWrongLen(n) = err {
        tracing::error!(
            name = "federation.keys.signature_wrong_length",
            target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            key_id = %key_id,
            len = n,
            message = "Signature bytes have wrong length (expected 64)"
        );
        return crate::response::SignatureCheckError::Mismatch;
    }
    let (event_name, msg, non_canonical) = sig_error_info(&err);
    tracing::error!(
        name = event_name,
        target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
        key_id = %key_id,
        message = msg
    );
    if non_canonical {
        crate::response::SignatureCheckError::NonCanonicalJson
    } else {
        crate::response::SignatureCheckError::Mismatch
    }
}

/// Verify one ed25519 signature, logging the specific failure reason on error.
///
/// Returns `None` on success, `Some(error)` on any failure. All failure paths
/// are handled gracefully — never panics.
#[tracing::instrument(skip(keys_string))]
fn verify_ed25519_signature(
    key_id: &str,
    public_key_bytes: &[u8],
    server_name: &str,
    keys_string: &str,
) -> Option<crate::response::SignatureCheckError> {
    let Ok(key_array) = public_key_bytes.try_into() else {
        return Some(crate::response::SignatureCheckError::Mismatch);
    };
    match verify_ed25519_inner(key_array, server_name, key_id, keys_string) {
        Ok(()) => None,
        Err(e) => Some(log_sig_error(key_id, e)),
    }
}

/// Check result for a single ed25519 verify key.
struct Ed25519KeyResult {
    check: Ed25519Check,
    /// The raw base64 key value — present only when signature matched.
    valid_key_value: Option<String>,
}

/// Process one entry from `verify_keys`. Returns `None` for non-ed25519 entries
/// or when the public key cannot be base64-decoded.
fn process_ed25519_key(
    key_id: &str,
    key_data: &crate::response::Ed25519VerifyKey,
    server_name: &str,
    keys_string: &str,
) -> Option<Ed25519KeyResult> {
    let algorithm = key_id.split(':').next().unwrap_or_default();
    if algorithm != "ed25519" {
        return None;
    }

    let Ok(public_key) = BASE64_STANDARD_NO_PAD.decode(&key_data.key) else {
        tracing::error!(
            name = "federation.keys.decode_public_key_failed",
            target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            key_id = %key_id,
            algorithm = %algorithm,
            public_key = %key_data.key,
            message = "Failed to base64-decode public key"
        );
        return None;
    };

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

    let sig_error = if valid_length {
        verify_ed25519_signature(key_id, &public_key, server_name, keys_string)
    } else {
        None
    };
    let matching_signature = valid_length && sig_error.is_none();

    Some(Ed25519KeyResult {
        check: Ed25519Check {
            valid_ed25519: valid_length,
            matching_signature,
            error: sig_error,
        },
        valid_key_value: matching_signature.then(|| key_data.key.clone()),
    })
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

    for (key_id, key_data) in &keys.verify_keys {
        let algorithm = key_id.split(':').next().unwrap_or_default();
        tracing::debug!(
            name = "federation.keys.check_key",
            target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            key_id = %key_id,
            algorithm = %algorithm,
            public_key = %key_data.key,
            message = "Checking key id and algorithm"
        );

        let Some(result) = process_ed25519_key(key_id, key_data, server_name, keys_string) else {
            continue;
        };

        has_ed25519key = true;
        if let Some(valid_key) = result.valid_key_value {
            ed25519_verify_keys.insert(key_id.clone(), valid_key);
        } else {
            all_ed25519checks_ok = false;
        }
        ed25519checks.insert(key_id.clone(), result.check);
    }

    (
        ed25519checks,
        has_ed25519key,
        all_ed25519checks_ok,
        ed25519_verify_keys,
    )
}
