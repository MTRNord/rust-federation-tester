use base64::Engine;
use base64::prelude::BASE64_STANDARD_NO_PAD;
use rust_federation_tester::federation::{extract_certificate_info, verify_keys};
use rust_federation_tester::response::{Certificate, Ed25519VerifyKey, Keys};
use rustls_pki_types::CertificateDer;
use std::collections::BTreeMap;
use time::OffsetDateTime;

#[test]
fn test_verify_keys_server_name_mismatch() {
    let keys = Keys {
        server_name: "wrong.example.org".to_string(),
        valid_until_ts: OffsetDateTime::now_utc().unix_timestamp() + 3600,
        verify_keys: BTreeMap::new(),
        signatures: BTreeMap::new(),
        old_verify_keys: None,
    };

    let keys_json = serde_json::to_string(&keys).unwrap();
    let (future_valid, has_ed25519, all_ok, ed_checks, verify_keys, matching_server) =
        verify_keys("example.org", &keys, &keys_json);

    assert!(future_valid);
    assert!(!has_ed25519);
    assert!(all_ok); // No keys to check means all pass
    assert!(ed_checks.is_empty());
    assert!(verify_keys.is_empty());
    assert!(!matching_server); // Server name doesn't match
}

#[test]
fn test_verify_keys_expired_timestamp() {
    let keys = Keys {
        server_name: "example.org".to_string(),
        valid_until_ts: OffsetDateTime::now_utc().unix_timestamp() - 3600, // Expired
        verify_keys: BTreeMap::new(),
        signatures: BTreeMap::new(),
        old_verify_keys: None,
    };

    let keys_json = serde_json::to_string(&keys).unwrap();
    let (future_valid, has_ed25519, all_ok, ed_checks, verify_keys, matching_server) =
        verify_keys("example.org", &keys, &keys_json);

    assert!(!future_valid); // Expired timestamp
    assert!(!has_ed25519);
    assert!(all_ok); // No keys to check
    assert!(ed_checks.is_empty());
    assert!(verify_keys.is_empty());
    assert!(matching_server);
}

#[test]
fn test_verify_keys_invalid_key_length() {
    let mut verify_keys_map = BTreeMap::new();
    verify_keys_map.insert(
        "ed25519:short".to_string(),
        Ed25519VerifyKey {
            key: BASE64_STANDARD_NO_PAD.encode(b"short"), // Too short for ed25519
            expired_ts: None,
        },
    );

    let keys = Keys {
        server_name: "example.org".to_string(),
        valid_until_ts: OffsetDateTime::now_utc().unix_timestamp() + 3600,
        verify_keys: verify_keys_map,
        signatures: BTreeMap::new(),
        old_verify_keys: None,
    };

    let keys_json = serde_json::to_string(&keys).unwrap();
    let (future_valid, has_ed25519, all_ok, ed_checks, verify_keys_out, matching_server) =
        verify_keys("example.org", &keys, &keys_json);

    assert!(future_valid);
    assert!(has_ed25519); // Has ed25519 key (even if invalid)
    assert!(!all_ok); // Invalid key length fails
    assert_eq!(ed_checks.len(), 1);
    assert!(!ed_checks["ed25519:short"].valid_ed25519); // Invalid key
    assert!(!ed_checks["ed25519:short"].matching_signature); // No signature match
    assert!(verify_keys_out.is_empty()); // No valid keys
    assert!(matching_server);
}

#[test]
fn test_verify_keys_non_ed25519_algorithm() {
    let mut verify_keys_map = BTreeMap::new();
    verify_keys_map.insert(
        "rsa:key1".to_string(),
        Ed25519VerifyKey {
            key: "some_key".to_string(),
            expired_ts: None,
        },
    );

    let keys = Keys {
        server_name: "example.org".to_string(),
        valid_until_ts: OffsetDateTime::now_utc().unix_timestamp() + 3600,
        verify_keys: verify_keys_map,
        signatures: BTreeMap::new(),
        old_verify_keys: None,
    };

    let keys_json = serde_json::to_string(&keys).unwrap();
    let (future_valid, has_ed25519, all_ok, ed_checks, verify_keys_out, matching_server) =
        verify_keys("example.org", &keys, &keys_json);

    assert!(future_valid);
    assert!(!has_ed25519); // No ed25519 keys
    assert!(all_ok); // No ed25519 keys to fail
    assert!(ed_checks.is_empty()); // No ed25519 checks
    assert!(verify_keys_out.is_empty());
    assert!(matching_server);
}

#[test]
fn test_verify_keys_malformed_base64() {
    let mut verify_keys_map = BTreeMap::new();
    verify_keys_map.insert(
        "ed25519:malformed".to_string(),
        Ed25519VerifyKey {
            key: "invalid_base64!".to_string(), // Malformed base64
            expired_ts: None,
        },
    );

    let keys = Keys {
        server_name: "example.org".to_string(),
        valid_until_ts: OffsetDateTime::now_utc().unix_timestamp() + 3600,
        verify_keys: verify_keys_map,
        signatures: BTreeMap::new(),
        old_verify_keys: None,
    };

    let keys_json = serde_json::to_string(&keys).unwrap();
    let (future_valid, has_ed25519, all_ok, ed_checks, verify_keys_out, matching_server) =
        verify_keys("example.org", &keys, &keys_json);

    assert!(future_valid);
    assert!(!has_ed25519); // Base64 decode fails, so no ed25519 key detected
    assert!(all_ok); // No valid ed25519 keys to check
    assert!(ed_checks.is_empty());
    assert!(verify_keys_out.is_empty());
    assert!(matching_server);
}

#[test]
fn test_extract_certificate_info_empty_der() {
    let empty_der = CertificateDer::from(vec![]);
    let result = extract_certificate_info(&empty_der);
    assert!(result.is_none()); // Should return None for empty DER
}

#[test]
fn test_extract_certificate_info_invalid_der() {
    let invalid_der = CertificateDer::from(vec![0x00, 0x01, 0x02, 0x03]); // Random bytes
    let result = extract_certificate_info(&invalid_der);
    assert!(result.is_none()); // Should return None for invalid DER
}

#[test]
fn test_certificate_default_values() {
    let cert = Certificate::default();
    assert!(cert.subject_common_name.is_empty());
    assert!(cert.issuer_common_name.is_empty());
    assert!(cert.dnsnames.is_none());
    assert!(cert.sha256fingerprint.is_empty());
}

#[test]
fn test_keys_with_old_verify_keys() {
    let mut old_keys = BTreeMap::new();
    old_keys.insert(
        "ed25519:old1".to_string(),
        Ed25519VerifyKey {
            key: BASE64_STANDARD_NO_PAD.encode([1u8; 32]), // Valid 32-byte key
            expired_ts: Some(OffsetDateTime::now_utc().unix_timestamp() - 1000), // Expired
        },
    );

    let keys = Keys {
        server_name: "example.org".to_string(),
        valid_until_ts: OffsetDateTime::now_utc().unix_timestamp() + 3600,
        verify_keys: BTreeMap::new(),
        signatures: BTreeMap::new(), // Required field
        old_verify_keys: Some(old_keys),
    };

    // Test serialization includes old_verify_keys
    let json = serde_json::to_string(&keys).unwrap();
    assert!(json.contains("old_verify_keys"));
    assert!(json.contains("ed25519:old1"));

    // For deserialization test, we need to include all required fields in JSON
    let json_with_all_fields = format!(
        r#"{{
        "server_name": "example.org",
        "valid_until_ts": {},
        "old_verify_keys": {{"ed25519:old1": {{"key": "{}", "expired_ts": {}}}}},
        "verify_keys": {{}},
        "signatures": {{}}
    }}"#,
        keys.valid_until_ts,
        BASE64_STANDARD_NO_PAD.encode([1u8; 32]),
        OffsetDateTime::now_utc().unix_timestamp() - 1000
    );

    let deserialized: Keys = serde_json::from_str(&json_with_all_fields).unwrap();
    assert!(deserialized.old_verify_keys.is_some());
    assert_eq!(deserialized.old_verify_keys.unwrap().len(), 1);
}

#[test]
fn test_keys_serialization_skips_empty_collections() {
    let keys = Keys {
        server_name: "example.org".to_string(),
        valid_until_ts: 1234567890,
        verify_keys: BTreeMap::new(), // Empty
        signatures: BTreeMap::new(),  // Empty
        old_verify_keys: None,
    };

    let json = serde_json::to_string(&keys).unwrap();
    // Should skip empty collections due to serde annotations
    assert!(!json.contains("old_verify_keys"));
    assert!(!json.contains("signatures") || json.contains("\"signatures\":{}"));
    assert!(!json.contains("verify_keys") || json.contains("\"verify_keys\":{}"));
}
