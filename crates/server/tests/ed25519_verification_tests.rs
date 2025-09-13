use base64::Engine;
use base64::prelude::BASE64_STANDARD_NO_PAD;
use rust_federation_tester::federation::verify_keys;
use rust_federation_tester::response::{Ed25519VerifyKey, Keys};
use serde_json::json;

// Helper to build a minimal keys JSON structure with a single ed25519 key & signature.
fn build_keys_json(
    server_name: &str,
    key_id: &str,
    public_key_b64: &str,
    signature_b64: &str,
    valid_until_ts: i64,
) -> String {
    json!({
        "server_name": server_name,
        "valid_until_ts": valid_until_ts,
        "verify_keys": { key_id: { "key": public_key_b64 } },
        "signatures": { server_name: { key_id: signature_b64 } }
    })
    .to_string()
}

#[test]
fn test_ed25519_verification_invalid_signature() {
    // A 32-byte random public key (not meaningful here) base64 (no padding)
    let public_key: [u8; 32] = [1u8; 32];
    let public_key_b64 = BASE64_STANDARD_NO_PAD.encode(public_key);

    // A 64-byte fake signature (also random)
    let signature: [u8; 64] = [2u8; 64];
    let signature_b64 = BASE64_STANDARD_NO_PAD.encode(signature);

    let server_name = "example.org";
    let key_id = "ed25519:a_1";
    let valid_until_ts = (time::OffsetDateTime::now_utc().unix_timestamp() + 3600) as i64;

    let keys_json = build_keys_json(
        server_name,
        key_id,
        &public_key_b64,
        &signature_b64,
        valid_until_ts,
    );

    // Build Keys struct (matches response::Keys layout)
    let keys = Keys {
        old_verify_keys: None,
        server_name: server_name.to_string(),
        signatures: std::collections::BTreeMap::new(), // Will be read from raw JSON in verification path
        valid_until_ts,
        verify_keys: {
            let mut map = std::collections::BTreeMap::new();
            map.insert(
                key_id.to_string(),
                Ed25519VerifyKey {
                    key: public_key_b64.clone(),
                    expired_ts: None,
                },
            );
            map
        },
    };

    let (_future_valid, has_ed25519, all_ok, ed_checks, _verify_keys, matching_server) =
        verify_keys(server_name, &keys, &keys_json);

    assert!(has_ed25519, "Should detect ed25519 key present");
    assert!(!all_ok, "Random signature must NOT verify");
    assert!(ed_checks.get(key_id).is_some());
    assert!(matching_server, "Server name must match in this test");
}
