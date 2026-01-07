use rust_federation_tester::response::{
    Certificate, Checks, Cipher, ConnectionReportData, Dnsresult, Ed25519Check, Ed25519VerifyKey,
    Error, ErrorCode, InvalidServerNameErrorCode, Keys, Root, SRVData, Version, WellKnownResult,
};

use std::collections::BTreeMap;

#[test]
fn test_root_default() {
    let root = Root::default();
    assert!(!root.federation_ok);
    assert!(root.well_known_result.is_empty());
    assert!(root.connection_reports.is_empty());
    assert!(root.connection_errors.is_empty());
    assert!(root.error.is_none());
}

#[test]
fn test_error_serialization() {
    let error = Error {
        error: "Test error message".to_string(),
        error_code: ErrorCode::NotOk("500".to_string()),
    };

    let json = serde_json::to_string(&error).expect("serialization failed");
    assert!(json.contains("Test error message"));
    assert!(json.contains("NotOk"));

    let deserialized: Error = serde_json::from_str(&json).expect("deserialization failed");
    assert_eq!(deserialized, error);
}

#[test]
fn test_error_code_variants() {
    let codes = vec![
        ErrorCode::Unknown,
        ErrorCode::NoRecordsFound,
        ErrorCode::NoResponse,
        ErrorCode::Timeout,
        ErrorCode::NotOk("404".to_string()),
        ErrorCode::InvalidJson("syntax error".to_string()),
        ErrorCode::UnexpectedContentType("text/html".to_string()),
        ErrorCode::MissingContentType,
        ErrorCode::InvalidServerName(InvalidServerNameErrorCode::InvalidCharacter),
    ];

    for code in codes {
        // Test serialization/deserialization
        let json = serde_json::to_string(&code).expect("serialization failed");
        let _: ErrorCode = serde_json::from_str(&json).expect("deserialization failed");
    }
}

#[test]
fn test_invalid_server_name_error_code_variants() {
    let codes = vec![
        InvalidServerNameErrorCode::Unknown,
        InvalidServerNameErrorCode::EmptyString,
        InvalidServerNameErrorCode::EmptyHostname,
        InvalidServerNameErrorCode::NotValidDNS,
        InvalidServerNameErrorCode::InvalidCharacter,
    ];

    for code in codes {
        let json = serde_json::to_string(&code).expect("serialization failed");
        let _: InvalidServerNameErrorCode =
            serde_json::from_str(&json).expect("deserialization failed");
    }
}

#[test]
fn test_version_serialization() {
    let version = Version {
        name: "Synapse".to_string(),
        version: "1.95.1".to_string(),
    };

    let json = serde_json::to_string(&version).expect("serialization failed");
    assert!(json.contains("Synapse"));
    assert!(json.contains("1.95.1"));

    let deserialized: Version = serde_json::from_str(&json).expect("deserialization failed");
    assert_eq!(deserialized, version);
}

#[test]
fn test_ed25519_verify_key() {
    let key = Ed25519VerifyKey {
        key: "abcd1234".to_string(),
        expired_ts: Some(1234567890),
    };

    let json = serde_json::to_string(&key).expect("serialization failed");
    assert!(json.contains("abcd1234"));
    assert!(json.contains("1234567890"));

    let deserialized: Ed25519VerifyKey =
        serde_json::from_str(&json).expect("deserialization failed");
    assert_eq!(deserialized, key);

    // Test None case
    let key_no_expiry = Ed25519VerifyKey {
        key: "efgh5678".to_string(),
        expired_ts: None,
    };
    let json = serde_json::to_string(&key_no_expiry).expect("serialization failed");
    assert!(!json.contains("expired_ts")); // Should be skipped if None
}

#[test]
fn test_ed25519_check() {
    let check = Ed25519Check {
        valid_ed25519: true,
        matching_signature: false,
    };

    let json = serde_json::to_string(&check).expect("serialization failed");
    assert!(json.contains("true"));
    assert!(json.contains("false"));

    let deserialized: Ed25519Check = serde_json::from_str(&json).expect("deserialization failed");
    assert_eq!(deserialized, check);
}

#[test]
fn test_keys_serialization() {
    let mut verify_keys = BTreeMap::new();
    verify_keys.insert(
        "ed25519:key1".to_string(),
        Ed25519VerifyKey {
            key: "abc123".to_string(),
            expired_ts: None,
        },
    );

    let mut signatures = BTreeMap::new();
    let mut server_sigs = BTreeMap::new();
    server_sigs.insert("ed25519:key1".to_string(), "signature123".to_string());
    signatures.insert("example.org".to_string(), server_sigs);

    let keys = Keys {
        old_verify_keys: None,
        server_name: "example.org".to_string(),
        signatures,
        valid_until_ts: 1234567890,
        verify_keys,
    };

    let json = serde_json::to_string(&keys).expect("serialization failed");
    assert!(json.contains("example.org"));
    assert!(json.contains("abc123"));
    assert!(json.contains("signature123"));

    let deserialized: Keys = serde_json::from_str(&json).expect("deserialization failed");
    assert_eq!(deserialized.server_name, "example.org");
    assert_eq!(deserialized.valid_until_ts, 1234567890);
}

#[test]
fn test_well_known_result() {
    let result = WellKnownResult {
        m_server: "matrix.example.org:443".to_string(),
        cache_expires_at: 1234567890,
        error: None,
    };

    let json = serde_json::to_string(&result).expect("serialization failed");
    assert!(json.contains("matrix.example.org"));
    assert!(json.contains("1234567890"));

    let deserialized: WellKnownResult =
        serde_json::from_str(&json).expect("deserialization failed");
    assert_eq!(deserialized, result);
}

#[test]
fn test_certificate_default() {
    let cert = Certificate::default();
    assert!(cert.subject_common_name.is_empty());
    assert!(cert.issuer_common_name.is_empty());
    assert!(cert.dnsnames.is_none());
    assert!(cert.sha256fingerprint.is_empty());
}

#[test]
fn test_cipher_serialization() {
    let cipher = Cipher {
        version: "TLSv1.3".to_string(),
        cipher_suite: "TLS_AES_256_GCM_SHA384".to_string(),
    };

    let json = serde_json::to_string(&cipher).expect("serialization failed");
    assert!(json.contains("TLSv1.3"));
    assert!(json.contains("TLS_AES_256_GCM_SHA384"));
}

#[test]
fn test_checks_default() {
    let checks = Checks::default();
    assert!(!checks.all_checks_ok);
    assert!(!checks.matching_server_name);
    assert!(!checks.future_valid_until_ts);
    assert!(!checks.has_ed25519key);
    assert!(!checks.all_ed25519checks_ok);
    assert!(checks.ed25519checks.is_empty());
    assert!(!checks.valid_certificates);
    assert!(!checks.server_version_parses);
}

#[test]
fn test_srv_data_serialization() {
    let srv = SRVData {
        target: "matrix.example.org".to_string(),
        srv_prefix: Some("_matrix._tcp".to_string()),
        addrs: vec!["192.168.1.1:8448".to_string()],
        error: None,
        port: 8448,
        priority: Some(10),
        weight: Some(0),
    };

    let json = serde_json::to_string(&srv).expect("serialization failed");
    assert!(json.contains("matrix.example.org"));
    assert!(json.contains("8448"));
    assert!(json.contains("10"));

    let deserialized: SRVData = serde_json::from_str(&json).expect("deserialization failed");
    assert_eq!(deserialized, srv);
}

#[test]
fn test_dnsresult_serialization() {
    let mut srv_targets = BTreeMap::new();
    srv_targets.insert(
        "_matrix._tcp.example.org".to_string(),
        vec![SRVData {
            target: "matrix.example.org".to_string(),
            srv_prefix: Some("_matrix._tcp".to_string()),
            addrs: vec!["192.168.1.1:8448".to_string()],
            error: None,
            port: 8448,
            priority: Some(10),
            weight: Some(0),
        }],
    );

    let dns_result = Dnsresult {
        srvskipped: false,
        srv_targets,
        addrs: vec!["192.168.1.1:8448".to_string(), "[::1]:8448".to_string()],
    };

    let json = serde_json::to_string(&dns_result).expect("serialization failed");
    assert!(json.contains("192.168.1.1:8448"));
    assert!(json.contains("matrix.example.org"));

    let deserialized: Dnsresult = serde_json::from_str(&json).expect("deserialization failed");
    assert_eq!(deserialized.addrs.len(), 2);
    assert!(!deserialized.srvskipped);
}

#[test]
fn test_connection_report_data_default() {
    let report = ConnectionReportData::default();
    assert!(report.error.is_none());
    assert!(report.certificates.is_empty());
    assert_eq!(report.version, Version::default());
    assert_eq!(report.checks, Checks::default());
    assert_eq!(report.cipher, Cipher::default());
    assert_eq!(report.keys, Keys::default()); // Keys is a struct, not an Option
}
