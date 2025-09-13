use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rust_federation_tester::response::Certificate;
use rust_federation_tester::response::Root;
use rust_federation_tester::utils::{absolutize_srv_target, extract_certificate_info};
use rust_federation_tester::validation::server_name::parse_and_validate_server_name;

#[test]
fn test_absolutize_srv_target_basic() {
    assert_eq!(
        absolutize_srv_target("matrix", "example.org"),
        "matrix.example.org."
    );
    assert_eq!(absolutize_srv_target("matrix.", "example.org"), "matrix.");
    assert_eq!(
        absolutize_srv_target("_matrix._tcp", "example.org"),
        "_matrix._tcp.example.org."
    );
}

#[test]
fn test_absolutize_srv_target_idempotent() {
    let first = absolutize_srv_target("srv", "example.com.");
    // Calling again with an already absolute (trailing dot) target should be a no-op
    let second = absolutize_srv_target(&first, "example.com.");
    assert_eq!(
        second, first,
        "absolutize_srv_target should be idempotent when input already ends with '.'"
    );
}

#[test]
fn test_server_name_validation_edge_cases() {
    let mut data = Root::default();
    // Max length close to 255 (compose a long but valid label chain)
    let long_label = "a".repeat(60);
    let server = format!("{0}.{0}.{0}.example", long_label);
    parse_and_validate_server_name(&mut data, &server);
    // Might still be valid unless >255 total length; this just ensures it doesn't erroneously reject mid-size
    assert!(data.error.is_none(), "Unexpected error: {:?}", data.error);

    // Uppercase should be allowed per DNS case-insensitivity
    data = Root::default();
    parse_and_validate_server_name(&mut data, "MATRIX.ORG");
    assert!(data.error.is_none());

    // Invalid character
    data = Root::default();
    parse_and_validate_server_name(&mut data, "bad_domain!org");
    assert!(data.error.is_some());

    // IP literal
    data = Root::default();
    parse_and_validate_server_name(&mut data, "192.168.1.10");
    assert!(data.error.is_none());
}

#[test]
fn test_extract_certificate_info_self_signed() {
    // Build a self-signed cert with SANs
    let mut params = CertificateParams::new(vec![
        "example.org".to_string(),
        "alt.example.org".to_string(),
    ])
    .expect("params");
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "example.org");
    params.distinguished_name = dn;

    // Generate a fresh key pair and create a self-signed certificate
    let key_pair = KeyPair::generate().expect("key generation");
    let cert = params.self_signed(&key_pair).expect("self-signed cert");
    let der = cert.der().to_vec();
    let der_wrapped = rustls_pki_types::CertificateDer::from(der);

    let info: Certificate = extract_certificate_info(&der_wrapped).expect("certificate parsed");
    assert_eq!(info.subject_common_name, "example.org");
    // Issuer = subject for self-signed
    assert_eq!(info.issuer_common_name, "example.org");
    let dns = info.dnsnames.clone().unwrap();
    assert!(dns.contains(&"example.org".to_string()));
    assert!(dns.contains(&"alt.example.org".to_string()));
    assert!(!info.sha256fingerprint.is_empty());
}
