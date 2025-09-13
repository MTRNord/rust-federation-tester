use hyper::StatusCode;
use rust_federation_tester::error::{FederationError, FetchError, WellKnownError};
use std::time::Duration;

#[test]
fn test_well_known_error_display_and_debug() {
    // Test all WellKnownError variants for Display and Debug traits
    let timeout_err = WellKnownError::Timeout(Duration::from_secs(5));
    assert!(
        timeout_err
            .to_string()
            .contains("Timeout after 5s while fetching well-known")
    );
    assert!(format!("{:?}", timeout_err).contains("Timeout"));

    let http_err = WellKnownError::Http {
        status: StatusCode::NOT_FOUND,
        context: "Not found".to_string(),
    };
    assert!(http_err.to_string().contains("HTTP 404 Not Found"));
    assert!(http_err.to_string().contains("Not found"));

    let redirect_err = WellKnownError::RedirectLimit(10);
    assert!(
        redirect_err
            .to_string()
            .contains("Redirect loop or too many redirects (limit 10)")
    );

    let json_err = WellKnownError::InvalidJson("invalid syntax".to_string());
    assert!(
        json_err
            .to_string()
            .contains("Invalid JSON body: invalid syntax")
    );

    let no_addrs_err = WellKnownError::NoAddresses;
    assert!(no_addrs_err.to_string().contains("No A/AAAA records found"));

    let other_err = WellKnownError::Other("custom error".to_string());
    assert!(other_err.to_string().contains("Other error: custom error"));
}

#[test]
fn test_fetch_error_from_well_known() {
    // Test conversion from WellKnownError to FetchError
    let well_known_err = WellKnownError::NoAddresses;
    let fetch_err: FetchError = well_known_err.into();

    match fetch_err {
        FetchError::WellKnown(WellKnownError::NoAddresses) => {
            // Expected
        }
        _ => panic!("Unexpected FetchError variant"),
    }
}

#[test]
fn test_fetch_error_variants() {
    let tls_err = FetchError::Tls("certificate invalid".to_string());
    assert!(
        tls_err
            .to_string()
            .contains("TLS error: certificate invalid")
    );

    let timeout_err = FetchError::Timeout(Duration::from_millis(500));
    assert!(
        timeout_err
            .to_string()
            .contains("Network timeout after 500ms")
    );

    let network_err = FetchError::Network("connection refused".to_string());
    assert!(
        network_err
            .to_string()
            .contains("Network error: connection refused")
    );

    let http_err = FetchError::Http {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        context: "server error".to_string(),
    };
    assert!(http_err.to_string().contains("HTTP status 500"));

    let json_err = FetchError::Json("malformed".to_string());
    assert!(json_err.to_string().contains("JSON parse error: malformed"));

    let domain_err = FetchError::InvalidDomain("bad.domain".to_string());
    assert!(
        domain_err
            .to_string()
            .contains("Invalid domain: bad.domain")
    );

    let content_type_err = FetchError::UnexpectedContentType("text/html".to_string());
    assert!(
        content_type_err
            .to_string()
            .contains("Unexpected content type: text/html")
    );
}

#[test]
fn test_federation_error_variants() {
    let fetch_err = FetchError::Network("timeout".to_string());
    let fed_err: FederationError = fetch_err.into();
    assert!(fed_err.to_string().contains("Network error: timeout"));

    let dns_err = FederationError::Dns("NXDOMAIN".to_string());
    assert!(
        dns_err
            .to_string()
            .contains("DNS resolution failed: NXDOMAIN")
    );

    let ed25519_err = FederationError::Ed25519("ed25519:key1".to_string());
    assert!(
        ed25519_err
            .to_string()
            .contains("Ed25519 verification failed for key ed25519:key1")
    );

    let server_name_err = FederationError::InvalidServerName("".to_string());
    assert!(
        server_name_err
            .to_string()
            .contains("Invalid server name: ")
    );

    let internal_err = FederationError::Internal("panic occurred".to_string());
    assert!(
        internal_err
            .to_string()
            .contains("Internal error: panic occurred")
    );
}

#[test]
fn test_federation_error_is_retryable() {
    // Test retryable errors
    let timeout_fetch = FederationError::Fetch(FetchError::Timeout(Duration::from_secs(1)));
    assert!(timeout_fetch.is_retryable());

    let network_fetch = FederationError::Fetch(FetchError::Network("conn reset".to_string()));
    assert!(network_fetch.is_retryable());

    let dns_err = FederationError::Dns("temporary failure".to_string());
    assert!(dns_err.is_retryable());

    // Test non-retryable errors
    let tls_fetch = FederationError::Fetch(FetchError::Tls("cert expired".to_string()));
    assert!(!tls_fetch.is_retryable());

    let ed25519_err = FederationError::Ed25519("key1".to_string());
    assert!(!ed25519_err.is_retryable());

    let invalid_server = FederationError::InvalidServerName("bad".to_string());
    assert!(!invalid_server.is_retryable());

    let internal_err = FederationError::Internal("bug".to_string());
    assert!(!internal_err.is_retryable());
}

#[test]
fn test_error_chain_display() {
    // Test that error chains display properly
    let well_known = WellKnownError::InvalidJson("missing field".to_string());
    let fetch = FetchError::WellKnown(well_known);
    let federation = FederationError::Fetch(fetch);

    let error_msg = federation.to_string();
    assert!(error_msg.contains("Invalid JSON body: missing field"));
}
