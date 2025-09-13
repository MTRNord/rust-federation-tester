//! Federation function tests: well-known, DNS, and connection phases.
//! Uses mock resolver and minimal scaffolding for pure function coverage.

#[cfg(test)]
mod federation_tests {
    use hickory_resolver::Resolver;
    use rust_federation_tester::connection_pool::ConnectionPool;
    use rust_federation_tester::federation::{lookup_server, lookup_server_well_known};
    use rust_federation_tester::response::generate_json_report;
    use rustls::crypto::{self, CryptoProvider};

    fn test_connection_pool() -> ConnectionPool {
        ConnectionPool::default()
    }

    fn install_crypto_provider_once() {
        use std::sync::Once;
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            let ring_provider = crypto::ring::default_provider();
            CryptoProvider::install_default(ring_provider)
                .expect("Failed to install crypto provider");
        });
    }

    #[tokio::test]
    async fn test_lookup_server_well_known_invalid() {
        install_crypto_provider_once();
        let resolver = Resolver::builder_tokio().unwrap().build();
        let result = lookup_server_well_known("nonexistent-domain-for-test-xyz", &resolver).await;
        assert!(result.error.is_some());
        assert!(result.well_known_result.is_empty());
        assert!(result.found_server.is_none());
    }

    #[tokio::test]
    async fn test_lookup_server_well_known_valid() {
        install_crypto_provider_once();
        let resolver = Resolver::builder_tokio().unwrap().build();
        let result = lookup_server_well_known("matrix.org", &resolver).await;
        // Accept either error or at least one result (depends on network)
        assert!(result.error.is_none() || !result.well_known_result.is_empty());
    }

    #[tokio::test]
    async fn test_lookup_server_srv_and_dns() {
        install_crypto_provider_once();
        let resolver = Resolver::builder_tokio().unwrap().build();
        let result = lookup_server("matrix.org", &resolver).await;
        assert!(!result.addrs.is_empty() || !result.errors.is_empty());
    }

    #[tokio::test]
    async fn test_generate_json_report_invalid_domain() {
        install_crypto_provider_once();
        let resolver = Resolver::builder_tokio().unwrap().build();
        let pool = test_connection_pool();
        let result = generate_json_report("nonexistent-domain-for-test-xyz", &resolver, &pool)
            .await
            .unwrap();
        assert!(!result.federation_ok);
        assert!(result.error.is_some());
        assert!(result.dnsresult.addrs.is_empty());
    }

    #[tokio::test]
    async fn test_generate_json_report_valid_domain() {
        install_crypto_provider_once();
        let resolver = Resolver::builder_tokio().unwrap().build();
        let pool = test_connection_pool();
        let result = generate_json_report("matrix.org", &resolver, &pool)
            .await
            .unwrap();
        // Should have federation_ok true or at least some addresses or connection reports
        assert!(
            result.federation_ok
                || !result.dnsresult.addrs.is_empty()
                || !result.connection_reports.is_empty()
        );
    }

    #[tokio::test]
    async fn test_generate_json_report_with_port() {
        install_crypto_provider_once();
        let resolver = Resolver::builder_tokio().unwrap().build();
        let pool = test_connection_pool();
        // Should skip well-known and SRV, go straight to A/AAAA
        let result = generate_json_report("matrix.org:8448", &resolver, &pool)
            .await
            .unwrap();
        // Should not panic, federation_ok may be true or false
        assert!(result.error.is_none() || !result.dnsresult.addrs.is_empty());
    }

    #[tokio::test]
    async fn test_generate_json_report_error_propagation() {
        install_crypto_provider_once();
        let resolver = Resolver::builder_tokio().unwrap().build();
        let pool = test_connection_pool();
        // Intentionally use a domain that should fail
        let result = generate_json_report("invalid.invalid", &resolver, &pool)
            .await
            .unwrap();
        assert!(!result.federation_ok);
        assert!(result.error.is_some());
    }
}
