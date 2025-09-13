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

    #[tokio::test]
    async fn test_generate_json_report_ipv4_only_server() {
        install_crypto_provider_once();
        let resolver = Resolver::builder_tokio().unwrap().build();
        let pool = test_connection_pool();
        // Test unredacted.org which is IPv4-only and should pass federation
        // despite AAAA lookup failures (regression test)
        let result = generate_json_report("unredacted.org", &resolver, &pool)
            .await
            .unwrap();

        // Should pass federation check despite AAAA lookup failures
        assert!(
            result.federation_ok,
            "IPv4-only server should pass federation check"
        );
        assert!(
            result.error.is_none(),
            "No error should be reported for IPv4-only server"
        );
        assert!(
            !result.dnsresult.addrs.is_empty(),
            "Should find IPv4 addresses"
        );

        // Verify we found at least one IPv4 address (format: "ip:port" without brackets)
        let has_ipv4_addr = result.dnsresult.addrs.iter().any(|addr| {
            // IPv4 addresses are formatted as "ip:port" (no brackets)
            // IPv6 addresses are formatted as "[ip]:port" (with brackets)
            !addr.starts_with('[') && addr.contains(':')
        });
        assert!(
            has_ipv4_addr,
            "Should find at least one IPv4 address for unredacted.org"
        );
    }

    #[tokio::test]
    async fn test_generate_json_report_known_good_servers() {
        install_crypto_provider_once();
        let resolver = Resolver::builder_tokio().unwrap().build();
        let pool = test_connection_pool();
        let servers = [
            "matrix.org",
            "maunium.net",
            "mtrnord.blog",
            "2.s.resolvematrix.dev:7652",
            "3b.s.resolvematrix.dev",
            "3c.msc4040.s.resolvematrix.dev",
            "3d.s.resolvematrix.dev",
            "4.s.resolvematrix.dev",
            "4.msc4040.s.resolvematrix.dev",
            "5.s.resolvematrix.dev",
            "rory.gay",
            "draupnir.midnightthoughts.space",
            "continuwuity.codestorm.net",
            "continuwuity.org",
        ];
        for server in servers {
            let result = generate_json_report(server, &resolver, &pool)
                .await
                .unwrap();
            assert!(
                result.federation_ok,
                "Federation should succeed for {} (error: {:?})",
                server, result.error
            );
            assert!(
                !result.dnsresult.addrs.is_empty(),
                "Should find at least one address for {}",
                server
            );
        }
    }

    #[tokio::test]
    async fn test_generate_json_report_known_bad_servers() {
        install_crypto_provider_once();
        let resolver = Resolver::builder_tokio().unwrap().build();
        let pool = test_connection_pool();

        // Servers known to have specific federation issues
        let bad_servers = [
            "timedout.uk", // Sends invalid error response on version endpoint
            "example.com", // Does not run Matrix server
        ];

        for server in bad_servers {
            let result = generate_json_report(server, &resolver, &pool)
                .await
                .unwrap();

            assert!(
                !result.federation_ok,
                "Federation should fail for {} due to known issues",
                server
            );
            assert!(
                !result.dnsresult.addrs.is_empty(),
                "Should find addresses for {} (DNS should work)",
                server
            );

            // Check that we have connection reports but they show failures
            if !result.connection_reports.is_empty() {
                let connection_report = result.connection_reports.values().next().unwrap();
                assert!(
                    !connection_report.checks.all_checks_ok,
                    "AllChecksOK should be false for known bad server {}",
                    server
                );

                // For timedout.uk specifically, check server version parsing failure
                if server == "timedout.uk" {
                    assert!(
                        !connection_report.checks.server_version_parses,
                        "ServerVersionParses should be false for timedout.uk"
                    );
                }
            }
        }
    }
}
