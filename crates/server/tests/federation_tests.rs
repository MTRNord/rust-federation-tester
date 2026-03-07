//! Federation function tests: well-known, DNS, and connection phases.
//! Uses mock resolver and minimal scaffolding for pure function coverage.

#[cfg(test)]
mod federation_tests {
    use hickory_resolver::Resolver;
    use hickory_resolver::config::ResolverConfig;
    use hickory_resolver::name_server::TokioConnectionProvider;
    use rust_federation_tester::connection_pool::ConnectionPool;
    use rust_federation_tester::federation::{lookup_server, lookup_server_well_known};
    use rust_federation_tester::response::generate_json_report;
    use rustls::crypto::{self, CryptoProvider};

    fn test_connection_pool() -> ConnectionPool {
        ConnectionPool::default()
    }

    /// Build a resolver that uses Google DNS (8.8.8.8 / 8.8.4.4) for reliable test resolution.
    /// Using the system resolver (/etc/resolv.conf) often causes intermittent timeouts in tests
    /// because the local resolver is too slow or rate-limits concurrent queries.
    fn test_resolver() -> Resolver<TokioConnectionProvider> {
        Resolver::builder_with_config(ResolverConfig::google(), TokioConnectionProvider::default())
            .build()
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
        let resolver = test_resolver();
        let result = lookup_server_well_known("nonexistent-domain-for-test-xyz", &resolver).await;
        assert!(result.error.is_some());
        assert!(result.well_known_result.is_empty());
        assert!(result.found_server.is_none());
    }

    #[tokio::test]
    async fn test_lookup_server_well_known_valid() {
        install_crypto_provider_once();
        let resolver = test_resolver();
        let result = lookup_server_well_known("matrix.org", &resolver).await;
        // Accept either error or at least one result (depends on network)
        assert!(result.error.is_none() || !result.well_known_result.is_empty());
    }

    #[tokio::test]
    async fn test_lookup_server_srv_and_dns() {
        install_crypto_provider_once();
        let resolver = test_resolver();
        let result = lookup_server("matrix.org", &resolver).await;
        assert!(!result.addrs.is_empty() || !result.errors.is_empty());
    }

    #[tokio::test]
    async fn test_generate_json_report_invalid_domain() {
        install_crypto_provider_once();
        let resolver = test_resolver();
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
        let resolver = test_resolver();
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
        let resolver = test_resolver();
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
        let resolver = test_resolver();
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
        let resolver = test_resolver();
        let pool = test_connection_pool();
        // Test unredacted.org which is IPv4-only and should pass federation
        // despite AAAA lookup failures (regression test)
        let result = generate_json_report("unredacted.org", &resolver, &pool)
            .await
            .unwrap();

        // The key regression: IPv4 addresses must be resolved even when AAAA times out.
        // We do NOT assert federation_ok — that depends on the live server's health,
        // which is outside our control and makes the test flaky in CI.
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
        let pool = test_connection_pool();
        let servers = [
            "matrix.org",
            "maunium.net",
            "mtrnord.blog",
            "2.s.resolvematrix.dev:7652",
            "3b.s.resolvematrix.dev",
            "3c.s.resolvematrix.dev",
            "3c.msc4040.s.resolvematrix.dev",
            "3d.s.resolvematrix.dev",
            "4.s.resolvematrix.dev",
            "4.msc4040.s.resolvematrix.dev",
            "5.s.resolvematrix.dev",
            "rory.gay",
            "draupnir.midnightthoughts.space",
            "continuwuity.codestorm.net",
            "continuwuity.org",
            "159.89.115.225", // IP literal regression test
        ];
        let is_github_actions =
            std::env::var("CI").is_ok() && std::env::var("GITHUB_RUN_ID").is_ok();
        for server in servers {
            // Use a fresh resolver per server to avoid exhausting the DNS query queue
            // when many servers are tested sequentially.
            let resolver = test_resolver();
            let result = generate_json_report(server, &resolver, &pool)
                .await
                .unwrap();

            let (federation_ok_for_test, _filtered_connection_errors) = if is_github_actions {
                // Filter out IPv6 os error 101 (network unreachable) connection errors for GitHub Actions only
                let filtered: std::collections::BTreeMap<_, _> = result
                    .connection_errors
                    .iter()
                    .filter(|(addr, err)| {
                        // Only filter IPv6 addresses with os error 101
                        if addr.starts_with('[') {
                            if err.error.to_lowercase().contains("os error 101") {
                                return false; // ignore this error in test
                            }
                            if err.error.to_lowercase().contains("network is unreachable") {
                                return false; // ignore this error in test
                            }
                        }
                        true
                    })
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                let ok = result.federation_ok
                    || (!result.connection_reports.is_empty() && filtered.is_empty());
                (ok, filtered)
            } else {
                (result.federation_ok, result.connection_errors.clone())
            };

            if !federation_ok_for_test || result.dnsresult.addrs.is_empty() {
                println!("FAILED KNOWN GOOD SERVER: {}", server);
                println!("  FederationOK: {}", result.federation_ok);
                println!("  Error: {:?}", result.error);
                println!("  DNS Addresses: {:?}", result.dnsresult.addrs);
                println!("  Connection Reports: {}", result.connection_reports.len());
                for (addr, report) in &result.connection_reports {
                    println!(
                        "    {}: AllChecksOK={}, Error={:?}",
                        addr, report.checks.all_checks_ok, report.error
                    );
                }
                println!("  Connection Errors: {:?}", result.connection_errors);
            }

            assert!(
                federation_ok_for_test,
                "Federation should succeed for {}{} - see printed details above",
                server,
                if is_github_actions {
                    " (ignoring IPv6 unreachable errors on GitHub Actions)"
                } else {
                    ""
                }
            );
            assert!(
                !result.dnsresult.addrs.is_empty(),
                "Should find at least one address for {} - see printed details above",
                server
            );
        }
    }

    // ── SRV resolution regression tests ───────────────────────────────────────

    /// Verify that a server documented to use _matrix-fed._tcp SRV is resolved
    /// to the correct SRV target and port, not port 8448.
    /// 4.msc4040.s.resolvematrix.dev → _matrix-fed._tcp → srv.4.msc4040.s.resolvematrix.dev:7054
    #[tokio::test]
    async fn test_matrix_fed_srv_resolution_4msc4040() {
        install_crypto_provider_once();
        let resolver = test_resolver();
        let pool = test_connection_pool();

        let result = generate_json_report("4.msc4040.s.resolvematrix.dev", &resolver, &pool)
            .await
            .unwrap();

        // Must have resolved addresses at all
        assert!(
            !result.dnsresult.addrs.is_empty(),
            "Expected addresses for 4.msc4040.s.resolvematrix.dev, got none. DNS result: {:?}",
            result.dnsresult
        );

        // All connection addresses must use port 7054 (from SRV), not 8448
        for addr in &result.dnsresult.addrs {
            assert!(
                addr.ends_with(":7054"),
                "Expected port 7054 from _matrix-fed._tcp SRV, got address: {addr}"
            );
        }

        // The SRV target must be srv.4.msc4040.s.resolvematrix.dev (with trailing dot)
        let srv_target_found = result.dnsresult.srv_targets.keys().any(|k| {
            k.to_lowercase()
                .contains("srv.4.msc4040.s.resolvematrix.dev")
        });
        assert!(
            srv_target_found,
            "Expected SRV target srv.4.msc4040.s.resolvematrix.dev, got targets: {:?}",
            result.dnsresult.srv_targets.keys().collect::<Vec<_>>()
        );

        // Verify the SRV entry uses the _matrix-fed._tcp prefix
        let used_matrix_fed = result.dnsresult.srv_targets.values().flatten().any(|srv| {
            srv.srv_prefix
                .as_deref()
                .is_some_and(|p| p == "_matrix-fed._tcp")
        });
        assert!(
            used_matrix_fed,
            "Expected _matrix-fed._tcp SRV prefix, found: {:?}",
            result
                .dnsresult
                .srv_targets
                .values()
                .flatten()
                .map(|s| &s.srv_prefix)
                .collect::<Vec<_>>()
        );

        assert!(
            result.federation_ok,
            "Federation should be OK for 4.msc4040.s.resolvematrix.dev. Error: {:?}",
            result.error
        );
    }

    /// Verify that 4.s.resolvematrix.dev resolves via _matrix._tcp SRV to port 7855.
    #[tokio::test]
    async fn test_matrix_srv_resolution_4s() {
        install_crypto_provider_once();
        let resolver = test_resolver();
        let pool = test_connection_pool();

        let result = generate_json_report("4.s.resolvematrix.dev", &resolver, &pool)
            .await
            .unwrap();

        assert!(
            !result.dnsresult.addrs.is_empty(),
            "Expected addresses for 4.s.resolvematrix.dev, got none"
        );

        for addr in &result.dnsresult.addrs {
            assert!(
                addr.ends_with(":7855"),
                "Expected port 7855 from _matrix._tcp SRV, got address: {addr}"
            );
        }

        // Verify the SRV entry uses the _matrix._tcp prefix (not _matrix-fed._tcp)
        let used_matrix = result.dnsresult.srv_targets.values().flatten().any(|srv| {
            srv.srv_prefix
                .as_deref()
                .is_some_and(|p| p == "_matrix._tcp")
        });
        assert!(
            used_matrix,
            "Expected _matrix._tcp SRV prefix, found: {:?}",
            result
                .dnsresult
                .srv_targets
                .values()
                .flatten()
                .map(|s| &s.srv_prefix)
                .collect::<Vec<_>>()
        );

        assert!(
            result.federation_ok,
            "Federation should be OK for 4.s.resolvematrix.dev. Error: {:?}",
            result.error
        );
    }

    // ── Spec resolution step tests (resolvematrix.dev) ────────────────────────
    //
    // Each server below exercises a specific step of the Matrix server name
    // resolution algorithm.  Reference: https://spec.matrix.org (§ Server discovery)
    //
    // Step 2  – 2.s.resolvematrix.dev:7652   explicit port → A/AAAA, SRV skipped
    // Step 3b – 3b.s.resolvematrix.dev       well-known → delegated host:7753
    // Step 3c – 3c.s.resolvematrix.dev       well-known → host → _matrix._tcp SRV → :7754
    // Step 3c* – 3c.msc4040.s.resolvematrix  well-known → host → _matrix-fed._tcp SRV → :7053
    // Step 3d – 3d.s.resolvematrix.dev       well-known → host → no SRV → :8448
    // Step 6  – 5.s.resolvematrix.dev        well-known fails → no SRV → :8448

    /// Step 2: explicit port in server name → skip well-known and SRV, A/AAAA at that port.
    #[tokio::test]
    async fn test_step2_explicit_port() {
        install_crypto_provider_once();
        let resolver = test_resolver();
        let pool = test_connection_pool();

        let result = generate_json_report("2.s.resolvematrix.dev:7652", &resolver, &pool)
            .await
            .unwrap();

        // Well-known must be skipped (explicit port → step 2)
        assert!(
            result.well_known_result.is_empty(),
            "Well-known must be skipped for server with explicit port, got: {:?}",
            result.well_known_result
        );

        // SRV must be skipped
        assert!(
            result.dnsresult.srvskipped,
            "SRV must be skipped for server with explicit port"
        );

        // All addresses must use port 7652
        assert!(
            !result.dnsresult.addrs.is_empty(),
            "Expected addresses for 2.s.resolvematrix.dev:7652"
        );
        for addr in &result.dnsresult.addrs {
            assert!(
                addr.ends_with(":7652"),
                "Expected port 7652, got address: {addr}"
            );
        }

        assert!(
            result.federation_ok,
            "Federation should be OK. Error: {:?}",
            result.error
        );
    }

    /// Step 3b: well-known returns a delegated hostname with explicit port → skip SRV on delegated.
    #[tokio::test]
    async fn test_step3b_wellknown_explicit_port() {
        install_crypto_provider_once();
        let resolver = test_resolver();
        let pool = test_connection_pool();

        let result = generate_json_report("3b.s.resolvematrix.dev", &resolver, &pool)
            .await
            .unwrap();

        // Well-known must have succeeded with a delegated server containing port 7753
        let wk_values: Vec<_> = result.well_known_result.values().collect();
        let delegated_with_port = wk_values
            .iter()
            .any(|wk| wk.error.is_none() && wk.m_server.contains(":7753"));
        assert!(
            delegated_with_port,
            "Expected well-known to return a server with port 7753, got: {:?}",
            result.well_known_result
        );

        // All addresses must use port 7753
        assert!(
            !result.dnsresult.addrs.is_empty(),
            "Expected addresses for 3b.s.resolvematrix.dev"
        );
        for addr in &result.dnsresult.addrs {
            assert!(
                addr.ends_with(":7753"),
                "Expected port 7753 from well-known delegated host, got address: {addr}"
            );
        }

        assert!(
            result.federation_ok,
            "Federation should be OK. Error: {:?}",
            result.error
        );
    }

    /// Step 3c (classic): well-known → delegated hostname without port → _matrix._tcp SRV → port 7754.
    #[tokio::test]
    async fn test_step3c_wellknown_matrix_srv() {
        install_crypto_provider_once();
        let resolver = test_resolver();
        let pool = test_connection_pool();

        let result = generate_json_report("3c.s.resolvematrix.dev", &resolver, &pool)
            .await
            .unwrap();

        // Well-known must have succeeded with wk.3c.s.resolvematrix.dev (no port)
        let wk_values: Vec<_> = result.well_known_result.values().collect();
        let delegated_no_port = wk_values.iter().any(|wk| {
            wk.error.is_none()
                && wk.m_server.contains("wk.3c.s.resolvematrix.dev")
                && !wk.m_server.contains(':')
        });
        assert!(
            delegated_no_port,
            "Expected well-known to return wk.3c.s.resolvematrix.dev (no port), got: {:?}",
            result.well_known_result
        );

        // All addresses must use port 7754 from the _matrix._tcp SRV
        assert!(
            !result.dnsresult.addrs.is_empty(),
            "Expected addresses for 3c.s.resolvematrix.dev"
        );
        for addr in &result.dnsresult.addrs {
            assert!(
                addr.ends_with(":7754"),
                "Expected port 7754 from _matrix._tcp SRV on delegated host, got: {addr}"
            );
        }

        // _matrix._tcp SRV prefix must have been used (on the delegated host)
        let used_matrix = result.dnsresult.srv_targets.values().flatten().any(|srv| {
            srv.srv_prefix
                .as_deref()
                .is_some_and(|p| p == "_matrix._tcp")
        });
        assert!(
            used_matrix,
            "Expected _matrix._tcp SRV prefix on delegated host, found: {:?}",
            result
                .dnsresult
                .srv_targets
                .values()
                .flatten()
                .map(|s| &s.srv_prefix)
                .collect::<Vec<_>>()
        );

        assert!(
            result.federation_ok,
            "Federation should be OK. Error: {:?}",
            result.error
        );
    }

    /// Step 3c (msc4040): well-known → delegated hostname without port → _matrix-fed._tcp SRV → port 7053.
    #[tokio::test]
    async fn test_step3c_wellknown_matrix_fed_srv() {
        install_crypto_provider_once();
        let resolver = test_resolver();
        let pool = test_connection_pool();

        let result = generate_json_report("3c.msc4040.s.resolvematrix.dev", &resolver, &pool)
            .await
            .unwrap();

        // Well-known must have succeeded with wk.3c.msc4040.s.resolvematrix.dev (no port)
        let wk_values: Vec<_> = result.well_known_result.values().collect();
        let delegated_no_port = wk_values.iter().any(|wk| {
            wk.error.is_none()
                && wk.m_server.contains("wk.3c.msc4040.s.resolvematrix.dev")
                && !wk.m_server.contains(':')
        });
        assert!(
            delegated_no_port,
            "Expected well-known to return wk.3c.msc4040.s.resolvematrix.dev (no port), got: {:?}",
            result.well_known_result
        );

        // All addresses must use port 7053 from the _matrix-fed._tcp SRV
        assert!(
            !result.dnsresult.addrs.is_empty(),
            "Expected addresses for 3c.msc4040.s.resolvematrix.dev"
        );
        for addr in &result.dnsresult.addrs {
            assert!(
                addr.ends_with(":7053"),
                "Expected port 7053 from _matrix-fed._tcp SRV on delegated host, got: {addr}"
            );
        }

        // _matrix-fed._tcp SRV prefix must have been used
        let used_matrix_fed = result.dnsresult.srv_targets.values().flatten().any(|srv| {
            srv.srv_prefix
                .as_deref()
                .is_some_and(|p| p == "_matrix-fed._tcp")
        });
        assert!(
            used_matrix_fed,
            "Expected _matrix-fed._tcp SRV prefix on delegated host, found: {:?}",
            result
                .dnsresult
                .srv_targets
                .values()
                .flatten()
                .map(|s| &s.srv_prefix)
                .collect::<Vec<_>>()
        );

        assert!(
            result.federation_ok,
            "Federation should be OK. Error: {:?}",
            result.error
        );
    }

    /// Step 3d: well-known → delegated hostname without port, no SRV → A/AAAA at port 8448.
    #[tokio::test]
    async fn test_step3d_wellknown_default_port() {
        install_crypto_provider_once();
        let resolver = test_resolver();
        let pool = test_connection_pool();

        let result = generate_json_report("3d.s.resolvematrix.dev", &resolver, &pool)
            .await
            .unwrap();

        // Well-known must have succeeded with wk.3d.s.resolvematrix.dev (no port)
        let wk_values: Vec<_> = result.well_known_result.values().collect();
        let delegated_no_port = wk_values.iter().any(|wk| {
            wk.error.is_none()
                && wk.m_server.contains("wk.3d.s.resolvematrix.dev")
                && !wk.m_server.contains(':')
        });
        assert!(
            delegated_no_port,
            "Expected well-known to return wk.3d.s.resolvematrix.dev (no port), got: {:?}",
            result.well_known_result
        );

        // All addresses must use port 8448 (fallback since delegated host has no SRV)
        assert!(
            !result.dnsresult.addrs.is_empty(),
            "Expected addresses for 3d.s.resolvematrix.dev"
        );
        for addr in &result.dnsresult.addrs {
            assert!(
                addr.ends_with(":8448"),
                "Expected port 8448 (no SRV on delegated host), got: {addr}"
            );
        }

        assert!(
            result.federation_ok,
            "Federation should be OK. Error: {:?}",
            result.error
        );
    }

    /// Step 6: well-known fails (returns non-JSON), no SRV → A/AAAA at port 8448.
    #[tokio::test]
    async fn test_step6_wellknown_fails_default_port() {
        install_crypto_provider_once();
        let resolver = test_resolver();
        let pool = test_connection_pool();

        let result = generate_json_report("5.s.resolvematrix.dev", &resolver, &pool)
            .await
            .unwrap();

        // Well-known must have been attempted but failed (errors present or no m.server)
        let wk_any_success = result
            .well_known_result
            .values()
            .any(|wk| wk.error.is_none() && !wk.m_server.is_empty());
        assert!(
            !wk_any_success,
            "Well-known should have failed for 5.s.resolvematrix.dev, but got a success: {:?}",
            result.well_known_result
        );

        // All addresses must use port 8448
        assert!(
            !result.dnsresult.addrs.is_empty(),
            "Expected addresses for 5.s.resolvematrix.dev"
        );
        for addr in &result.dnsresult.addrs {
            assert!(
                addr.ends_with(":8448"),
                "Expected port 8448 (well-known failed, no SRV), got: {addr}"
            );
        }

        assert!(
            result.federation_ok,
            "Federation should be OK. Error: {:?}",
            result.error
        );
    }

    // ── IP literal regression tests ────────────────────────────────────────────

    #[tokio::test]
    async fn test_lookup_server_well_known_skips_ipv4_literal() {
        install_crypto_provider_once();
        let resolver = test_resolver();
        // Well-known must be skipped for IP literals (spec step 1)
        let result = lookup_server_well_known("159.89.115.225", &resolver).await;
        assert!(
            result.error.is_none(),
            "IP literal must not produce a well-known error: {:?}",
            result.error
        );
        assert!(
            result.well_known_result.is_empty(),
            "IP literal well-known result should be empty"
        );
        assert!(result.found_server.is_none());
        assert!(result.per_ip_found_server.is_empty());
    }

    #[tokio::test]
    async fn test_lookup_server_well_known_skips_ipv4_literal_with_port() {
        install_crypto_provider_once();
        let resolver = test_resolver();
        let result = lookup_server_well_known("159.89.115.225:8448", &resolver).await;
        assert!(result.error.is_none());
        assert!(result.well_known_result.is_empty());
    }

    #[tokio::test]
    async fn test_lookup_server_well_known_skips_ipv6_literal() {
        install_crypto_provider_once();
        let resolver = test_resolver();
        let result = lookup_server_well_known("[::1]", &resolver).await;
        assert!(result.error.is_none());
        assert!(result.well_known_result.is_empty());
    }

    #[tokio::test]
    async fn test_lookup_server_dns_ipv4_literal_no_port() {
        install_crypto_provider_once();
        let resolver = test_resolver();
        // DNS phase must return the IP directly at port 8448 without doing any DNS lookup
        let result = lookup_server("159.89.115.225", &resolver).await;
        assert!(
            result.errors.is_empty(),
            "IP literal must not produce DNS errors: {:?}",
            result.errors
        );
        assert!(result.srvskipped, "SRV should be skipped for IP literals");
        assert_eq!(
            result.addrs,
            vec!["159.89.115.225:8448"],
            "Should directly use IP:8448 without DNS"
        );
        assert!(
            result.srv_targets.is_empty(),
            "No SRV targets should be created for IP literals"
        );
    }

    #[tokio::test]
    async fn test_lookup_server_dns_ipv4_literal_with_port() {
        install_crypto_provider_once();
        let resolver = test_resolver();
        let result = lookup_server("159.89.115.225:8448", &resolver).await;
        assert!(
            result.errors.is_empty(),
            "Should not error: {:?}",
            result.errors
        );
        assert!(result.srvskipped);
        assert_eq!(result.addrs, vec!["159.89.115.225:8448"]);
    }

    #[tokio::test]
    async fn test_lookup_server_dns_ipv6_literal_no_port() {
        install_crypto_provider_once();
        let resolver = test_resolver();
        let result = lookup_server("[::1]", &resolver).await;
        assert!(
            result.errors.is_empty(),
            "Should not error: {:?}",
            result.errors
        );
        assert!(result.srvskipped);
        assert_eq!(result.addrs, vec!["[::1]:8448"]);
    }

    #[tokio::test]
    async fn test_lookup_server_dns_ipv6_literal_with_port() {
        install_crypto_provider_once();
        let resolver = test_resolver();
        let result = lookup_server("[::1]:8448", &resolver).await;
        assert!(
            result.errors.is_empty(),
            "Should not error: {:?}",
            result.errors
        );
        assert!(result.srvskipped);
        assert_eq!(result.addrs, vec!["[::1]:8448"]);
    }

    #[tokio::test]
    async fn test_generate_json_report_ipv4_literal_dns_resolves() {
        // Regression test for 159.89.115.225: the backend must not fail with a DNS
        // lookup error when an IP literal is submitted.
        install_crypto_provider_once();
        let resolver = test_resolver();
        let pool = test_connection_pool();
        let result = generate_json_report("159.89.115.225", &resolver, &pool)
            .await
            .unwrap();

        // The DNS phase must succeed and return the IP address directly.
        assert!(
            !result.dnsresult.addrs.is_empty(),
            "IP literal should produce a DNS addr without doing a DNS lookup"
        );
        assert_eq!(
            result.dnsresult.addrs,
            vec!["159.89.115.225:8448"],
            "Should use IP:8448 directly"
        );
        assert!(
            result.dnsresult.srvskipped,
            "SRV should be skipped for IP literals"
        );
        // The error must NOT be a DNS lookup error (it may fail at TLS/keys level,
        // but not at the DNS resolution phase).
        if let Some(err) = &result.error {
            assert!(
                !err.error.contains("A record lookup error"),
                "Should not have DNS A-record lookup error for IP literal, got: {}",
                err.error
            );
            assert!(
                !err.error.contains("AAAA record lookup error"),
                "Should not have DNS AAAA-record lookup error for IP literal, got: {}",
                err.error
            );
        }
        // Well-known must have been skipped
        assert!(
            result.well_known_result.is_empty(),
            "Well-known must be skipped for IP literals"
        );
    }

    #[tokio::test]
    async fn test_generate_json_report_ipv4_literal_with_port_dns_resolves() {
        install_crypto_provider_once();
        let resolver = test_resolver();
        let pool = test_connection_pool();
        let result = generate_json_report("159.89.115.225:8448", &resolver, &pool)
            .await
            .unwrap();

        assert!(
            !result.dnsresult.addrs.is_empty(),
            "IP literal with port should resolve directly"
        );
        assert_eq!(result.dnsresult.addrs, vec!["159.89.115.225:8448"]);
        if let Some(err) = &result.error {
            assert!(
                !err.error.contains("record lookup error"),
                "Should not have DNS lookup error for IP literal, got: {}",
                err.error
            );
        }
    }

    // ── Validation regression tests ────────────────────────────────────────────

    #[test]
    fn test_validate_ipv4_literal() {
        use rust_federation_tester::response::Root;
        use rust_federation_tester::validation::server_name::parse_and_validate_server_name;
        let mut root = Root::default();
        parse_and_validate_server_name(&mut root, "159.89.115.225");
        assert!(root.error.is_none(), "IPv4 literal should be valid");
    }

    #[test]
    fn test_validate_ipv4_literal_with_port() {
        use rust_federation_tester::response::Root;
        use rust_federation_tester::validation::server_name::parse_and_validate_server_name;
        let mut root = Root::default();
        parse_and_validate_server_name(&mut root, "159.89.115.225:8448");
        assert!(
            root.error.is_none(),
            "IPv4 literal with port should be valid"
        );
    }

    #[test]
    fn test_validate_ipv6_literal_with_brackets() {
        use rust_federation_tester::response::Root;
        use rust_federation_tester::validation::server_name::parse_and_validate_server_name;
        let mut root = Root::default();
        parse_and_validate_server_name(&mut root, "[::1]");
        assert!(
            root.error.is_none(),
            "IPv6 literal in brackets should be valid"
        );
    }

    #[test]
    fn test_validate_ipv6_literal_with_brackets_and_port() {
        use rust_federation_tester::response::Root;
        use rust_federation_tester::validation::server_name::parse_and_validate_server_name;
        let mut root = Root::default();
        parse_and_validate_server_name(&mut root, "[::1]:8448");
        assert!(
            root.error.is_none(),
            "IPv6 literal with port should be valid"
        );
    }

    #[test]
    fn test_validate_ipv6_literal_missing_closing_bracket() {
        use rust_federation_tester::response::Root;
        use rust_federation_tester::validation::server_name::parse_and_validate_server_name;
        let mut root = Root::default();
        parse_and_validate_server_name(&mut root, "[::1");
        assert!(
            root.error.is_some(),
            "IPv6 literal missing closing bracket should be invalid"
        );
    }

    #[tokio::test]
    async fn test_generate_json_report_known_bad_servers() {
        install_crypto_provider_once();
        let resolver = test_resolver();
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

            if result.federation_ok || result.dnsresult.addrs.is_empty() {
                println!("UNEXPECTED KNOWN BAD SERVER RESULT: {}", server);
                println!("  FederationOK: {} (expected: false)", result.federation_ok);
                println!("  Error: {:?}", result.error);
                println!("  DNS Addresses: {:?}", result.dnsresult.addrs);
                println!("  Connection Reports: {}", result.connection_reports.len());
                for (addr, report) in &result.connection_reports {
                    println!(
                        "    {}: AllChecksOK={}, ServerVersionParses={}, Error={:?}",
                        addr,
                        report.checks.all_checks_ok,
                        report.checks.server_version_parses,
                        report.error
                    );
                }
                println!("  Connection Errors: {:?}", result.connection_errors);
            }

            assert!(
                !result.federation_ok,
                "Federation should fail for {} due to known issues - see printed details above",
                server
            );
            assert!(
                !result.dnsresult.addrs.is_empty(),
                "Should find addresses for {} (DNS should work) - see printed details above",
                server
            );

            // Check that we have connection reports but they show failures
            if !result.connection_reports.is_empty() {
                let connection_report = result.connection_reports.values().next().unwrap();
                assert!(
                    !connection_report.checks.all_checks_ok,
                    "AllChecksOK should be false for known bad server {} - see printed details above",
                    server
                );

                // For timedout.uk specifically, check server version parsing failure
                if server == "timedout.uk" {
                    assert!(
                        !connection_report.checks.server_version_parses,
                        "ServerVersionParses should be false for timedout.uk - see printed details above"
                    );
                }
            }
        }
    }
}
