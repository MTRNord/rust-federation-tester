use clap::{Parser, ValueEnum};
use hickory_resolver::Resolver;
use hickory_resolver::config as resolver_config;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use matrix_federation_tester::{FederationConfig, connection_pool::ConnectionPool, response::Root};
use std::process;

#[derive(Parser)]
#[command(
    name = "matrix-federation-test",
    about = "Test a Matrix server's federation compliance",
    version
)]
struct Args {
    /// Matrix server name to test (e.g. matrix.org or matrix.org:8448)
    #[arg(long, short)]
    server: String,

    /// Output format
    #[arg(long, default_value = "pretty")]
    format: OutputFormat,

    /// Network timeout in seconds
    #[arg(long, default_value = "10")]
    timeout: u64,
}

#[derive(ValueEnum, Clone)]
enum OutputFormat {
    Pretty,
    Json,
    Tap,
}

struct TestResult {
    name: &'static str,
    passed: bool,
    message: String,
}

fn well_known_reachable(root: &Root) -> TestResult {
    let passed = root.well_known_result.values().any(|wk| wk.error.is_none());
    TestResult {
        name: "well_known_reachable",
        passed,
        message: if passed {
            "at least one IP reached /.well-known/matrix/server".into()
        } else if root.well_known_result.is_empty() {
            "well-known lookup was skipped (IP literal or explicit port — expected)".into()
        } else {
            "all well-known attempts failed".into()
        },
    }
}

fn well_known_valid(root: &Root) -> TestResult {
    let passed = root
        .well_known_result
        .values()
        .any(|wk| !wk.m_server.is_empty() && wk.error.is_none());
    TestResult {
        name: "well_known_valid",
        passed: passed || root.well_known_result.is_empty(),
        message: if root.well_known_result.is_empty() {
            "well-known skipped — not applicable".into()
        } else if passed {
            "at least one well-known response contains a valid m.server".into()
        } else {
            "no well-known response has a valid m.server value".into()
        },
    }
}

fn well_known_consistent(root: &Root) -> TestResult {
    TestResult {
        name: "well_known_consistent",
        passed: !root.federation_warning,
        message: if root.federation_warning {
            "split-brain: different IPs returned different m.server values".into()
        } else {
            "well-known responses are consistent across IPs".into()
        },
    }
}

fn srv_or_dns_resolves(root: &Root) -> TestResult {
    let passed = !root.dnsresult.addrs.is_empty();
    TestResult {
        name: "srv_or_dns_resolves",
        passed,
        message: if passed {
            format!(
                "resolved {} address(es){}",
                root.dnsresult.addrs.len(),
                if root.dnsresult.srvskipped {
                    " via A/AAAA (SRV skipped)"
                } else {
                    " via SRV"
                }
            )
        } else {
            "no addresses resolved".into()
        },
    }
}

fn tls_valid(root: &Root) -> TestResult {
    let passed = root
        .connection_reports
        .values()
        .any(|r| r.checks.valid_certificates);
    TestResult {
        name: "tls_valid",
        passed,
        message: if passed {
            "at least one connection has valid TLS certificates".into()
        } else if root.connection_reports.is_empty() {
            "no connections established".into()
        } else {
            "no connection has valid TLS certificates".into()
        },
    }
}

fn version_reachable(root: &Root) -> TestResult {
    let passed = root
        .connection_reports
        .values()
        .any(|r| r.checks.server_version_parses);
    TestResult {
        name: "version_reachable",
        passed,
        message: if passed {
            format!("server version: {}", root.version.name)
        } else if root.connection_reports.is_empty() {
            "no connections established".into()
        } else {
            "/_matrix/federation/v1/version did not return a parseable response".into()
        },
    }
}

fn keys_reachable(root: &Root) -> TestResult {
    let passed = !root.connection_reports.is_empty() && root.connection_errors.is_empty();
    TestResult {
        name: "keys_reachable",
        passed,
        message: if root.connection_errors.is_empty() && !root.connection_reports.is_empty() {
            "/_matrix/key/v2/server reachable on all tested addresses".into()
        } else if !root.connection_errors.is_empty() {
            format!("{} connection(s) failed", root.connection_errors.len())
        } else {
            "no connections attempted".into()
        },
    }
}

fn keys_valid_ed25519(root: &Root) -> TestResult {
    let passed = root
        .connection_reports
        .values()
        .any(|r| r.checks.has_ed25519key && r.checks.all_ed25519checks_ok);
    TestResult {
        name: "keys_valid_ed25519",
        passed,
        message: if passed {
            "ed25519 key present and signature verifies".into()
        } else if root.connection_reports.is_empty() {
            "no connections established".into()
        } else {
            "ed25519 key missing or signature verification failed".into()
        },
    }
}

fn federation_ok(root: &Root) -> TestResult {
    TestResult {
        name: "federation_ok",
        passed: root.federation_ok,
        message: if root.federation_ok {
            "FederationOK = true".into()
        } else {
            root.error
                .as_ref()
                .map(|e| e.error.clone())
                .unwrap_or_else(|| "FederationOK = false".into())
        },
    }
}

const ALL_TESTS: &[fn(&Root) -> TestResult] = &[
    well_known_reachable,
    well_known_valid,
    well_known_consistent,
    srv_or_dns_resolves,
    tls_valid,
    version_reachable,
    keys_reachable,
    keys_valid_ed25519,
    federation_ok,
];

fn print_pretty(results: &[TestResult]) {
    for r in results {
        let icon = if r.passed { "✓" } else { "✗" };
        println!("{icon} {}: {}", r.name, r.message);
    }
}

fn print_tap(results: &[TestResult]) {
    println!("TAP version 13");
    println!("1..{}", results.len());
    for (i, r) in results.iter().enumerate() {
        let status = if r.passed { "ok" } else { "not ok" };
        println!("{status} {} - {} # {}", i + 1, r.name, r.message);
    }
}

fn print_json(results: &[TestResult]) {
    let obj: Vec<_> = results
        .iter()
        .map(|r| {
            serde_json::json!({
                "name": r.name,
                "passed": r.passed,
                "message": r.message,
            })
        })
        .collect();
    println!("{}", serde_json::to_string_pretty(&obj).unwrap());
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("matrix_federation_test=warn".parse().unwrap()),
        )
        .with_writer(std::io::stderr)
        .init();

    // Install a TLS crypto provider.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let resolver = Resolver::builder_with_config(
        resolver_config::ResolverConfig::udp_and_tcp(&resolver_config::GOOGLE),
        TokioRuntimeProvider::default(),
    )
    .build()
    .expect("failed to build DNS resolver");

    let pool = ConnectionPool::default();
    let config = FederationConfig {
        network_timeout: tokio::time::Duration::from_secs(args.timeout),
        allow_private_targets: false,
    };

    let report = match matrix_federation_tester::response::generate_json_report(
        &args.server,
        &resolver,
        &pool,
        &config,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Fatal error generating report: {e}");
            process::exit(2);
        }
    };

    let results: Vec<TestResult> = ALL_TESTS.iter().map(|f| f(&report)).collect();

    match args.format {
        OutputFormat::Pretty => print_pretty(&results),
        OutputFormat::Tap => print_tap(&results),
        OutputFormat::Json => print_json(&results),
    }

    let all_passed = results.iter().all(|r| r.passed);
    process::exit(if all_passed { 0 } else { 1 });
}
