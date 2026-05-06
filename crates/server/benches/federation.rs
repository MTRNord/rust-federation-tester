use std::time::Duration;

/// Criterion benchmarks for the main federation-check path.
///
/// # Note
/// The `full_check` group makes real network requests. Run it only in
/// environments with internet access. Use `--bench full_check` to run just
/// that group, or `--bench validation_only` for the CPU-only baseline.
///
/// ```sh
/// cargo bench --bench federation
/// cargo bench --bench federation -- full_check
/// cargo bench --bench federation -- validation_only
/// ```
use criterion::{Criterion, criterion_group, criterion_main};
use hickory_resolver::Resolver;
use hickory_resolver::config::ResolverConfig;
use hickory_resolver::name_server::TokioConnectionProvider;
use rust_federation_tester::connection_pool::ConnectionPool;
use rust_federation_tester::response::generate_json_report;
use rustls::crypto::CryptoProvider;

fn install_crypto_provider() {
    use std::sync::OnceLock;
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        let _ = CryptoProvider::install_default(rustls::crypto::ring::default_provider());
    });
}

fn build_resolver(rt: &tokio::runtime::Runtime) -> Resolver<TokioConnectionProvider> {
    // build() spawns background tasks and requires an active Tokio runtime.
    let _guard = rt.enter();
    Resolver::builder_with_config(ResolverConfig::google(), TokioConnectionProvider::default())
        .build()
}

/// Benchmarks the full federation check against a known-good public server.
/// Each iteration does real DNS resolution, TLS handshake, and HTTP federation
/// requests, so sample counts are kept low and measurement time is generous.
fn bench_full_check(c: &mut Criterion) {
    install_crypto_provider();

    let rt = tokio::runtime::Runtime::new().unwrap();
    let resolver = build_resolver(&rt);
    let pool = ConnectionPool::default();

    let mut group = c.benchmark_group("full_check");
    group.sample_size(200);
    group.measurement_time(Duration::from_mins(2));

    group.bench_function("mtrnord.blog", |b| {
        b.iter(|| {
            rt.block_on(async {
                generate_json_report("mtrnord.blog", &resolver, &pool)
                    .await
                    .expect("federation check failed")
            })
        });
    });

    group.finish();
}

/// Benchmarks the pure-CPU paths that return before any network I/O, giving a
/// baseline for validation and early-exit overhead.
fn bench_validation_only(c: &mut Criterion) {
    install_crypto_provider();

    let rt = tokio::runtime::Runtime::new().unwrap();
    let resolver = build_resolver(&rt);
    let pool = ConnectionPool::default();

    let mut group = c.benchmark_group("validation_only");
    group.sample_size(200);

    // Server name that fails parse_and_validate_server_name immediately.
    group.bench_function("invalid_server_name", |b| {
        b.iter(|| {
            rt.block_on(async {
                generate_json_report("not a valid $server!", &resolver, &pool)
                    .await
                    .expect("report generation should not error")
            })
        });
    });

    group.finish();
}

criterion_group!(benches, bench_full_check, bench_validation_only);
criterion_main!(benches);
