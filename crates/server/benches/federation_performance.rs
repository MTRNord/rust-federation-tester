use criterion::{Criterion, black_box, criterion_group, criterion_main};
use rust_federation_tester::cache::{DnsCache, VersionCache};
use rust_federation_tester::connection_pool::ConnectionPool;

// CI-friendly benchmark configuration
fn is_ci_mode() -> bool {
    std::env::var("CI").is_ok() || std::env::var("QUICK_BENCH").is_ok()
}

fn benchmark_cache_operations(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("dns_cache_insert", |b| {
        let _guard = rt.enter();
        // Create cache outside the benchmark loop to avoid spawning too many cleanup tasks
        let cache = DnsCache::default();
        let mut counter = 0;
        b.iter(|| {
            counter += 1;
            let key = format!("example{}.com", counter);
            let value = vec!["192.168.1.1:8448".to_string()];
            cache.insert(black_box(key), black_box(value));
        });
    });

    c.bench_function("dns_cache_get", |b| {
        let _guard = rt.enter();
        let cache = DnsCache::default();
        let key = "example.com".to_string();
        let value = vec!["192.168.1.1:8448".to_string()];
        cache.insert(key.clone(), value);

        b.iter(|| {
            let result = cache.get(black_box(&key));
            black_box(result);
        });
    });

    c.bench_function("version_cache_operations", |b| {
        let _guard = rt.enter();
        let cache = VersionCache::default();
        let key = "192.168.1.1:8448".to_string();
        let value = r#"{"name":"Synapse","version":"1.95.1"}"#.to_string();

        b.iter(|| {
            cache.insert(black_box(key.clone()), black_box(value.clone()));
            let result = cache.get(black_box(&key));
            black_box(result);
        });
    });
}

fn benchmark_concurrent_cache_access(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("concurrent_cache_access", |b| {
        let _guard = rt.enter();
        // Create cache once outside the iteration loop to avoid spawning
        // multiple background cleanup tasks
        let cache = DnsCache::default();

        b.iter(|| {
            // Reduced concurrency to avoid OOM - was 10, now 3
            for i in 0..3 {
                let key = format!("test{}.com", i);
                let value = vec![format!("192.168.1.{}:8448", i)];
                cache.insert(key.clone(), value);
                black_box(cache.get(&key));
            }
        });
    });
}

fn benchmark_connection_pool_creation(c: &mut Criterion) {
    c.bench_function("connection_pool_creation", |b| {
        b.iter(|| {
            let pool = ConnectionPool::new(black_box(5), black_box(10));
            black_box(pool);
        });
    });
}

#[allow(dead_code)]
fn benchmark_cache_expiration_handling(c: &mut Criterion) {
    // Fixed: Cache is now created once outside the iteration loop
    // to avoid spawning multiple background cleanup tasks that cause OOM

    c.bench_function("cache_basic_operations", |b| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();

        // Create cache once outside the iteration loop to avoid spawning
        // multiple background cleanup tasks
        let cache = DnsCache::default();

        b.iter(|| {
            let key = "example.com".to_string();
            let value = vec!["192.168.1.1:8448".to_string()];

            cache.insert(black_box(key.clone()), black_box(value));
            let result = cache.get(black_box(&key));
            black_box(result);
        });
    });
}

criterion_group!(
    benches,
    benchmark_cache_operations,
    benchmark_concurrent_cache_access,
    benchmark_connection_pool_creation,
    benchmark_cache_expiration_handling
);
criterion_main!(benches);
