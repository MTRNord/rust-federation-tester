use criterion::{Criterion, black_box, criterion_group, criterion_main};
use hickory_resolver::Resolver;
use hickory_resolver::config::ResolverConfig;
use hickory_resolver::name_server::TokioConnectionProvider;
use rust_federation_tester::connection_pool::ConnectionPool;
use rust_federation_tester::response::generate_json_report;
use rustls::crypto::CryptoProvider;
use std::alloc::{GlobalAlloc, Layout, System};
use std::time::Duration;

// Forces malloc+copy+free instead of potentially non-deterministic in-place realloc grow.
// Whether in-place growing succeeds depends on OS memory state, making it non-deterministic.
// This allocator always takes the slower but fully predictable path.
struct DeterministicAlloc;

unsafe impl GlobalAlloc for DeterministicAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_layout = unsafe { Layout::from_size_align_unchecked(new_size, layout.align()) };
        let new_ptr = unsafe { System.alloc(new_layout) };
        if !new_ptr.is_null() {
            unsafe { std::ptr::copy_nonoverlapping(ptr, new_ptr, layout.size().min(new_size)) };
            unsafe { System.dealloc(ptr, layout) };
        }
        new_ptr
    }
}

#[global_allocator]
static ALLOC: DeterministicAlloc = DeterministicAlloc;

fn install_crypto_provider() {
    use std::sync::OnceLock;
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        let _ = CryptoProvider::install_default(rustls::crypto::ring::default_provider());
    });
}

fn build_resolver(rt: &tokio::runtime::Runtime) -> Resolver<TokioConnectionProvider> {
    let _guard = rt.enter();
    Resolver::builder_with_config(ResolverConfig::google(), TokioConnectionProvider::default())
        .build()
}

/// Benchmarks the full federation check against a known-good public server.
/// Each iteration does real DNS resolution, TLS handshake (first) or pool reuse
/// (subsequent), and HTTP federation requests.
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
            black_box(rt.block_on(async {
                generate_json_report(black_box("mtrnord.blog"), &resolver, &pool)
                    .await
                    .expect("federation check failed")
            }))
        });
    });

    group.finish();
}

criterion_group!(benches, bench_full_check);
criterion_main!(benches);
