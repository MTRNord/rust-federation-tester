use criterion::{Criterion, black_box, criterion_group, criterion_main};
use hickory_resolver::Resolver;
use hickory_resolver::config::ResolverConfig;
use hickory_resolver::name_server::TokioConnectionProvider;
use rust_federation_tester::connection_pool::ConnectionPool;
use rust_federation_tester::response::generate_json_report;
use rustls::crypto::CryptoProvider;
use std::alloc::{GlobalAlloc, Layout, System};

// Same deterministic allocator as full_check — each bench binary needs its own.
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

/// Benchmarks the pure-CPU paths that return before any network I/O, giving a
/// baseline for validation and early-exit overhead.
fn bench_validation_only(c: &mut Criterion) {
    install_crypto_provider();

    let rt = tokio::runtime::Runtime::new().unwrap();
    let resolver = build_resolver(&rt);
    let pool = ConnectionPool::default();

    let mut group = c.benchmark_group("validation_only");
    group.sample_size(200);

    group.bench_function("invalid_server_name", |b| {
        b.iter(|| {
            black_box(rt.block_on(async {
                generate_json_report(black_box("not a valid $server!"), &resolver, &pool)
                    .await
                    .expect("report generation should not error")
            }))
        });
    });

    group.finish();
}

criterion_group!(benches, bench_validation_only);
criterion_main!(benches);
