use dashmap::DashMap;
use std::hash::Hash;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct CacheEntry<T> {
    data: T,
    expires_at: Instant,
}

impl<T> CacheEntry<T> {
    pub fn new(data: T, ttl: Duration) -> Self {
        Self {
            data,
            expires_at: Instant::now() + ttl,
        }
    }

    pub fn is_expired(&self) -> bool {
        Instant::now() > self.expires_at
    }

    pub fn data(&self) -> &T {
        &self.data
    }
}

#[derive(Clone)]
pub struct ResponseCache<K, V>
where
    K: Clone + Eq + Hash + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    cache: Arc<DashMap<K, CacheEntry<V>>>,
    default_ttl: Duration,
    last_cleanup: Arc<std::sync::Mutex<Instant>>,
    stats: Arc<CacheStatsInner>,
}

#[derive(Default, Debug)]
struct CacheStatsInner {
    hits: std::sync::atomic::AtomicU64,
    misses: std::sync::atomic::AtomicU64,
    insertions: std::sync::atomic::AtomicU64,
    evictions: std::sync::atomic::AtomicU64,
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub insertions: u64,
    pub evictions: u64,
    pub len: usize,
}

impl<K, V> ResponseCache<K, V>
where
    K: Clone + Eq + Hash + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    pub fn new(default_ttl: Duration) -> Self {
        Self {
            cache: Arc::new(DashMap::new()),
            default_ttl,
            last_cleanup: Arc::new(std::sync::Mutex::new(Instant::now())),
            stats: Arc::new(CacheStatsInner::default()),
        }
    }

    /// Perform lazy cleanup if enough time has passed
    fn maybe_cleanup(&self) {
        const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

        // Check if cleanup is needed (non-blocking)
        if let Ok(mut last_cleanup) = self.last_cleanup.try_lock()
            && last_cleanup.elapsed() >= CLEANUP_INTERVAL
        {
            *last_cleanup = Instant::now();
            drop(last_cleanup); // Release lock before cleanup

            // Perform cleanup
            let mut evicted = 0u64;
            self.cache.retain(|_, entry| {
                let keep = !entry.is_expired();
                if !keep {
                    evicted += 1;
                }
                keep
            });
            if evicted > 0 {
                self.stats
                    .evictions
                    .fetch_add(evicted, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }

    pub fn get(&self, key: &K) -> Option<V> {
        // Perform lazy cleanup on get operations
        self.maybe_cleanup();

        let result = self.cache.get(key).and_then(|entry| {
            if entry.is_expired() {
                None
            } else {
                Some(entry.data().clone())
            }
        });
        if result.is_some() {
            self.stats
                .hits
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        } else {
            self.stats
                .misses
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        result
    }

    /// Get cached value only if explicitly requested and not expired
    pub fn get_cached(&self, key: &K, use_cache: bool) -> Option<V> {
        if !use_cache {
            return None;
        }
        self.get(key)
    }

    pub fn insert(&self, key: K, value: V) {
        // Perform lazy cleanup on insert operations
        self.maybe_cleanup();

        self.cache
            .insert(key, CacheEntry::new(value, self.default_ttl));
        self.stats
            .insertions
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn insert_with_ttl(&self, key: K, value: V, ttl: Duration) {
        self.cache.insert(key, CacheEntry::new(value, ttl));
        self.stats
            .insertions
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn invalidate(&self, key: &K) {
        self.cache.remove(key);
    }

    pub fn clear(&self) {
        self.cache.clear();
    }

    pub fn len(&self) -> usize {
        self.cache.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }
}

impl<K, V> ResponseCache<K, V>
where
    K: Clone + Eq + Hash + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            hits: self.stats.hits.load(std::sync::atomic::Ordering::Relaxed),
            misses: self.stats.misses.load(std::sync::atomic::Ordering::Relaxed),
            insertions: self
                .stats
                .insertions
                .load(std::sync::atomic::Ordering::Relaxed),
            evictions: self
                .stats
                .evictions
                .load(std::sync::atomic::Ordering::Relaxed),
            len: self.cache.len(),
        }
    }
}

// Specific cache types for our use case
pub type DnsCache = ResponseCache<String, Vec<String>>;
pub type WellKnownCache = ResponseCache<String, crate::response::WellKnownResult>;
pub type VersionCache = ResponseCache<String, String>;

// Cache keys for different types of requests
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct WellKnownCacheKey {
    pub server_name: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct VersionCacheKey {
    pub addr: String,
    pub sni: String,
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new(Duration::from_secs(30)) // 30 seconds for DNS - quick re-testing
    }
}

impl Default for WellKnownCache {
    fn default() -> Self {
        Self::new(Duration::from_secs(15)) // 15 seconds for well-known - debugging friendly
    }
}

impl Default for VersionCache {
    fn default() -> Self {
        Self::new(Duration::from_secs(10)) // 10 seconds for version - very short for debugging
    }
}
