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
}

impl<K, V> ResponseCache<K, V>
where
    K: Clone + Eq + Hash + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    pub fn new(default_ttl: Duration) -> Self {
        let cache = Self {
            cache: Arc::new(DashMap::new()),
            default_ttl,
        };

        // Start cleanup task
        let cache_clone = cache.cache.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                cache_clone.retain(|_, entry| !entry.is_expired());
            }
        });

        cache
    }

    pub fn get(&self, key: &K) -> Option<V> {
        self.cache.get(key).and_then(|entry| {
            if entry.is_expired() {
                None
            } else {
                Some(entry.data().clone())
            }
        })
    }

    /// Get cached value only if explicitly requested and not expired
    pub fn get_cached(&self, key: &K, use_cache: bool) -> Option<V> {
        if !use_cache {
            return None;
        }
        self.get(key)
    }

    pub fn insert(&self, key: K, value: V) {
        self.cache
            .insert(key, CacheEntry::new(value, self.default_ttl));
    }

    pub fn insert_with_ttl(&self, key: K, value: V, ttl: Duration) {
        self.cache.insert(key, CacheEntry::new(value, ttl));
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
