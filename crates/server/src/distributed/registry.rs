//! Shared confirmation registry for alert failure counts.
//!
//! The [`Registry`] abstraction tracks how many consecutive 1-minute failures
//! each alert has accumulated in the confirmation phase. It has two backends:
//!
//! - [`InMemoryRegistry`] — `Arc<Mutex<HashMap>>`, suitable for a single instance.
//! - [`RedisRegistry`] — Redis hash, required for horizontal scaling.
//!
//! Both variants are accessed through the [`Registry`] enum so call sites don't
//! need to be generic over the backend.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use tokio::sync::Mutex;

/// Shared confirmation registry.
///
/// Maps `alert_id → consecutive 1-minute failure count` during the
/// confirmation phase. When an alert's count reaches
/// [`CONFIRMATION_THRESHOLD`][crate::alerts::checks::CONFIRMATION_THRESHOLD]
/// it transitions to "confirmed failing" and the entry is removed.
///
/// ## Backend selection
///
/// Use [`Registry::InMemory`] (via [`crate::distributed::in_memory`]) for
/// single-instance deployments. Use [`Registry::Redis`] (via
/// [`crate::distributed::redis_backed`]) when running multiple pods.
#[derive(Clone, Debug)]
pub enum Registry {
    /// In-memory storage — zero dependencies, suitable for single-instance deployments.
    InMemory(InMemoryRegistry),
    /// Redis/Valkey-backed storage — required for horizontal scaling.
    #[cfg(feature = "redis-backend")]
    Redis(RedisRegistry),
}

impl Registry {
    /// Returns the current failure count for `alert_id`, or `None` if absent.
    pub async fn get(&self, alert_id: i32) -> Option<u32> {
        match self {
            Self::InMemory(r) => r.get(alert_id).await,
            #[cfg(feature = "redis-backend")]
            Self::Redis(r) => r.get(alert_id).await,
        }
    }

    /// Atomically increment the failure count for `alert_id`.
    ///
    /// If the key is absent, it is initialised to `1`. Returns the new count.
    pub async fn increment(&self, alert_id: i32) -> u32 {
        match self {
            Self::InMemory(r) => r.increment(alert_id).await,
            #[cfg(feature = "redis-backend")]
            Self::Redis(r) => r.increment(alert_id).await,
        }
    }

    /// Explicitly set the failure count for `alert_id`.
    pub async fn set(&self, alert_id: i32, count: u32) {
        match self {
            Self::InMemory(r) => r.set(alert_id, count).await,
            #[cfg(feature = "redis-backend")]
            Self::Redis(r) => r.set(alert_id, count).await,
        }
    }

    /// Remove the entry for `alert_id` (called on recovery or promotion to confirmed-failing).
    pub async fn remove(&self, alert_id: i32) {
        match self {
            Self::InMemory(r) => r.remove(alert_id).await,
            #[cfg(feature = "redis-backend")]
            Self::Redis(r) => r.remove(alert_id).await,
        }
    }

    /// Returns the set of all alert IDs currently in the confirmation phase.
    pub async fn all_ids(&self) -> HashSet<i32> {
        match self {
            Self::InMemory(r) => r.all_ids().await,
            #[cfg(feature = "redis-backend")]
            Self::Redis(r) => r.all_ids().await,
        }
    }
}

// ---------------------------------------------------------------------------
// In-memory implementation
// ---------------------------------------------------------------------------

/// In-memory registry backed by a `tokio::sync::Mutex`-protected `HashMap`.
///
/// This is the default for single-instance deployments. On restart the
/// registry is empty, which is intentional — stale failure counts from an
/// unknown time in the past should not be resumed.
#[derive(Clone, Debug, Default)]
pub struct InMemoryRegistry(Arc<Mutex<HashMap<i32, u32>>>);

impl InMemoryRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    async fn get(&self, alert_id: i32) -> Option<u32> {
        self.0.lock().await.get(&alert_id).copied()
    }

    async fn increment(&self, alert_id: i32) -> u32 {
        let mut map = self.0.lock().await;
        let entry = map.entry(alert_id).or_insert(0);
        *entry += 1;
        *entry
    }

    async fn set(&self, alert_id: i32, count: u32) {
        self.0.lock().await.insert(alert_id, count);
    }

    async fn remove(&self, alert_id: i32) {
        self.0.lock().await.remove(&alert_id);
    }

    async fn all_ids(&self) -> HashSet<i32> {
        self.0.lock().await.keys().copied().collect()
    }
}

// ---------------------------------------------------------------------------
// Redis/Valkey implementation
// ---------------------------------------------------------------------------

/// Redis/Valkey-backed registry.
///
/// Stores all confirmation counts in a single Redis hash:
/// `{key_prefix}:confirmation` with `alert_id` strings as fields.
///
/// Redis commands used: `HGET`, `HINCRBY`, `HSET`, `HDEL`, `HKEYS`.
#[cfg(feature = "redis-backend")]
#[derive(Clone, Debug)]
pub struct RedisRegistry {
    pool: deadpool_redis::Pool,
    /// The Redis hash key, e.g. `"federation-tester:confirmation"`.
    hash_key: String,
}

#[cfg(feature = "redis-backend")]
impl RedisRegistry {
    pub fn new(pool: deadpool_redis::Pool, key_prefix: &str) -> Self {
        Self {
            pool,
            hash_key: format!("{key_prefix}:confirmation"),
        }
    }

    /// Acquire a pooled Redis connection, logging a warning and returning `None` on failure.
    async fn conn(&self, ctx: &str) -> Option<deadpool_redis::Connection> {
        match self.pool.get().await {
            Ok(c) => Some(c),
            Err(e) => {
                tracing::warn!(error = %e, ctx, "Redis pool error in registry");
                None
            }
        }
    }

    async fn get(&self, alert_id: i32) -> Option<u32> {
        let mut conn = self.pool.get().await.ok()?;
        let val: Option<u32> = redis::cmd("HGET")
            .arg(&self.hash_key)
            .arg(alert_id)
            .query_async(&mut *conn)
            .await
            .unwrap_or(None);
        val
    }

    async fn increment(&self, alert_id: i32) -> u32 {
        let Some(mut conn) = self.conn("increment").await else {
            return 1;
        };
        let result: redis::RedisResult<i64> = redis::cmd("HINCRBY")
            .arg(&self.hash_key)
            .arg(alert_id)
            .arg(1i64)
            .query_async(&mut *conn)
            .await;
        match result {
            Ok(v) => v.max(0) as u32,
            Err(e) => {
                tracing::warn!(alert_id = alert_id, error = %e, "HINCRBY failed; returning 1");
                1
            }
        }
    }

    async fn set(&self, alert_id: i32, count: u32) {
        let Some(mut conn) = self.conn("set").await else {
            return;
        };
        let _: redis::RedisResult<()> = redis::cmd("HSET")
            .arg(&self.hash_key)
            .arg(alert_id)
            .arg(count)
            .query_async(&mut *conn)
            .await;
    }

    async fn remove(&self, alert_id: i32) {
        let Some(mut conn) = self.conn("remove").await else {
            return;
        };
        let _: redis::RedisResult<()> = redis::cmd("HDEL")
            .arg(&self.hash_key)
            .arg(alert_id)
            .query_async(&mut *conn)
            .await;
    }

    async fn all_ids(&self) -> HashSet<i32> {
        let Some(mut conn) = self.conn("all_ids").await else {
            return HashSet::new();
        };
        let result: redis::RedisResult<Vec<String>> = redis::cmd("HKEYS")
            .arg(&self.hash_key)
            .query_async(&mut *conn)
            .await;
        result
            .unwrap_or_default()
            .into_iter()
            .filter_map(|s| s.parse::<i32>().ok())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn new_in_memory() -> Registry {
        Registry::InMemory(InMemoryRegistry::new())
    }

    // ── InMemoryRegistry via Registry enum ────────────────────────────────

    #[tokio::test]
    async fn get_returns_none_for_unknown_alert() {
        let r = new_in_memory().await;
        assert!(r.get(99).await.is_none());
    }

    #[tokio::test]
    async fn increment_starts_at_one() {
        let r = new_in_memory().await;
        assert_eq!(r.increment(1).await, 1);
    }

    #[tokio::test]
    async fn increment_accumulates() {
        let r = new_in_memory().await;
        assert_eq!(r.increment(1).await, 1);
        assert_eq!(r.increment(1).await, 2);
        assert_eq!(r.increment(1).await, 3);
    }

    #[tokio::test]
    async fn get_returns_value_after_increment() {
        let r = new_in_memory().await;
        r.increment(5).await;
        r.increment(5).await;
        assert_eq!(r.get(5).await, Some(2));
    }

    #[tokio::test]
    async fn set_overrides_existing_value() {
        let r = new_in_memory().await;
        r.increment(7).await;
        r.increment(7).await;
        r.set(7, 42).await;
        assert_eq!(r.get(7).await, Some(42));
    }

    #[tokio::test]
    async fn remove_deletes_entry() {
        let r = new_in_memory().await;
        r.set(3, 10).await;
        r.remove(3).await;
        assert!(r.get(3).await.is_none());
    }

    #[tokio::test]
    async fn remove_nonexistent_is_noop() {
        let r = new_in_memory().await;
        r.remove(999).await; // should not panic
        assert!(r.get(999).await.is_none());
    }

    #[tokio::test]
    async fn all_ids_returns_all_keys() {
        let r = new_in_memory().await;
        r.set(1, 1).await;
        r.set(2, 5).await;
        r.set(3, 9).await;
        let ids = r.all_ids().await;
        assert_eq!(ids.len(), 3);
        assert!(ids.contains(&1));
        assert!(ids.contains(&2));
        assert!(ids.contains(&3));
    }

    #[tokio::test]
    async fn all_ids_empty_when_nothing_set() {
        let r = new_in_memory().await;
        assert!(r.all_ids().await.is_empty());
    }

    #[tokio::test]
    async fn increment_different_alerts_are_independent() {
        let r = new_in_memory().await;
        r.increment(10).await;
        r.increment(10).await;
        r.increment(20).await;
        assert_eq!(r.get(10).await, Some(2));
        assert_eq!(r.get(20).await, Some(1));
    }
}
