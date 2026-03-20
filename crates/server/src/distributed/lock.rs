//! Distributed loop mutex for background check loops.
//!
//! The [`Lock`] abstraction ensures that only one server instance runs a
//! given background loop iteration at a time when deployed horizontally.
//!
//! ## Backends
//!
//! - [`Lock::Noop`] — always acquires (single-instance passthrough).
//! - [`Lock::Redis`] — uses `SET key instance_uuid NX PX ttl_ms` so the lock
//!   expires automatically if the holding instance crashes.
//!
//! ## Fail-open policy
//!
//! If Redis is unreachable, [`Lock::Redis`] returns `true` (acquire succeeds)
//! so checks continue with a warning rather than silently stopping. This
//! degrades gracefully to single-instance behaviour at the cost of potential
//! duplicate emails — acceptable for a monitoring tool.

use std::sync::Arc;

/// Distributed mutex for a named background loop.
///
/// Acquire at the top of each loop iteration. If [`Lock::try_acquire`]
/// returns `false`, skip the current cycle and wait for the next interval.
#[derive(Clone, Debug)]
pub enum Lock {
    /// Always acquires — suitable for single-instance deployments.
    Noop,
    /// Redis/Valkey-backed distributed lock.
    #[cfg(feature = "redis-backend")]
    Redis(RedisLock),
}

impl Lock {
    /// Try to acquire the lock for `name` with the given TTL.
    ///
    /// Returns `true` if this instance should run the loop iteration,
    /// `false` if another instance already holds the lock for this cycle.
    ///
    /// The TTL should be slightly longer than the loop interval so the lock
    /// outlives a slow iteration, but short enough to recover within one cycle
    /// if the holder crashes.
    pub async fn try_acquire(&self, name: &str, ttl_ms: u64) -> bool {
        match self {
            Self::Noop => true,
            #[cfg(feature = "redis-backend")]
            Self::Redis(l) => l.try_acquire(name, ttl_ms).await,
        }
    }
}

// ---------------------------------------------------------------------------
// Redis/Valkey implementation
// ---------------------------------------------------------------------------

/// Redis/Valkey-backed distributed lock.
///
/// Uses `SET {prefix}:lock:{name} {instance_id} NX PX {ttl_ms}` so that:
/// - Only one instance can hold the lock at a time (`NX`).
/// - The lock expires automatically if the holder crashes (`PX ttl_ms`).
/// - Each instance identifies itself with a unique UUID so future extensions
///   (e.g. explicit release) can verify ownership.
#[cfg(feature = "redis-backend")]
#[derive(Clone, Debug)]
pub struct RedisLock {
    pool: deadpool_redis::Pool,
    key_prefix: String,
    /// Unique identifier for this process, generated once at startup.
    instance_id: Arc<str>,
}

#[cfg(feature = "redis-backend")]
impl RedisLock {
    pub fn new(pool: deadpool_redis::Pool, key_prefix: &str, instance_id: String) -> Self {
        Self {
            pool,
            key_prefix: key_prefix.to_string(),
            instance_id: instance_id.into(),
        }
    }

    async fn try_acquire(&self, name: &str, ttl_ms: u64) -> bool {
        let key = format!("{}:lock:{}", self.key_prefix, name);
        let mut conn = match self.pool.get().await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(
                    lock = name,
                    error = %e,
                    "Redis pool error acquiring lock; proceeding (fail-open)"
                );
                return true;
            }
        };
        // SET key value NX PX ttl_ms
        // Returns "OK" if acquired, nil if another instance holds it.
        let result: redis::RedisResult<Option<String>> = redis::cmd("SET")
            .arg(&key)
            .arg(self.instance_id.as_ref())
            .arg("NX")
            .arg("PX")
            .arg(ttl_ms)
            .query_async(&mut *conn)
            .await;
        match result {
            Ok(Some(_)) => true,
            Ok(None) => false,
            Err(e) => {
                tracing::warn!(
                    lock = name,
                    error = %e,
                    "Redis SET NX failed; proceeding (fail-open)"
                );
                true
            }
        }
    }
}
