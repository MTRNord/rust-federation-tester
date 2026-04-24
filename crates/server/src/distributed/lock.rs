//! Distributed loop mutex for background check loops.
//!
//! The [`Lock`] abstraction ensures that only one server instance runs a
//! given background loop iteration at a time when deployed horizontally.
//!
//! ## Backends
//!
//! - [`Lock::Noop`] — always acquires (single-instance passthrough).
//! - [`Lock::Redis`] — initial acquire uses `SET key uuid NX PX ttl_ms`;
//!   subsequent renewal uses a Lua script that atomically checks ownership
//!   and refreshes the TTL, so the holder processes on every tick instead of
//!   once per TTL window.
//!
//! ## Usage pattern
//!
//! ```text
//! let mut holding = false;
//! loop {
//!     interval.tick().await;
//!     let ok = if holding {
//!         lock.try_renew("my_loop", ttl_ms).await   // extend our existing lock
//!     } else {
//!         let acquired = lock.try_acquire("my_loop", ttl_ms).await;
//!         holding = acquired;
//!         acquired
//!     };
//!     if !ok { holding = false; continue; }
//!     // … do work …
//! }
//! ```
//!
//! ## Fail-open policy
//!
//! If Redis is unreachable, both operations return `true` so background tasks
//! continue with a warning rather than silently stopping.  This degrades
//! gracefully to single-instance behaviour at the cost of potential duplicate
//! emails — acceptable for a monitoring tool.

use std::sync::Arc;

/// Distributed mutex for a named background loop.
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
    /// Uses `SET NX PX` — only succeeds when no other instance holds the lock.
    /// Returns `true` if this instance now holds the lock.
    pub async fn try_acquire(&self, name: &str, ttl_ms: u64) -> bool {
        match self {
            Self::Noop => true,
            #[cfg(feature = "redis-backend")]
            Self::Redis(l) => l.try_acquire(name, ttl_ms).await,
        }
    }

    /// Renew the lock for `name` if this instance still owns it.
    ///
    /// Atomically checks that the stored value equals this instance's ID and,
    /// if so, resets the TTL. Returns `true` on success, `false` if another
    /// instance has taken over (or the key expired).
    ///
    /// Call this instead of `try_acquire` on every tick after the initial
    /// acquire so the holder processes work on every interval rather than once
    /// per TTL window.
    pub async fn try_renew(&self, name: &str, ttl_ms: u64) -> bool {
        match self {
            Self::Noop => true,
            #[cfg(feature = "redis-backend")]
            Self::Redis(l) => l.try_renew(name, ttl_ms).await,
        }
    }
}

// ---------------------------------------------------------------------------
// Redis/Valkey implementation
// ---------------------------------------------------------------------------

/// Redis/Valkey-backed distributed lock.
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

    async fn try_renew(&self, name: &str, ttl_ms: u64) -> bool {
        let key = format!("{}:lock:{}", self.key_prefix, name);
        let mut conn = match self.pool.get().await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(
                    lock = name,
                    error = %e,
                    "Redis pool error renewing lock; proceeding (fail-open)"
                );
                return true;
            }
        };
        // Atomically: if GET(key) == instance_id, then PEXPIRE(key, ttl_ms).
        // Returns 1 on success (we still own it), 0 if someone else owns it or
        // the key has already expired.
        let script = redis::Script::new(
            r"
            if redis.call('GET', KEYS[1]) == ARGV[1] then
                return redis.call('PEXPIRE', KEYS[1], ARGV[2])
            else
                return 0
            end
            ",
        );
        let result: redis::RedisResult<i64> = script
            .key(&key)
            .arg(self.instance_id.as_ref())
            .arg(ttl_ms)
            .invoke_async(&mut *conn)
            .await;
        match result {
            Ok(1) => true,
            Ok(_) => false,
            Err(e) => {
                tracing::warn!(
                    lock = name,
                    error = %e,
                    "Redis lock renewal failed; proceeding (fail-open)"
                );
                true
            }
        }
    }
}
