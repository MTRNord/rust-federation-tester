//! Distributed coordination primitives for horizontal scaling.
//!
//! This module provides three abstractions that allow the server to run as
//! multiple replicas behind a load balancer without sending duplicate alert
//! emails or producing inconsistent failure state.
//!
//! | Primitive | Purpose |
//! |-----------|---------|
//! | [`Registry`] | Shared confirmation failure counts across pods |
//! | [`Lock`] | Ensures only one pod runs a check loop per cycle |
//! | [`EmailGuard`] | Prevents duplicate emails across racing pods |
//!
//! ## Backends
//!
//! Each primitive has two backends selected via the [`Registry`], [`Lock`],
//! and [`EmailGuard`] enums:
//!
//! - **In-memory / Noop** — default, zero external dependencies, suitable
//!   for single-instance deployments.
//! - **Redis/Valkey** — available when the `redis-backend` Cargo feature is
//!   enabled (the default). Activated at runtime by setting `redis.url` in
//!   the configuration.
//!
//! ## Recommended backend: Valkey
//!
//! [Valkey](https://valkey.io/) is the recommended Redis-compatible server.
//! It is BSD-3-Clause licensed (Linux Foundation backed), forked from
//! Redis 7.2 before Redis changed to SSPL/RSALv2. The Rust `redis` crate
//! used here is MIT licensed and fully compatible with Valkey, Redict, and
//! KeyDB as wire-compatible alternatives.
//!
//! ## Usage
//!
//! ```rust,ignore
//! // Single-instance (no Redis needed):
//! let (registry, lock, email_guard) = distributed::in_memory();
//!
//! // Multi-instance (Redis/Valkey required):
//! let (registry, lock, email_guard) = distributed::redis_backed(&config.redis)?;
//! ```
//!
//! ## Fail-open policy
//!
//! All Redis operations degrade gracefully on error: locks return `true`
//! (proceed), registry reads return `None` or empty, email guard returns
//! `true` (allow send). A Redis outage therefore degrades to the original
//! single-instance behaviour at the cost of potential duplicate emails —
//! acceptable for a monitoring tool.

pub mod email_guard;
pub mod lock;
pub mod registry;

pub use email_guard::EmailGuard;
pub use lock::Lock;
pub use registry::Registry;

use crate::config::RedisConfig;

/// Returns the in-memory (single-instance) triplet.
///
/// - [`Registry::InMemory`] — `Arc<Mutex<HashMap>>` confirmation registry
/// - [`Lock::Noop`] — always acquires the lock (no contention)
/// - [`EmailGuard::Noop`] — always allows sending (no deduplication)
///
/// This is the correct choice for single-instance deployments and the default
/// when `redis.url` is not configured.
pub fn in_memory() -> (Registry, Lock, EmailGuard) {
    (
        Registry::InMemory(registry::InMemoryRegistry::new()),
        Lock::Noop,
        EmailGuard::Noop,
    )
}

/// Builds a Redis/Valkey-backed triplet from the provided configuration.
///
/// Creates a shared connection pool used by all three primitives.
/// The `instance_id` uniquely identifies this process in the lock key so that
/// future extensions (e.g. explicit lock release) can verify ownership.
///
/// Returns an error if the connection pool cannot be created (e.g. invalid URL).
/// The pool is lazy — connections are established on first use, not here.
///
/// Only available when the `redis-backend` feature is enabled (the default).
#[cfg(feature = "redis-backend")]
pub fn redis_backed(
    config: &RedisConfig,
) -> Result<(Registry, Lock, EmailGuard), deadpool_redis::CreatePoolError> {
    use uuid::Uuid;

    let pool_cfg = deadpool_redis::Config {
        url: Some(config.url.clone()),
        pool: Some(deadpool_redis::PoolConfig {
            max_size: config.pool_size,
            ..Default::default()
        }),
        connection: None,
    };

    let pool = pool_cfg.create_pool(Some(deadpool_redis::Runtime::Tokio1))?;
    let instance_id = Uuid::new_v4().to_string();

    tracing::info!(
        instance_id = %instance_id,
        url = %config.url,
        pool_size = config.pool_size,
        key_prefix = %config.key_prefix,
        "Created Redis/Valkey connection pool for distributed coordination"
    );

    Ok((
        Registry::Redis(registry::RedisRegistry::new(
            pool.clone(),
            &config.key_prefix,
        )),
        Lock::Redis(lock::RedisLock::new(
            pool.clone(),
            &config.key_prefix,
            instance_id,
        )),
        EmailGuard::Redis(email_guard::RedisEmailGuard::new(
            pool,
            &config.key_prefix,
            config.email_bucket_secs,
        )),
    ))
}
