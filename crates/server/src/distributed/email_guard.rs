//! Email idempotency guard.
//!
//! The [`EmailGuard`] abstraction ensures that each alert email (failure,
//! reminder, recovery) is sent at most once per time bucket across all
//! running instances, even if the loop lock fails and multiple pods process
//! the same alert in the same cycle.
//!
//! ## Time buckets
//!
//! The Redis backend divides time into buckets of `bucket_secs` width
//! (default: 3600 s = 1 hour). Each claim key is:
//!
//! ```text
//! {prefix}:email:{alert_id}:{kind}:{bucket}
//! ```
//!
//! where `bucket = unix_timestamp / bucket_secs`. This means:
//! - Failure emails: sent at most once per hour per alert.
//! - Reminder emails: controlled by [`should_send_reminder_email`] (12 h) and
//!   additionally capped to once per bucket by the guard.
//! - Recovery emails: sent at most once per hour per alert.
//!
//! [`should_send_reminder_email`]: crate::alerts::checks::should_send_reminder_email

use time::OffsetDateTime;

/// Email idempotency guard.
///
/// Call [`EmailGuard::try_claim`] before sending an email. If it returns
/// `false`, another instance already sent this email in the current time
/// bucket — skip the send.
#[derive(Clone, Debug)]
pub enum EmailGuard {
    /// Always allows — suitable for single-instance deployments.
    Noop,
    /// Redis/Valkey-backed idempotency guard.
    #[cfg(feature = "redis-backend")]
    Redis(RedisEmailGuard),
}

impl EmailGuard {
    /// Try to claim the right to send an email of `kind` for `alert_id`.
    ///
    /// Returns `true` if this instance should send the email.
    /// Returns `false` if another instance already claimed it this bucket.
    ///
    /// `kind` should identify the email type, e.g. `"failure"`, `"reminder"`,
    /// `"recovery"`. The Redis backend appends a time bucket so the same email
    /// can fire again in a later bucket.
    pub async fn try_claim(&self, alert_id: i32, kind: &str) -> bool {
        match self {
            Self::Noop => true,
            #[cfg(feature = "redis-backend")]
            Self::Redis(g) => g.try_claim(alert_id, kind).await,
        }
    }
}

// ---------------------------------------------------------------------------
// Redis/Valkey implementation
// ---------------------------------------------------------------------------

/// Redis/Valkey-backed email idempotency guard.
///
/// Uses `SET key 1 NX EX ttl` where:
/// - `key = {prefix}:email:{alert_id}:{kind}:{bucket}`
/// - `bucket = unix_timestamp / bucket_secs`
/// - `ttl = 2 * bucket_secs` so the key outlives the bucket
#[cfg(feature = "redis-backend")]
#[derive(Clone, Debug)]
pub struct RedisEmailGuard {
    pool: deadpool_redis::Pool,
    key_prefix: String,
    bucket_secs: u64,
}

#[cfg(feature = "redis-backend")]
impl RedisEmailGuard {
    pub fn new(pool: deadpool_redis::Pool, key_prefix: &str, bucket_secs: u64) -> Self {
        Self {
            pool,
            key_prefix: key_prefix.to_string(),
            bucket_secs,
        }
    }

    // tracing macros expand to `if` blocks that inflate the cognitive complexity
    // score beyond what the three logical branches here actually warrant.
    #[allow(clippy::cognitive_complexity)]
    async fn try_claim(&self, alert_id: i32, kind: &str) -> bool {
        let bucket = OffsetDateTime::now_utc().unix_timestamp().max(0) as u64 / self.bucket_secs;
        let key = format!("{}:email:{}:{}:{}", self.key_prefix, alert_id, kind, bucket);
        let ttl_secs = self.bucket_secs * 2;

        let mut conn = match self.pool.get().await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(
                    alert_id = alert_id,
                    kind = kind,
                    error = %e,
                    "Redis pool error in email guard; proceeding (fail-open)"
                );
                return true;
            }
        };

        // SET key 1 NX EX ttl_secs — returns "OK" if claimed, nil if already exists.
        let result: redis::RedisResult<Option<String>> = redis::cmd("SET")
            .arg(&key)
            .arg("1")
            .arg("NX")
            .arg("EX")
            .arg(ttl_secs)
            .query_async(&mut *conn)
            .await;

        match result {
            Ok(Some(_)) => true,
            Ok(None) => {
                tracing::debug!(
                    alert_id = alert_id,
                    kind = kind,
                    "Email guard: another instance already claimed this send slot"
                );
                false
            }
            Err(e) => {
                tracing::warn!(
                    alert_id = alert_id,
                    kind = kind,
                    error = %e,
                    "Redis SET NX failed in email guard; proceeding (fail-open)"
                );
                true
            }
        }
    }
}
