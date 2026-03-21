use serde::Deserialize;
use std::net::IpAddr;
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Configuration build error: {0}")]
    Build(#[from] config::ConfigError),
    #[error("Invalid configuration: {0}")]
    Validation(String),
}

#[derive(Debug, Deserialize)]
pub struct SmtpConfig {
    pub server: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub from: String,
    /// Timeout in seconds for SMTP connections and commands. Default: 10.
    ///
    /// If the relay does not respond within this time, the send is aborted
    /// and the caller receives an error immediately rather than hanging.
    #[serde(default = "default_smtp_timeout_secs")]
    pub timeout_secs: u64,
}

fn default_smtp_timeout_secs() -> u64 {
    10
}
#[derive(Debug, Deserialize)]
pub struct AppConfig {
    pub database_url: String,
    pub smtp: SmtpConfig,
    pub frontend_url: String,
    pub magic_token_secret: String,
    /// CIDR networks allowed to access debug endpoints. Examples: "127.0.0.1/32", "10.0.0.0/8".
    /// If not provided, defaults to common private & loopback ranges.
    #[serde(default = "default_debug_allowed_nets")]
    pub debug_allowed_nets: Vec<IpNet>,
    #[serde(default)]
    pub statistics: StatisticsConfig,
    #[serde(default)]
    pub oauth2: OAuth2Config,
    /// Network timeout in seconds for individual federation checks (DNS, TLS, HTTP).
    /// Default: 3 seconds — suitable for the public internet.
    /// Increase this for high-latency intranet links (e.g. 10–30).
    #[serde(default = "default_federation_timeout_secs")]
    pub federation_timeout_secs: u64,
    /// When true, the SSRF guard that rejects private/internal IP addresses is disabled.
    ///
    /// **WARNING:** Only enable this for closed-federation / intranet deployments where
    /// the tool is not reachable from untrusted networks. Enabling it on a public-facing
    /// instance allows any user to probe internal network resources via the well-known
    /// delegation mechanism.
    #[serde(default)]
    pub allow_private_targets: bool,
    /// Redis/Valkey connection settings for distributed multi-instance operation.
    ///
    /// Leave unconfigured (empty `url`) for single-instance mode.
    /// See [`RedisConfig`] for details and Valkey as the recommended backend.
    #[serde(default)]
    pub redis: RedisConfig,
    /// Optional label for the deployment environment (e.g. `"staging"` or `"production"`).
    ///
    /// When set, every outgoing email will have its subject prefixed with `[<name>]`
    /// and include a visible banner in the body, making it easy to tell which
    /// environment sent a given alert during debugging.
    ///
    /// Leave unset (the default) to send plain unlabelled emails.
    #[serde(default)]
    pub environment_name: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct OAuth2Config {
    /// Whether OAuth2 is enabled
    #[serde(default)]
    pub enabled: bool,
    /// Base URL for the OAuth2 issuer (e.g., "https://federation-tester.example.com")
    #[serde(default)]
    pub issuer_url: String,
    /// Access token lifetime in seconds (default: 3600 = 1 hour)
    #[serde(default = "default_access_token_lifetime")]
    pub access_token_lifetime: i64,
    /// Refresh token lifetime in seconds (default: 604800 = 7 days)
    #[serde(default = "default_refresh_token_lifetime")]
    pub refresh_token_lifetime: i64,
    /// Whether legacy magic link authentication is enabled (default: true for backward compatibility)
    #[serde(default = "default_magic_links_enabled")]
    pub magic_links_enabled: bool,
    /// Client secret for the built-in account-internal OAuth2 client.
    /// Required when oauth2.enabled = true. Generate with: openssl rand -hex 32
    #[serde(default)]
    pub account_client_secret: String,
}

impl Default for OAuth2Config {
    fn default() -> Self {
        Self {
            enabled: false,
            issuer_url: String::new(),
            access_token_lifetime: default_access_token_lifetime(),
            refresh_token_lifetime: default_refresh_token_lifetime(),
            magic_links_enabled: default_magic_links_enabled(),
            account_client_secret: String::new(),
        }
    }
}

fn default_magic_links_enabled() -> bool {
    true // Enabled by default for backward compatibility
}

fn default_access_token_lifetime() -> i64 {
    3600 // 1 hour
}

fn default_refresh_token_lifetime() -> i64 {
    604800 // 7 days
}

#[derive(Debug, Deserialize, Clone)]
pub struct StatisticsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_prometheus_enabled")]
    pub prometheus_enabled: bool,
    /// Salt used for anonymization hashing. MUST be configured (non-empty) if statistics.enabled && prometheus_enabled.
    #[serde(default)]
    pub anonymization_salt: String,
    #[serde(default = "default_raw_retention_days")]
    pub raw_retention_days: u32,
}

impl Default for StatisticsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            prometheus_enabled: true,
            anonymization_salt: String::new(),
            raw_retention_days: default_raw_retention_days(),
        }
    }
}

// ---------------------------------------------------------------------------
// RedisConfig
// ---------------------------------------------------------------------------

/// Connection settings for a Redis-compatible server used for distributed operation.
///
/// **Recommended backend: [Valkey](https://valkey.io/)** — BSD-3-Clause licensed,
/// Linux Foundation backed (AWS, Google, Oracle). Valkey is a direct fork of
/// Redis 7.2 from before Redis changed to SSPL/RSALv2. Use it instead of Redis
/// for licensing clarity in production.
///
/// When configured, this enables:
/// - Distributed loop locks — only one pod runs alert checks per cycle
/// - Shared confirmation registry — failure counts are consistent across pods
/// - Email idempotency guards — each alert email is sent exactly once
///
/// When `url` is empty the server runs in single-instance mode using in-memory
/// state. All other fields are ignored in that case.
///
/// # Example config.yaml
///
/// ```yaml
/// redis:
///   url: "redis://valkey:6379"  # Valkey recommended; Redis also works
///   pool_size: 4
///   key_prefix: "federation-tester"
/// ```
///
/// Environment override: `REDIS__URL=redis://valkey:6379`
#[derive(Debug, Deserialize, Clone)]
pub struct RedisConfig {
    /// Valkey or Redis connection URL.
    ///
    /// Examples:
    /// - `redis://valkey:6379`            (Valkey — recommended)
    /// - `redis://redis:6379`             (Redis — check licensing)
    /// - `redis://:password@valkey:6379`  (with auth)
    /// - `redis://valkey:6379/1`          (specific database)
    ///
    /// Leave empty (the default) to run in single-instance mode with in-memory
    /// fallback. All other `redis.*` fields are ignored when this is empty.
    #[serde(default)]
    pub url: String,

    /// Connection pool size per instance. Default: 4.
    ///
    /// Each instance opens at most this many connections to Redis/Valkey.
    /// A value of 4 is sufficient for the three background primitives plus
    /// headroom for concurrent alert checks.
    #[serde(default = "default_redis_pool_size")]
    pub pool_size: usize,

    /// Key namespace prefix. Default: `"federation-tester"`.
    ///
    /// All Redis keys written by this application are prefixed with this
    /// value. Useful when sharing a Redis instance across environments
    /// (e.g. `"ft-prod"` vs `"ft-staging"`).
    #[serde(default = "default_redis_key_prefix")]
    pub key_prefix: String,

    /// Lock TTL for the healthy check loop in seconds. Default: 360.
    ///
    /// Should be slightly longer than `CHECK_INTERVAL` (300 s) so the lock
    /// outlives a slow iteration. Short enough that a crashed instance
    /// releases the lock within one extra cycle.
    #[serde(default = "default_healthy_lock_ttl_secs")]
    pub healthy_lock_ttl_secs: u64,

    /// Lock TTL for the active check loop in seconds. Default: 90.
    ///
    /// Should be slightly longer than `ACTIVE_CHECK_INTERVAL` (60 s).
    #[serde(default = "default_active_lock_ttl_secs")]
    pub active_lock_ttl_secs: u64,

    /// Time bucket width for email idempotency keys in seconds. Default: 3600.
    ///
    /// Each email type (failure, reminder, recovery) can fire at most once per
    /// bucket per alert across all instances. The default of one hour means a
    /// reminder email sent at 13:45 cannot be re-sent until 14:00. Since
    /// reminders are governed by a 12-hour interval check, this guard only
    /// matters when the loop lock fails (Redis outage / fail-open).
    #[serde(default = "default_email_bucket_secs")]
    pub email_bucket_secs: u64,
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            pool_size: default_redis_pool_size(),
            key_prefix: default_redis_key_prefix(),
            healthy_lock_ttl_secs: default_healthy_lock_ttl_secs(),
            active_lock_ttl_secs: default_active_lock_ttl_secs(),
            email_bucket_secs: default_email_bucket_secs(),
        }
    }
}

fn default_redis_pool_size() -> usize {
    4
}

fn default_redis_key_prefix() -> String {
    "federation-tester".to_string()
}

fn default_healthy_lock_ttl_secs() -> u64 {
    360 // 6 minutes — slightly longer than CHECK_INTERVAL (5 min)
}

fn default_active_lock_ttl_secs() -> u64 {
    90 // 1.5 minutes — slightly longer than ACTIVE_CHECK_INTERVAL (1 min)
}

fn default_email_bucket_secs() -> u64 {
    3600 // 1 hour
}

fn default_federation_timeout_secs() -> u64 {
    3
}

fn default_prometheus_enabled() -> bool {
    true
}
fn default_raw_retention_days() -> u32 {
    30
}

#[derive(Clone, Debug, Deserialize)]
pub struct IpNet {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl IpNet {
    #[tracing::instrument()]
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix as u32)
                };
                (u32::from(a) & mask) == (u32::from(*b) & mask)
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                let a_bytes = a.octets();
                let b_bytes = b.octets();
                let full_bytes = (self.prefix / 8) as usize;
                let rem_bits = self.prefix % 8;
                if full_bytes > 16 {
                    return false;
                }
                if a_bytes[..full_bytes] != b_bytes[..full_bytes] {
                    return false;
                }
                if rem_bits == 0 {
                    return true;
                }
                let mask = (!0u8) << (8 - rem_bits);
                (a_bytes[full_bytes] & mask) == (b_bytes[full_bytes] & mask)
            }
            _ => false,
        }
    }
}

impl FromStr for IpNet {
    type Err = String;

    #[tracing::instrument()]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (ip_part, prefix_part) = s
            .split_once('/')
            .ok_or_else(|| "CIDR must contain '/'".to_string())?;
        let addr = IpAddr::from_str(ip_part).map_err(|e| format!("Invalid IP: {e}"))?;
        let prefix: u8 = prefix_part
            .parse()
            .map_err(|e| format!("Invalid prefix: {e}"))?;
        let max = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix as u32 > max {
            return Err("Prefix out of range".into());
        }
        Ok(IpNet { addr, prefix })
    }
}

#[tracing::instrument()]
fn default_debug_allowed_nets() -> Vec<IpNet> {
    [
        "127.0.0.1/32",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "::1/128",
        "fc00::/7",
    ]
    .iter()
    .filter_map(|s| s.parse().ok())
    .collect()
}

/// Load application configuration from `config.yaml` + environment overrides.
///
/// Environment variable override convention (current): any var matching the key path
/// separated by double underscores (e.g. `SMTP__PORT`) *without* a prefix will override
/// the file value. A future iteration may introduce a prefix (e.g. `APP__`).
///
/// Returns a `ConfigError` instead of panicking so the caller can decide how to fail.
#[tracing::instrument()]
pub fn load_config() -> Result<AppConfig, ConfigError> {
    use config::{Config, Environment, File};
    let cfg = Config::builder()
        .add_source(File::with_name("config.yaml"))
        .add_source(Environment::default().separator("__"))
        .build()?;

    let app: AppConfig = cfg.try_deserialize()?;

    if app.magic_token_secret.len() < 32 {
        return Err(ConfigError::Validation(
            "magic_token_secret must be at least 16 characters".into(),
        ));
    }

    if app.oauth2.enabled && app.oauth2.account_client_secret.is_empty() {
        return Err(ConfigError::Validation(
            "oauth2.account_client_secret must be set when oauth2.enabled = true".into(),
        ));
    }
    if app.smtp.port == 0 {
        return Err(ConfigError::Validation("smtp.port must be > 0".into()));
    }

    if app.statistics.enabled
        && app.statistics.prometheus_enabled
        && app.statistics.anonymization_salt.is_empty()
    {
        return Err(ConfigError::Validation(
            "statistics.enabled is true and prometheus_enabled is true but anonymization_salt is empty".into(),
        ));
    }

    if app.statistics.enabled && app.statistics.anonymization_salt.len() < 16 {
        return Err(ConfigError::Validation(
            "statistics.anonymization_salt must be at least 16 characters".into(),
        ));
    }

    Ok(app)
}

/// Convenience helper for binaries wanting the old panic-on-error behaviour.
#[tracing::instrument()]
pub fn load_config_or_panic() -> AppConfig {
    let span = tracing::debug_span!("Loading configuration");
    span.in_scope(|| match load_config() {
        Ok(c) => c,
        Err(e) => panic!("Failed to load configuration: {e}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn ipv4_basic_matching() {
        let net: IpNet = "192.168.1.0/24".parse().unwrap();
        assert!(net.contains(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42))));
        assert!(!net.contains(&IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1))));
    }

    #[test]
    fn ipv4_prefix_zero() {
        let net: IpNet = "0.0.0.0/0".parse().unwrap();
        assert!(net.contains(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(net.contains(&IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
    }

    #[test]
    fn ipv6_basic_matching() {
        let net: IpNet = "2001:db8::/32".parse().unwrap();
        assert!(net.contains(&IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap())));
        assert!(!net.contains(&IpAddr::V6("2001:dead::1".parse::<Ipv6Addr>().unwrap())));
    }

    #[test]
    fn ipv6_full_prefix() {
        let net: IpNet = "::1/128".parse().unwrap();
        assert!(net.contains(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!net.contains(&IpAddr::V6("::2".parse::<Ipv6Addr>().unwrap())));
    }

    #[test]
    fn parse_rejects_bad_prefix() {
        assert!("192.168.0.0/33".parse::<IpNet>().is_err());
        assert!("2001:db8::/129".parse::<IpNet>().is_err());
    }
}
