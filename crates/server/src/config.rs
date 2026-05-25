use serde::Deserialize;
use std::collections::HashMap;
use std::fmt;
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

#[derive(Deserialize)]
pub struct SmtpConfig {
    /// When false, all email sending and email-dependent routes (alerts, OAuth2) are disabled.
    /// Defaults to true for backward compatibility.
    #[serde(default = "default_smtp_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub server: String,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub from: String,
    /// Timeout in seconds for SMTP connections and commands. Default: 10.
    ///
    /// If the relay does not respond within this time, the send is aborted
    /// and the caller receives an error immediately rather than hanging.
    #[serde(default = "default_smtp_timeout_secs")]
    pub timeout_secs: u64,
}

fn default_smtp_enabled() -> bool {
    true
}

impl Default for SmtpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            server: String::new(),
            port: 0,
            username: String::new(),
            password: String::new(),
            from: String::new(),
            timeout_secs: default_smtp_timeout_secs(),
        }
    }
}

impl fmt::Debug for SmtpConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SmtpConfig")
            .field("enabled", &self.enabled)
            .field("server", &self.server)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .field("from", &self.from)
            .field("timeout_secs", &self.timeout_secs)
            .finish()
    }
}

fn default_smtp_timeout_secs() -> u64 {
    10
}
#[derive(Deserialize)]
pub struct AppConfig {
    pub database_url: String,
    pub listen_addr: Option<String>,
    pub smtp: SmtpConfig,
    pub frontend_url: String,
    pub magic_token_secret: String,
    /// CIDR networks allowed to access debug endpoints. Examples: "127.0.0.1/32", "10.0.0.0/8".
    /// If not provided, defaults to common private & loopback ranges.
    #[serde(default = "default_debug_allowed_nets")]
    pub debug_allowed_nets: Vec<IpNet>,
    /// CIDR networks of trusted reverse proxies. When the direct TCP connection comes from one of
    /// these CIDRs, the rightmost `X-Forwarded-For` value is used as the client IP for
    /// `debug_allowed_nets` checking. If empty (the default), `X-Forwarded-For` is ignored and
    /// only the real connection IP is used.
    #[serde(default)]
    pub trusted_proxy_nets: Vec<IpNet>,
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
    /// URL for the GitHub Sponsors page. When set, a sponsor link is shown in the
    /// OAuth2 consent page footer. Leave unset to hide the sponsoring section.
    #[serde(default)]
    pub github_sponsors_url: Option<String>,
    /// URL for the Liberapay page. When set, a sponsor link is shown in the
    /// OAuth2 consent page footer. Leave unset to hide the sponsoring section.
    #[serde(default)]
    pub liberapay_url: Option<String>,
    /// How many days to retain the email notification log (`email_log` table).
    ///
    /// The log records the type, server, and timestamp of each notification sent.
    /// It is also cleared when a user deletes their account. Set to `0` to disable
    /// automatic pruning (not recommended). Default: 7 days.
    #[serde(default = "default_email_log_retention_days")]
    pub email_log_retention_days: u32,
    /// Per-software release note sources. Keys are lowercase software names (e.g. `"synapse"`).
    ///
    /// See [`ReleaseSourceConfig`] for per-entry fields. When a key is absent, version change
    /// emails include no release-notes link or excerpt (Tier C). When present but no API is
    /// configured, a link to the release page is shown (Tier A). When the API is reachable,
    /// an excerpt is fetched and cached for one hour (Tier B).
    ///
    /// # Example config.yaml
    ///
    /// ```yaml
    /// release_sources:
    ///   synapse:
    ///     release_url_template: "https://github.com/element-hq/synapse/releases/tag/v{version}"
    ///     api_type: "github"
    ///     api_repo: "element-hq/synapse"
    ///   continuwuity:
    ///     release_url_template: "https://forgejo.ellis.link/continuwuation/continuwuity/releases/tag/v{version}"
    ///     api_type: "forgejo"
    ///     api_base_url: "https://forgejo.ellis.link"
    ///     api_repo: "continuwuation/continuwuity"
    /// ```
    #[serde(default)]
    pub release_sources: HashMap<String, ReleaseSourceConfig>,
    /// Optional cap on how many webhook endpoints a single alert may have.
    ///
    /// When `None` (the default), there is no hard limit.
    /// Set to a positive integer to prevent runaway webhook registrations.
    #[serde(default)]
    pub max_webhooks_per_alert: Option<usize>,
}

/// Configuration for fetching release notes for a specific server software.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct ReleaseSourceConfig {
    /// URL template for the release page. Use `{version}` as a placeholder.
    ///
    /// Example: `"https://github.com/element-hq/synapse/releases/tag/v{version}"`
    #[serde(default)]
    pub release_url_template: Option<String>,
    /// API type for fetching a release notes excerpt. Supported values: `"github"`, `"forgejo"`.
    ///
    /// Omit (or set to null) to use link-only mode — a button pointing to `release_url_template`
    /// will be shown but no excerpt will be fetched.
    #[serde(default)]
    pub api_type: Option<String>,
    /// Base URL for self-hosted Forgejo or Gitea instances.
    ///
    /// Not needed for `api_type = "github"` (uses `api.github.com` automatically).
    /// Example: `"https://forgejo.ellis.link"`
    #[serde(default)]
    pub api_base_url: Option<String>,
    /// Repository slug in `"owner/repo"` format.
    ///
    /// Example: `"element-hq/synapse"` or `"continuwuation/continuwuity"`
    #[serde(default)]
    pub api_repo: Option<String>,
}

impl fmt::Debug for AppConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppConfig")
            .field("database_url", &"[REDACTED]")
            .field("smtp", &self.smtp)
            .field("frontend_url", &self.frontend_url)
            .field("magic_token_secret", &"[REDACTED]")
            .field("debug_allowed_nets", &self.debug_allowed_nets)
            .field("statistics", &self.statistics)
            .field("oauth2", &self.oauth2)
            .field("federation_timeout_secs", &self.federation_timeout_secs)
            .field("allow_private_targets", &self.allow_private_targets)
            .field("redis", &self.redis)
            .field("environment_name", &self.environment_name)
            .field("github_sponsors_url", &self.github_sponsors_url)
            .field("liberapay_url", &self.liberapay_url)
            .field("email_log_retention_days", &self.email_log_retention_days)
            .field("release_sources", &self.release_sources)
            .field("max_webhooks_per_alert", &self.max_webhooks_per_alert)
            .finish()
    }
}

#[derive(Deserialize, Clone)]
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

impl fmt::Debug for OAuth2Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuth2Config")
            .field("enabled", &self.enabled)
            .field("issuer_url", &self.issuer_url)
            .field("access_token_lifetime", &self.access_token_lifetime)
            .field("refresh_token_lifetime", &self.refresh_token_lifetime)
            .field("magic_links_enabled", &self.magic_links_enabled)
            .field("account_client_secret", &"[REDACTED]")
            .finish()
    }
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
#[derive(Deserialize, Clone)]
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

impl fmt::Debug for RedisConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedisConfig")
            .field("url", &"[REDACTED]")
            .field("pool_size", &self.pool_size)
            .field("key_prefix", &self.key_prefix)
            .field("healthy_lock_ttl_secs", &self.healthy_lock_ttl_secs)
            .field("active_lock_ttl_secs", &self.active_lock_ttl_secs)
            .field("email_bucket_secs", &self.email_bucket_secs)
            .finish()
    }
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

fn default_email_log_retention_days() -> u32 {
    7
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
            "magic_token_secret must be at least 32 characters".into(),
        ));
    }

    if app.oauth2.enabled && app.oauth2.account_client_secret.is_empty() {
        return Err(ConfigError::Validation(
            "oauth2.account_client_secret must be set when oauth2.enabled = true".into(),
        ));
    }
    if app.smtp.enabled {
        if app.smtp.server.is_empty() {
            return Err(ConfigError::Validation(
                "smtp.server must be set when smtp.enabled = true".into(),
            ));
        }
        if app.smtp.port == 0 {
            return Err(ConfigError::Validation(
                "smtp.port must be > 0 when smtp.enabled = true".into(),
            ));
        }
        if app.smtp.username.is_empty() {
            return Err(ConfigError::Validation(
                "smtp.username must be set when smtp.enabled = true".into(),
            ));
        }
        if app.smtp.password.is_empty() {
            return Err(ConfigError::Validation(
                "smtp.password must be set when smtp.enabled = true".into(),
            ));
        }
        if app.smtp.from.is_empty() {
            return Err(ConfigError::Validation(
                "smtp.from must be set when smtp.enabled = true".into(),
            ));
        }
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

    #[test]
    fn parse_rejects_missing_slash() {
        assert!("192.168.0.0".parse::<IpNet>().is_err());
    }

    #[test]
    fn parse_rejects_invalid_ip() {
        assert!("not.an.ip/24".parse::<IpNet>().is_err());
    }

    #[test]
    fn ipv4_slash32_single_host() {
        let net: IpNet = "10.0.0.1/32".parse().unwrap();
        assert!(net.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(!net.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
    }

    #[test]
    fn ipv6_slash128_single_host() {
        let net: IpNet = "2001:db8::1/128".parse().unwrap();
        assert!(net.contains(&IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap())));
        assert!(!net.contains(&IpAddr::V6("2001:db8::2".parse::<Ipv6Addr>().unwrap())));
    }

    #[test]
    fn cross_family_never_matches() {
        // IPv4 net vs IPv6 address and vice versa
        let v4_net: IpNet = "192.168.1.0/24".parse().unwrap();
        assert!(!v4_net.contains(&IpAddr::V6("::1".parse::<Ipv6Addr>().unwrap())));

        let v6_net: IpNet = "::1/128".parse().unwrap();
        assert!(!v6_net.contains(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    }

    #[test]
    fn ipv6_slash0_matches_all() {
        let net: IpNet = "::/0".parse().unwrap();
        assert!(net.contains(&IpAddr::V6("::1".parse::<Ipv6Addr>().unwrap())));
        assert!(net.contains(&IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap())));
        assert!(net.contains(&IpAddr::V6("fe80::1".parse::<Ipv6Addr>().unwrap())));
    }

    #[test]
    fn ipv6_partial_prefix_boundary() {
        // /48 — matches first 48 bits (6 bytes)
        let net: IpNet = "2001:db8:cafe::/48".parse().unwrap();
        assert!(net.contains(&IpAddr::V6("2001:db8:cafe::1".parse::<Ipv6Addr>().unwrap())));
        assert!(!net.contains(&IpAddr::V6("2001:db8:dead::1".parse::<Ipv6Addr>().unwrap())));
    }

    // ── default_debug_allowed_nets ────────────────────────────────────────────

    #[test]
    fn default_debug_allowed_nets_includes_loopback() {
        let nets = default_debug_allowed_nets();
        let loopback_v4 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let loopback_v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert!(nets.iter().any(|n| n.contains(&loopback_v4)));
        assert!(nets.iter().any(|n| n.contains(&loopback_v6)));
    }

    #[test]
    fn default_debug_allowed_nets_includes_rfc1918() {
        let nets = default_debug_allowed_nets();
        let private_10 = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));
        let private_172 = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1));
        let private_192 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert!(nets.iter().any(|n| n.contains(&private_10)));
        assert!(nets.iter().any(|n| n.contains(&private_172)));
        assert!(nets.iter().any(|n| n.contains(&private_192)));
    }

    #[test]
    fn default_debug_allowed_nets_excludes_public_internet() {
        let nets = default_debug_allowed_nets();
        let public = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert!(!nets.iter().any(|n| n.contains(&public)));
    }

    // ── AppConfig Debug ───────────────────────────────────────────────────────

    #[test]
    fn app_config_debug_redacts_database_url_and_magic_token() {
        let cfg = crate::config::AppConfig {
            database_url: "postgres://user:secret@localhost/db".to_string(),
            listen_addr: None,
            smtp: SmtpConfig::default(),
            frontend_url: "https://app.example.com".to_string(),
            magic_token_secret: "my-super-secret-token-value".to_string(),
            debug_allowed_nets: vec![],
            trusted_proxy_nets: vec![],
            statistics: StatisticsConfig::default(),
            oauth2: OAuth2Config::default(),
            federation_timeout_secs: 3,
            allow_private_targets: false,
            redis: RedisConfig::default(),
            environment_name: None,
            github_sponsors_url: None,
            liberapay_url: None,
            email_log_retention_days: 7,
            release_sources: Default::default(),
            max_webhooks_per_alert: None,
        };
        let debug_str = format!("{cfg:?}");
        assert!(
            !debug_str.contains("postgres://"),
            "database URL should be redacted: {debug_str}"
        );
        assert!(
            !debug_str.contains("my-super-secret"),
            "magic token should be redacted: {debug_str}"
        );
        assert!(
            debug_str.contains("[REDACTED]"),
            "should have redacted placeholder: {debug_str}"
        );
    }

    // ── SmtpConfig ────────────────────────────────────────────────────────────

    #[test]
    fn smtp_config_default_is_disabled() {
        let cfg = SmtpConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.timeout_secs, 10);
    }

    #[test]
    fn smtp_config_debug_redacts_password() {
        let mut cfg = SmtpConfig::default();
        cfg.password = "secret123".to_string();
        let debug_str = format!("{cfg:?}");
        assert!(
            !debug_str.contains("secret123"),
            "password should not appear in debug: {debug_str}"
        );
        assert!(debug_str.contains("[REDACTED]"), "debug: {debug_str}");
    }

    // ── OAuth2Config ──────────────────────────────────────────────────────────

    #[test]
    fn oauth2_config_default_values() {
        let cfg = OAuth2Config::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.access_token_lifetime, 3600);
        assert_eq!(cfg.refresh_token_lifetime, 604800);
        assert!(cfg.magic_links_enabled);
    }

    #[test]
    fn oauth2_config_debug_redacts_secret() {
        let mut cfg = OAuth2Config::default();
        cfg.account_client_secret = "topsecret".to_string();
        let debug_str = format!("{cfg:?}");
        assert!(
            !debug_str.contains("topsecret"),
            "secret should not appear: {debug_str}"
        );
        assert!(debug_str.contains("[REDACTED]"), "debug: {debug_str}");
    }

    // ── StatisticsConfig ──────────────────────────────────────────────────────

    #[test]
    fn statistics_config_default_values() {
        let cfg = StatisticsConfig::default();
        assert!(!cfg.enabled);
        assert!(cfg.prometheus_enabled);
        assert_eq!(cfg.raw_retention_days, 30);
    }

    // ── RedisConfig ───────────────────────────────────────────────────────────

    #[test]
    fn redis_config_default_values() {
        let cfg = RedisConfig::default();
        assert_eq!(cfg.pool_size, 4);
        assert_eq!(cfg.key_prefix, "federation-tester");
        assert_eq!(cfg.healthy_lock_ttl_secs, 360);
        assert_eq!(cfg.active_lock_ttl_secs, 90);
        assert_eq!(cfg.email_bucket_secs, 3600);
    }

    #[test]
    fn redis_config_debug_redacts_url() {
        let mut cfg = RedisConfig::default();
        cfg.url = "redis://:password@localhost:6379".to_string();
        let debug_str = format!("{cfg:?}");
        assert!(
            !debug_str.contains("password"),
            "url should not appear: {debug_str}"
        );
        assert!(debug_str.contains("[REDACTED]"), "debug: {debug_str}");
    }
}
