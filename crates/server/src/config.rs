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

#[derive(Deserialize)]
pub struct SmtpConfig {
    pub server: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub from: String,
}
#[derive(Deserialize)]
pub struct AppConfig {
    pub database_url: String,
    pub smtp: SmtpConfig,
    pub frontend_url: String,
    pub magic_token_secret: String,
    /// CIDR networks allowed to access debug endpoints. Examples: "127.0.0.1/32", "10.0.0.0/8".
    /// If not provided, defaults to common private & loopback ranges.
    #[serde(default = "default_debug_allowed_nets")]
    pub debug_allowed_nets: Vec<IpNet>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct IpNet {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl IpNet {
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
    if app.smtp.port == 0 {
        return Err(ConfigError::Validation("smtp.port must be > 0".into()));
    }

    Ok(app)
}

/// Convenience helper for binaries wanting the old panic-on-error behaviour.
pub fn load_config_or_panic() -> AppConfig {
    match load_config() {
        Ok(c) => c,
        Err(e) => panic!("Failed to load configuration: {e}"),
    }
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
