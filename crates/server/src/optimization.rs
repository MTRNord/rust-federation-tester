//! Performance optimization utilities for the federation tester
//!
//! This module contains optimized implementations of frequently used operations
//! to improve performance and memory usage.

use once_cell::sync::OnceCell;
use rustls::{ClientConfig, RootCertStore};
use std::sync::Arc;

/// Shared TLS configuration to avoid recreating it for every connection
/// This significantly reduces memory allocations and CPU overhead
static TLS_CONFIG: OnceCell<Arc<ClientConfig>> = OnceCell::new();

/// Get a shared TLS client configuration
/// This avoids rebuilding the root certificate store and config on every connection
pub fn get_shared_tls_config() -> Arc<ClientConfig> {
    TLS_CONFIG
        .get_or_init(|| {
            let mut root_cert_store = RootCertStore::empty();
            root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

            let config = ClientConfig::builder()
                .with_root_certificates(root_cert_store)
                .with_no_client_auth();

            Arc::new(config)
        })
        .clone()
}

/// Optimized string operations to reduce allocations
pub mod string_ops {
    use std::borrow::Cow;

    /// Convert to string only if needed, avoiding unnecessary allocations
    pub fn to_string_if_needed(s: &str) -> Cow<'_, str> {
        Cow::Borrowed(s)
    }

    /// More efficient string concatenation for known small strings
    pub fn format_addr_port(addr: &str, port: u16) -> String {
        let mut result = String::with_capacity(addr.len() + 6); // addr + ':' + port (max 5 digits)
        result.push_str(addr);
        result.push(':');
        result.push_str(&port.to_string());
        result
    }

    /// Format IPv6 address with port efficiently
    pub fn format_ipv6_port(addr: &str, port: u16) -> String {
        let mut result = String::with_capacity(addr.len() + 8); // '[' + addr + ']:' + port
        result.push('[');
        result.push_str(addr);
        result.push_str("]:");
        result.push_str(&port.to_string());
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shared_tls_config() {
        // Initialize crypto provider for tests
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let config1 = get_shared_tls_config();
        let config2 = get_shared_tls_config();

        // Should return the same Arc instance
        assert!(Arc::ptr_eq(&config1, &config2));
    }

    #[test]
    fn test_string_ops() {
        use string_ops::*;

        let result = format_addr_port("192.168.1.1", 8448);
        assert_eq!(result, "192.168.1.1:8448");

        let result = format_ipv6_port("2001:db8::1", 8448);
        assert_eq!(result, "[2001:db8::1]:8448");
    }
}
