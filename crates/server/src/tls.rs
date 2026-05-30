use once_cell::sync::OnceCell;
use rustls::{ClientConfig, RootCertStore};
use std::sync::Arc;

static TLS_CONFIG: OnceCell<Arc<ClientConfig>> = OnceCell::new();
static TLS_CONFIG_ALPN: OnceCell<Arc<ClientConfig>> = OnceCell::new();

fn load_root_certs() -> RootCertStore {
    let mut store = RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().expect("could not load platform certs") {
        store.add(cert).unwrap();
    }
    store
}

/// Returns a shared TLS client configuration built from the platform's native root certificates.
///
/// Initialised once; subsequent calls return a clone of the same `Arc`. Used by fallback
/// connection paths that only speak HTTP/1.1.
pub fn shared_tls_config() -> Arc<ClientConfig> {
    TLS_CONFIG
        .get_or_init(|| {
            Arc::new(
                ClientConfig::builder()
                    .with_root_certificates(load_root_certs())
                    .with_no_client_auth(),
            )
        })
        .clone()
}

/// Returns a shared TLS client configuration that advertises HTTP/2 via ALPN.
///
/// Used by the connection pool, which negotiates the best available protocol per connection.
/// Falls back to HTTP/1.1 if the server does not advertise `h2`.
pub fn shared_tls_config_with_alpn() -> Arc<ClientConfig> {
    TLS_CONFIG_ALPN
        .get_or_init(|| {
            let mut config = ClientConfig::builder()
                .with_root_certificates(load_root_certs())
                .with_no_client_auth();
            config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            Arc::new(config)
        })
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_arc_returned_each_call() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let a = shared_tls_config();
        let b = shared_tls_config();
        assert!(Arc::ptr_eq(&a, &b));
    }

    #[test]
    fn alpn_config_has_h2_protocol() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let config = shared_tls_config_with_alpn();
        assert!(config.alpn_protocols.contains(&b"h2".to_vec()));
        assert!(config.alpn_protocols.contains(&b"http/1.1".to_vec()));
    }
}
