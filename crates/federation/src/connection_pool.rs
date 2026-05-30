use crate::federation::certificate::extract_certificate_info;
use crate::response::Certificate;
use crate::tls::shared_tls_config_with_alpn;
use bytes::Bytes;
use dashmap::DashMap;
use futures::FutureExt;
use http_body_util::Empty;
use hyper::body::Incoming;
use hyper::client::conn::{http1, http2};
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls_pki_types::ServerName;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::{Duration, timeout};
use tokio_rustls::TlsConnector;

type ConnectionKey = (Arc<str>, Arc<str>); // (addr, sni)
type H1Entry = (http1::SendRequest<Empty<Bytes>>, Arc<TlsConnectionInfo>);
type H2Entry = (http2::SendRequest<Empty<Bytes>>, Arc<TlsConnectionInfo>);

/// Application-layer protocol negotiated via ALPN.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum HttpVersion {
    #[default]
    H1,
    H2,
}

/// TLS and HTTP protocol metadata captured at connection-establishment time.
///
/// Stored alongside pooled connections so callers can report cert and cipher details
/// without re-reading them from a live stream on each request.
#[derive(Debug, Clone, Default)]
pub struct TlsConnectionInfo {
    /// TLS version string, e.g. `"TlsV1_3"`.
    pub protocol: String,
    pub cipher_suite: String,
    pub certificates: Vec<Certificate>,
    pub http_version: HttpVersion,
}

/// A connection handle that abstracts over HTTP/1.1 and HTTP/2.
///
/// HTTP/2 handles are cheap clones of a shared multiplexed connection.
/// HTTP/1.1 handles are exclusive — only one request can be in-flight per handle.
pub enum PooledSender {
    H1(http1::SendRequest<Empty<Bytes>>),
    H2(http2::SendRequest<Empty<Bytes>>),
}

impl PooledSender {
    /// Send a request and return the response.
    ///
    /// For H2, the request URI is automatically converted to absolute form (`https://…`)
    /// if it is relative, because the h2 framing requires an explicit `:scheme` pseudo-header.
    pub async fn send_request(
        &mut self,
        req: Request<Empty<Bytes>>,
    ) -> hyper::Result<Response<Incoming>> {
        match self {
            Self::H1(s) => s.send_request(req).await,
            Self::H2(s) => s.send_request(to_absolute_uri(req)).await,
        }
    }
}

/// Convert a relative-form request URI to absolute `https://host/path` form.
///
/// H2 requires `:scheme` to be set; hyper derives it from the URI scheme.
/// For IPv6 hosts the bare address is wrapped in brackets per RFC 3986 §3.2.2.
/// Returns the request unchanged if the Host header is absent or the URI already
/// has a scheme.
fn to_absolute_uri(req: Request<Empty<Bytes>>) -> Request<Empty<Bytes>> {
    if req.uri().scheme().is_some() {
        return req;
    }
    let Some(host_hdr) = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|h| h.to_str().ok())
    else {
        return req;
    };
    // IPv6 literals need brackets in URIs: "::1" → "[::1]"
    let authority = if host_hdr.contains(':') && !host_hdr.starts_with('[') {
        format!("[{host_hdr}]")
    } else {
        host_hdr.to_string()
    };
    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let Ok(uri) = format!("https://{authority}{path}").parse::<hyper::Uri>() else {
        return req;
    };
    let (mut parts, body) = req.into_parts();
    parts.uri = uri;
    Request::from_parts(parts, body)
}

/// A pool of reusable TLS connections keyed by `(addr, sni)`.
///
/// The pool negotiates the best available protocol via ALPN on every new connection:
/// - **HTTP/2**: a single multiplexed connection is shared across all concurrent callers.
///   Requests are sent by cloning the sender; returning is a no-op.
/// - **HTTP/1.1**: a stack of exclusive idle connections per target.
///   Connections are popped on use and pushed back when returned.
///
/// Per-key and total idle limits apply to H1 connections only; H2 connections
/// are inherently bounded to one per target.
#[derive(Clone)]
pub struct ConnectionPool {
    h1_pools: Arc<DashMap<ConnectionKey, Arc<Mutex<Vec<H1Entry>>>>>,
    h2_senders: Arc<DashMap<ConnectionKey, H2Entry>>,
    max_connections_per_key: usize,
    max_total_connections: usize,
    connection_timeout: Duration,
}

impl ConnectionPool {
    /// Create a pool with the given per-key idle limit and connect timeout.
    pub fn new(max_connections_per_key: usize, connection_timeout_secs: u64) -> Self {
        Self {
            h1_pools: Arc::new(DashMap::new()),
            h2_senders: Arc::new(DashMap::new()),
            max_connections_per_key,
            max_total_connections: max_connections_per_key * 20,
            connection_timeout: Duration::from_secs(connection_timeout_secs),
        }
    }

    /// Get a connection for `(addr, sni)`, reusing an existing one or creating a new one.
    pub async fn get_connection(
        &self,
        addr: &str,
        sni: &str,
    ) -> Result<(PooledSender, Arc<TlsConnectionInfo>), crate::error::FetchError> {
        let key: ConnectionKey = (Arc::from(addr), Arc::from(sni));
        if let Some(conn) = self.try_get_h2(&key) {
            return Ok(conn);
        }
        if let Some(conn) = self.try_get_h1(&key).await {
            return Ok(conn);
        }
        self.enforce_h1_memory_limits().await;
        tracing::debug!(addr, sni, "opening new connection");
        self.create_new_connection(addr, sni, key).await
    }

    fn try_get_h2(&self, key: &ConnectionKey) -> Option<(PooledSender, Arc<TlsConnectionInfo>)> {
        if let Some(entry) = self.h2_senders.get(key) {
            let mut probe = entry.0.clone();
            if probe.ready().now_or_never().is_some_and(|r| r.is_ok()) {
                tracing::debug!(addr = %key.0, sni = %key.1, "reusing pooled H2 connection");
                return Some((PooledSender::H2(entry.0.clone()), Arc::clone(&entry.1)));
            }
            drop(entry);
            self.h2_senders.remove(key);
        }
        None
    }

    async fn try_get_h1(
        &self,
        key: &ConnectionKey,
    ) -> Option<(PooledSender, Arc<TlsConnectionInfo>)> {
        if let Some(pool) = self.h1_pools.get(key) {
            let mut connections = pool.lock().await;
            while let Some((mut sender, tls_info)) = connections.pop() {
                if sender.ready().await.is_ok() {
                    tracing::debug!(addr = %key.0, sni = %key.1, "reusing pooled H1 connection");
                    return Some((PooledSender::H1(sender), tls_info));
                }
            }
        }
        None
    }

    /// Return a connection to the pool for later reuse.
    ///
    /// For H2, this is a no-op: the shared connection remains in the pool regardless.
    /// For H1, the connection is pushed back onto the idle stack if still healthy.
    pub async fn return_connection(
        &self,
        addr: &str,
        sni: &str,
        sender: PooledSender,
        tls_info: Arc<TlsConnectionInfo>,
    ) {
        match sender {
            PooledSender::H2(_) => {
                // The shared H2 sender stays in h2_senders; nothing to do.
            }
            PooledSender::H1(mut h1_sender) => {
                if h1_sender.ready().now_or_never().is_some_and(|r| r.is_ok()) {
                    let key: ConnectionKey = (Arc::from(addr), Arc::from(sni));
                    let pool = self.h1_pools.entry(key).or_insert_with(|| {
                        Arc::new(Mutex::new(Vec::with_capacity(self.max_connections_per_key)))
                    });
                    let mut connections = pool.lock().await;
                    if connections.len() < self.max_connections_per_key {
                        tracing::debug!(addr, sni, "returned H1 connection to pool");
                        connections.push((h1_sender, tls_info));
                    }
                }
            }
        }
    }

    /// Evict dead idle connections. Should be called periodically by a background task.
    pub async fn cleanup_dead_connections(&self) {
        self.cleanup_dead_h1_connections().await;
        self.cleanup_dead_h2_connections();
    }

    async fn cleanup_dead_h1_connections(&self) {
        for entry in self.h1_pools.iter() {
            let mut connections = entry.value().lock().await;
            let before = connections.len();
            let mut healthy = Vec::with_capacity(connections.len());
            for (mut sender, tls_info) in connections.drain(..) {
                if sender.ready().now_or_never().is_some_and(|r| r.is_ok()) {
                    healthy.push((sender, tls_info));
                }
            }
            let removed = before - healthy.len();
            *connections = healthy;
            if removed > 0 {
                tracing::debug!(removed, pool_key = ?entry.key(), "cleaned up dead H1 connections");
            }
        }
    }

    fn cleanup_dead_h2_connections(&self) {
        let dead_keys: Vec<ConnectionKey> = self
            .h2_senders
            .iter()
            .filter_map(|entry| {
                let mut probe = entry.value().0.clone();
                if probe.ready().now_or_never().is_none_or(|r| r.is_err()) {
                    Some(entry.key().clone())
                } else {
                    None
                }
            })
            .collect();
        for key in dead_keys {
            tracing::debug!(pool_key = ?key, "removed dead H2 connection");
            self.h2_senders.remove(&key);
        }
    }

    /// Number of distinct target endpoints with pooled connections.
    pub fn pool_count(&self) -> usize {
        self.h1_pools.len() + self.h2_senders.len()
    }

    /// Pool statistics snapshot for the debug endpoint.
    pub async fn stats(&self) -> ConnectionPoolStats {
        let mut h1_idle = 0;
        for pool in self.h1_pools.iter() {
            h1_idle += pool.lock().await.len();
        }
        ConnectionPoolStats {
            h1_pools_count: self.h1_pools.len(),
            h1_idle_connections: h1_idle,
            h2_connections: self.h2_senders.len(),
            max_connections_per_key: self.max_connections_per_key,
        }
    }

    // ──────────────────────────────────────────────────────────────────────────────
    // Private helpers
    // ──────────────────────────────────────────────────────────────────────────────

    async fn create_new_connection(
        &self,
        addr: &str,
        sni: &str,
        key: ConnectionKey,
    ) -> Result<(PooledSender, Arc<TlsConnectionInfo>), crate::error::FetchError> {
        let sni_host = if sni.starts_with('[') {
            &sni[1..sni.find(']').unwrap_or(sni.len())]
        } else {
            sni.split(':').next().unwrap_or(sni)
        };

        let stream = timeout(self.connection_timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| crate::error::FetchError::Timeout(self.connection_timeout))
            .and_then(|r| r.map_err(|e| crate::error::FetchError::Network(e.to_string())))?;

        let config = shared_tls_config_with_alpn();
        let connector = TlsConnector::from(config);
        let domain = ServerName::try_from(sni_host.to_string())
            .map_err(|_| crate::error::FetchError::InvalidDomain(sni_host.to_string()))?;

        let tls_stream = connector
            .connect(domain, stream)
            .await
            .map_err(|e| crate::error::FetchError::Tls(e.to_string()))?;
        let (_, conn_info) = tls_stream.get_ref();

        let http_version = match conn_info.alpn_protocol() {
            Some(b"h2") => HttpVersion::H2,
            _ => HttpVersion::H1,
        };

        let tls_info = Arc::new(TlsConnectionInfo {
            protocol: conn_info
                .protocol_version()
                .map(|v| format!("{v:?}"))
                .unwrap_or_default(),
            cipher_suite: conn_info
                .negotiated_cipher_suite()
                .map(|c| c.suite().as_str().unwrap_or("unknown").to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            certificates: conn_info
                .peer_certificates()
                .map(|certs| certs.iter().filter_map(extract_certificate_info).collect())
                .unwrap_or_default(),
            http_version: http_version.clone(),
        });

        let io = TokioIo::new(tls_stream);

        if http_version == HttpVersion::H2 {
            let (sender, conn) = http2::handshake(TokioExecutor::new(), io)
                .await
                .map_err(|e| crate::error::FetchError::Network(e.to_string()))?;
            tokio::task::spawn(async move {
                if let Err(err) = conn.await {
                    tracing::warn!(?err, "H2 connection driver ended");
                }
            });
            self.h2_senders
                .insert(key, (sender.clone(), Arc::clone(&tls_info)));
            Ok((PooledSender::H2(sender), tls_info))
        } else {
            let (sender, conn) = http1::handshake(io)
                .await
                .map_err(|e| crate::error::FetchError::Network(e.to_string()))?;
            tokio::task::spawn(async move {
                if let Err(err) = conn.await {
                    tracing::warn!(?err, "H1 connection driver ended");
                }
            });
            Ok((PooledSender::H1(sender), tls_info))
        }
    }

    fn total_h1_connections(&self) -> usize {
        self.h1_pools
            .iter()
            .filter_map(|entry| entry.value().try_lock().ok().map(|c| c.len()))
            .sum()
    }

    async fn enforce_h1_memory_limits(&self) {
        let excess = self
            .total_h1_connections()
            .saturating_sub(self.max_total_connections);
        if excess == 0 {
            return;
        }
        let mut removed = 0;
        for entry in self.h1_pools.iter() {
            if removed >= excess {
                break;
            }
            let mut connections = entry.value().lock().await;
            while !connections.is_empty() && removed < excess {
                connections.pop();
                removed += 1;
            }
        }
        if removed > 0 {
            tracing::debug!(
                removed,
                "evicted H1 idle connections to enforce memory limit"
            );
        }
    }
}

impl Default for ConnectionPool {
    fn default() -> Self {
        Self::new(5, 5)
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionPoolStats {
    pub h1_pools_count: usize,
    pub h1_idle_connections: usize,
    pub h2_connections: usize,
    pub max_connections_per_key: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pool(max_per_key: usize) -> ConnectionPool {
        ConnectionPool::new(max_per_key, 5)
    }

    #[test]
    fn new_sets_expected_limits() {
        let pool = ConnectionPool::new(4, 5);
        assert_eq!(pool.max_connections_per_key, 4);
        assert_eq!(pool.max_total_connections, 80); // 4 * 20
        assert_eq!(pool.connection_timeout, Duration::from_secs(5));
    }

    #[test]
    fn default_creates_pool_with_5_per_key() {
        let pool = ConnectionPool::default();
        assert_eq!(pool.max_connections_per_key, 5);
    }

    #[test]
    fn pool_count_starts_at_zero() {
        let pool = make_pool(5);
        assert_eq!(pool.pool_count(), 0);
    }

    #[test]
    fn total_h1_connections_starts_at_zero() {
        let pool = make_pool(5);
        assert_eq!(pool.total_h1_connections(), 0);
    }

    #[test]
    fn can_create_connection_true_when_empty() {
        let pool = make_pool(5);
        assert!(pool.total_h1_connections() < pool.max_total_connections);
    }

    #[tokio::test]
    async fn stats_returns_zero_counts_for_empty_pool() {
        let pool = make_pool(5);
        let stats = pool.stats().await;
        assert_eq!(stats.h1_pools_count, 0);
        assert_eq!(stats.h1_idle_connections, 0);
        assert_eq!(stats.h2_connections, 0);
        assert_eq!(stats.max_connections_per_key, pool.max_connections_per_key);
    }

    #[tokio::test]
    async fn enforce_h1_memory_limits_noop_when_under_limit() {
        let pool = make_pool(5);
        pool.enforce_h1_memory_limits().await;
    }

    #[tokio::test]
    async fn cleanup_dead_connections_noop_when_empty() {
        let pool = make_pool(5);
        pool.cleanup_dead_connections().await;
    }

    #[test]
    fn to_absolute_uri_adds_scheme_from_host_header() {
        let req = Request::builder()
            .uri("/_matrix/federation/v1/version")
            .header(hyper::header::HOST, "matrix.example.com")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let converted = to_absolute_uri(req);
        assert_eq!(
            converted.uri().to_string(),
            "https://matrix.example.com/_matrix/federation/v1/version"
        );
    }

    #[test]
    fn to_absolute_uri_wraps_ipv6_in_brackets() {
        let req = Request::builder()
            .uri("/_matrix/key/v2/server")
            .header(hyper::header::HOST, "::1")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let converted = to_absolute_uri(req);
        assert_eq!(
            converted.uri().to_string(),
            "https://[::1]/_matrix/key/v2/server"
        );
    }

    #[test]
    fn to_absolute_uri_leaves_absolute_uri_unchanged() {
        let req = Request::builder()
            .uri("https://matrix.example.com/_matrix/federation/v1/version")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let converted = to_absolute_uri(req);
        assert_eq!(
            converted.uri().to_string(),
            "https://matrix.example.com/_matrix/federation/v1/version"
        );
    }
}
