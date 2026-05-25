use crate::federation::certificate::extract_certificate_info;
use crate::optimization::get_shared_tls_config;
use crate::response::Certificate;
use bytes::Bytes;
use dashmap::DashMap;
use futures::FutureExt;
use http_body_util::Empty;
use hyper::client::conn::http1::SendRequest;
use hyper_util::rt::TokioIo;
use rustls_pki_types::ServerName;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::{Duration, timeout};
use tokio_rustls::TlsConnector;

type ConnectionKey = (Arc<str>, Arc<str>); // (addr, sni)
type PooledConnection = (SendRequest<Empty<Bytes>>, Arc<TlsConnectionInfo>);

/// TLS metadata captured at handshake time and stored alongside the pooled connection.
///
/// Reusing a pooled connection means no new TLS handshake, so this cached info is
/// returned to callers (like `fetch_keys`) that need cert/protocol data without paying
/// the cost of a fresh handshake.
#[derive(Debug, Clone, Default)]
pub struct TlsConnectionInfo {
    pub protocol: String,
    pub cipher_suite: String,
    pub certificates: Vec<Certificate>,
}

/// Tracks how many live connections a single client (identified by IP) currently holds.
/// Used to enforce the per-client connection cap and prevent one caller from exhausting
/// the pool.
#[derive(Debug)]
struct ClientUsage {
    connection_count: AtomicUsize,
}

impl ClientUsage {
    fn new() -> Self {
        Self {
            connection_count: AtomicUsize::new(0),
        }
    }
}

/// A pool of reusable HTTP/1.1 connections keyed by `(addr, sni)`.
///
/// Reusing connections avoids repeated TCP handshakes and TLS negotiations when the
/// same target server is checked multiple times. Each unique `(addr, sni)` pair gets
/// its own sub-pool capped at `max_connections_per_key` idle connections.
///
/// ## Limits
/// - **Per-key**: at most `max_connections_per_key` idle connections stored per target.
/// - **Per-client**: a single caller IP may hold at most `max_connections_per_client`
///   live connections at once. Callers that exceed this get an immediate error rather
///   than blocking — this prevents one aggressive client from starving others.
/// - **Total**: at most `max_connections_per_key * 20` idle connections across all
///   targets. Excess connections are evicted when the limit is hit.
#[derive(Clone)]
pub struct ConnectionPool {
    pools: Arc<DashMap<ConnectionKey, Arc<Mutex<Vec<PooledConnection>>>>>,
    /// Live connection count per client IP. Decremented when a connection is returned
    /// or dropped.
    client_usage: Arc<DashMap<String, ClientUsage>>,
    max_connections_per_key: usize,
    max_total_connections: usize,
    max_connections_per_client: usize,
    connection_timeout: Duration,
}

impl ConnectionPool {
    /// Create a pool for the public API request handler.
    ///
    /// `max_connections_per_key` idle connections are kept per target; each client IP
    /// may hold twice that many live connections simultaneously.
    #[tracing::instrument()]
    pub fn new(max_connections_per_key: usize, connection_timeout_secs: u64) -> Self {
        Self::new_with_limits(
            max_connections_per_key,
            max_connections_per_key * 2,
            connection_timeout_secs,
        )
    }

    /// Create a pool for the background alert-check loops.
    ///
    /// All background checks share the single `"anonymous"` client ID, so the
    /// per-client limit is disabled (`usize::MAX`). The per-key and total limits
    /// still apply.
    #[tracing::instrument()]
    pub fn new_for_background_checks(
        max_connections_per_key: usize,
        connection_timeout_secs: u64,
    ) -> Self {
        Self::new_with_limits(max_connections_per_key, usize::MAX, connection_timeout_secs)
    }

    #[tracing::instrument()]
    fn new_with_limits(
        max_connections_per_key: usize,
        max_connections_per_client: usize,
        connection_timeout_secs: u64,
    ) -> Self {
        Self {
            pools: Arc::new(DashMap::new()),
            client_usage: Arc::new(DashMap::new()),
            max_connections_per_key,
            max_total_connections: max_connections_per_key * 20,
            max_connections_per_client,
            connection_timeout: Duration::from_secs(connection_timeout_secs),
        }
    }

    /// Get a connection from the pool or create a new one, returning TLS metadata.
    ///
    /// Uses `"anonymous"` as the client ID. Call [`get_connection_with_client_id`] when
    /// the caller's IP is available to enforce per-client limits.
    #[tracing::instrument(skip(self))]
    pub async fn get_connection(
        &self,
        addr: &str,
        sni: &str,
    ) -> color_eyre::eyre::Result<(SendRequest<Empty<Bytes>>, Arc<TlsConnectionInfo>)> {
        self.get_connection_with_client_id(addr, sni, "anonymous")
            .await
    }

    /// Get a connection from the pool or create a new one, enforcing per-client limits.
    ///
    /// Returns an error immediately if the client has reached `max_connections_per_client`
    /// live connections — this is intentional back-pressure, not a server error.
    ///
    /// The returned `Arc<TlsConnectionInfo>` holds the cert/protocol/cipher data captured
    /// when the connection was originally established. Callers that don't need this can
    /// ignore it but must pass it back to `return_connection` to preserve it in the pool.
    #[tracing::instrument(skip(self))]
    pub async fn get_connection_with_client_id(
        &self,
        addr: &str,
        sni: &str,
        client_id: &str,
    ) -> color_eyre::eyre::Result<(SendRequest<Empty<Bytes>>, Arc<TlsConnectionInfo>)> {
        if !self.client_within_limit(client_id) {
            return Err(color_eyre::eyre::eyre!("Client connection limit exceeded"));
        }

        let key = (Arc::from(addr), Arc::from(sni));

        // Try to reuse an idle connection from the pool.
        if let Some(pool) = self.pools.get(&key) {
            let mut connections = pool.lock().await;
            while let Some((mut sender, tls_info)) = connections.pop() {
                if sender.ready().await.is_ok() {
                    tracing::debug!(addr, sni, client_id, "reusing pooled connection");
                    self.increment_client_usage(client_id);
                    return Ok((sender, tls_info));
                }
                // Connection is dead — discard and try the next one.
            }
        }

        // Evict excess idle connections before opening a new one.
        if !self.can_create_connection() {
            self.enforce_memory_limits().await;
        }

        tracing::debug!(addr, sni, client_id, "creating new pooled connection");
        let (sender, tls_info) = self.create_new_connection(addr, sni).await?;
        self.increment_client_usage(client_id);
        Ok((sender, tls_info))
    }

    /// Return a connection to the pool so it can be reused by the next caller.
    ///
    /// `tls_info` must be the value returned by `get_connection` / `get_connection_with_client_id`
    /// so the TLS metadata is preserved for the next caller that needs it.
    ///
    /// Uses `now_or_never()` rather than `.await` on the readiness check deliberately:
    /// we don't want to block the caller while probing a connection that might be slow
    /// to signal health. If it isn't immediately ready we simply discard it.
    #[tracing::instrument(skip(self, sender))]
    pub async fn return_connection(
        &self,
        addr: &str,
        sni: &str,
        client_id: &str,
        mut sender: SendRequest<Empty<Bytes>>,
        tls_info: Arc<TlsConnectionInfo>,
    ) {
        if sender.ready().now_or_never().is_some_and(|r| r.is_ok()) {
            let key = (Arc::from(addr), Arc::from(sni));
            let pool = self.pools.entry(key).or_insert_with(|| {
                Arc::new(Mutex::new(Vec::with_capacity(self.max_connections_per_key)))
            });

            let mut connections = pool.lock().await;
            if connections.len() < self.max_connections_per_key {
                tracing::debug!(addr, sni, "returned connection to pool");
                connections.push((sender, tls_info));
            }
        }

        self.decrement_client_usage(client_id);
    }

    /// Drop dead idle connections from every sub-pool.
    ///
    /// Should be called periodically by a background task.
    #[tracing::instrument(skip(self))]
    pub async fn cleanup_dead_connections(&self) {
        for entry in self.pools.iter() {
            let pool = entry.value();
            let mut connections = pool.lock().await;
            let before = connections.len();

            let mut healthy = Vec::with_capacity(connections.len());
            for (mut sender, tls_info) in connections.drain(..) {
                if sender.ready().now_or_never().is_some_and(|r| r.is_ok()) {
                    healthy.push((sender, tls_info));
                }
            }
            *connections = healthy;

            let removed = before - connections.len();
            if removed > 0 {
                tracing::debug!(removed, pool_key = ?entry.key(), "cleaned up dead connections");
            }
        }
    }

    /// Number of distinct `(addr, sni)` sub-pools currently tracked.
    ///
    /// This is the number of unique target endpoints that have had connections opened,
    /// not the total number of idle connections. Use [`stats`] for full counts.
    #[tracing::instrument(skip(self))]
    pub fn pool_count(&self) -> usize {
        self.pools.len()
    }

    /// Connection pool statistics for the debug endpoint.
    #[tracing::instrument(skip(self))]
    pub async fn stats(&self) -> ConnectionPoolStats {
        let mut total_connections = 0;
        let mut pools_count = 0;

        for pool in self.pools.iter() {
            pools_count += 1;
            total_connections += pool.lock().await.len();
        }

        ConnectionPoolStats {
            pools_count,
            total_connections,
            max_connections_per_key: self.max_connections_per_key,
        }
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /// Total number of idle connections across all sub-pools.
    ///
    /// Uses `try_lock` to avoid blocking — pools that are currently locked are skipped,
    /// so the count is approximate. Good enough for the memory-limit heuristic.
    fn total_connections(&self) -> usize {
        self.pools
            .iter()
            .filter_map(|entry| entry.value().try_lock().ok().map(|c| c.len()))
            .sum()
    }

    fn can_create_connection(&self) -> bool {
        self.total_connections() < self.max_total_connections
    }

    /// Returns `true` if the client has not yet reached the per-client connection cap.
    fn client_within_limit(&self, client_id: &str) -> bool {
        self.client_usage.get(client_id).is_none_or(|u| {
            u.connection_count.load(Ordering::Relaxed) < self.max_connections_per_client
        })
    }

    fn increment_client_usage(&self, client_id: &str) {
        self.client_usage
            .entry(client_id.to_string())
            .or_insert_with(ClientUsage::new)
            .connection_count
            .fetch_add(1, Ordering::Relaxed);
    }

    fn decrement_client_usage(&self, client_id: &str) {
        if let Some(usage) = self.client_usage.get(client_id) {
            usage.connection_count.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Open a fresh TCP + TLS connection, capturing TLS metadata, and complete the HTTP/1.1 handshake.
    #[tracing::instrument(skip(self))]
    async fn create_new_connection(
        &self,
        addr: &str,
        sni: &str,
    ) -> color_eyre::eyre::Result<(SendRequest<Empty<Bytes>>, Arc<TlsConnectionInfo>)> {
        // Strip brackets and port to get the bare hostname for SNI.
        let sni_host = if sni.starts_with('[') {
            &sni[1..sni.find(']').unwrap_or(sni.len())]
        } else {
            sni.split(':').next().unwrap_or(sni)
        };

        let stream = timeout(self.connection_timeout, TcpStream::connect(addr)).await??;

        let config = get_shared_tls_config();
        let connector = TlsConnector::from(config);
        let domain = ServerName::try_from(sni_host.to_string())
            .map_err(|_| color_eyre::eyre::eyre!("Invalid domain name: {}", sni_host))?;

        let tls_stream = connector.connect(domain, stream).await?;

        // Capture TLS metadata before consuming the stream into TokioIo.
        let (_, conn_info) = tls_stream.get_ref();
        let protocol = conn_info
            .protocol_version()
            .map(|v| format!("{v:?}"))
            .unwrap_or_default();
        let cipher_suite = conn_info
            .negotiated_cipher_suite()
            .map(|c| c.suite().as_str().unwrap_or("unknown").to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let certificates = conn_info
            .peer_certificates()
            .map(|certs| certs.iter().filter_map(extract_certificate_info).collect())
            .unwrap_or_default();
        let tls_info = Arc::new(TlsConnectionInfo {
            protocol,
            cipher_suite,
            certificates,
        });

        let io = TokioIo::new(tls_stream);

        let (sender, conn) = hyper::client::conn::http1::handshake(io).await?;

        tokio::task::spawn(async move {
            if let Err(err) = conn.await {
                tracing::warn!(?err, "connection driver task failed");
            }
        });

        Ok((sender, tls_info))
    }

    /// Evict idle connections until we are back within `max_total_connections`.
    ///
    /// Iterates sub-pools in DashMap iteration order (effectively arbitrary) and pops
    /// connections until enough have been removed. Not perfectly fair across pools but
    /// simple and lock-safe.
    #[tracing::instrument(skip(self))]
    async fn enforce_memory_limits(&self) {
        let excess = self
            .total_connections()
            .saturating_sub(self.max_total_connections);
        if excess == 0 {
            return;
        }

        let mut removed = 0;
        for entry in self.pools.iter() {
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
            tracing::debug!(removed, "evicted idle connections to enforce memory limit");
        }
    }
}

impl Default for ConnectionPool {
    fn default() -> Self {
        Self::new(5, 5) // 5 connections per target, 5-second connect timeout
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionPoolStats {
    pub pools_count: usize,
    pub total_connections: usize,
    pub max_connections_per_key: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pool(max_per_key: usize, max_per_client: usize) -> ConnectionPool {
        ConnectionPool::new_with_limits(max_per_key, max_per_client, 5)
    }

    // ── constructors ──────────────────────────────────────────────────────────

    #[test]
    fn new_sets_expected_limits() {
        let pool = ConnectionPool::new(4, 5);
        assert_eq!(pool.max_connections_per_key, 4);
        assert_eq!(pool.max_connections_per_client, 8); // 4 * 2
        assert_eq!(pool.max_total_connections, 80); // 4 * 20
    }

    #[test]
    fn new_for_background_checks_disables_client_limit() {
        let pool = ConnectionPool::new_for_background_checks(3, 5);
        assert_eq!(pool.max_connections_per_client, usize::MAX);
    }

    #[test]
    fn default_creates_pool_with_5_per_key() {
        let pool = ConnectionPool::default();
        assert_eq!(pool.max_connections_per_key, 5);
    }

    // ── pool_count / total_connections ────────────────────────────────────────

    #[test]
    fn pool_count_starts_at_zero() {
        let pool = ConnectionPool::default();
        assert_eq!(pool.pool_count(), 0);
    }

    #[test]
    fn total_connections_starts_at_zero() {
        let pool = ConnectionPool::default();
        assert_eq!(pool.total_connections(), 0);
    }

    #[test]
    fn can_create_connection_true_when_empty() {
        let pool = ConnectionPool::default();
        assert!(pool.can_create_connection());
    }

    // ── client usage tracking ─────────────────────────────────────────────────

    #[test]
    fn client_within_limit_true_for_new_client() {
        let pool = make_pool(5, 3);
        assert!(pool.client_within_limit("new-client"));
    }

    #[test]
    fn client_within_limit_false_when_limit_reached() {
        let pool = make_pool(5, 2);
        pool.increment_client_usage("client-a");
        pool.increment_client_usage("client-a");
        assert!(!pool.client_within_limit("client-a"));
    }

    #[test]
    fn increment_and_decrement_client_usage() {
        let pool = make_pool(5, 10);
        pool.increment_client_usage("c");
        pool.increment_client_usage("c");
        // 2 live connections — within limit of 10
        assert!(pool.client_within_limit("c"));
        pool.decrement_client_usage("c");
        pool.decrement_client_usage("c");
        // back to 0
        assert!(pool.client_within_limit("c"));
    }

    #[test]
    fn decrement_nonexistent_client_is_noop() {
        let pool = ConnectionPool::default();
        pool.decrement_client_usage("ghost"); // should not panic
    }

    // ── stats ─────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn stats_returns_zero_counts_for_empty_pool() {
        let pool = ConnectionPool::default();
        let stats = pool.stats().await;
        assert_eq!(stats.pools_count, 0);
        assert_eq!(stats.total_connections, 0);
        assert_eq!(stats.max_connections_per_key, pool.max_connections_per_key);
    }

    // ── enforce_memory_limits no-op on empty pool ─────────────────────────────

    #[tokio::test]
    async fn enforce_memory_limits_noop_when_under_limit() {
        let pool = ConnectionPool::default();
        pool.enforce_memory_limits().await; // should not panic
    }

    // ── cleanup_dead_connections on empty pool ────────────────────────────────

    #[tokio::test]
    async fn cleanup_dead_connections_noop_when_empty() {
        let pool = ConnectionPool::default();
        pool.cleanup_dead_connections().await; // should not panic
    }
}
