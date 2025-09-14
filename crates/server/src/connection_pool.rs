use crate::optimization::get_shared_tls_config;
use bytes::Bytes;
use dashmap::DashMap;
use futures::FutureExt;
use http_body_util::Empty;
use hyper::client::conn::http1::SendRequest;
use hyper_util::rt::TokioIo;
use rustls_pki_types::ServerName;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::{Duration, timeout};
use tokio_rustls::TlsConnector;
use tracing::{debug, warn};

type ConnectionKey = (Arc<str>, Arc<str>); // (addr, sni) - use Arc<str> for better memory efficiency
type PooledConnection = SendRequest<Empty<Bytes>>;

/// Connection pool for reusing HTTP/1.1 connections with custom SNI
/// This helps avoid repeated TCP handshakes and TLS negotiations
#[derive(Clone)]
pub struct ConnectionPool {
    pools: Arc<DashMap<ConnectionKey, Arc<Mutex<Vec<PooledConnection>>>>>,
    max_connections_per_key: usize,
    max_total_connections: usize,
    connection_timeout: Duration,
}

impl ConnectionPool {
    pub fn new(max_connections_per_key: usize, connection_timeout_secs: u64) -> Self {
        Self {
            pools: Arc::new(DashMap::new()),
            max_connections_per_key,
            max_total_connections: max_connections_per_key * 20, // Reasonable total limit
            connection_timeout: Duration::from_secs(connection_timeout_secs),
        }
    }

    /// Get a connection from the pool or create a new one
    #[tracing::instrument(name = "connection_pool_get", skip(self), fields(addr = %addr, sni = %sni))]
    pub async fn get_connection(
        &self,
        addr: &str,
        sni: &str,
    ) -> color_eyre::eyre::Result<PooledConnection> {
        let key = (Arc::from(addr), Arc::from(sni));

        // Try to get an existing connection from the pool
        if let Some(pool) = self.pools.get(&key) {
            let mut connections = pool.lock().await;
            while let Some(mut conn) = connections.pop() {
                // Test if connection is still alive
                if conn.ready().await.is_ok() {
                    debug!("Reusing pooled connection for {addr} with SNI {sni}");
                    return Ok(conn);
                }
                // Connection is dead, continue to try next one
            }
        }

        // Check memory limits before creating new connection
        if !self.can_create_connection() {
            self.enforce_memory_limits().await;
        }

        // Create new connection
        debug!("Creating new connection for {addr} with SNI {sni}");
        self.create_new_connection(addr, sni).await
    }

    /// Return a connection to the pool for reuse
    #[tracing::instrument(name = "connection_pool_return", skip(self, conn), fields(addr = %addr, sni = %sni))]
    pub async fn return_connection(&self, addr: &str, sni: &str, mut conn: PooledConnection) {
        let key = (Arc::from(addr), Arc::from(sni));

        // Only return connection if it's still ready
        if conn.ready().now_or_never().is_some_and(|r| r.is_ok()) {
            let pool = self.pools.entry(key).or_insert_with(|| {
                Arc::new(Mutex::new(Vec::with_capacity(self.max_connections_per_key)))
            });

            let mut connections = pool.lock().await;
            if connections.len() < self.max_connections_per_key {
                connections.push(conn);
                debug!("Returned connection to pool for {addr} with SNI {sni}");
            }
        }
    }

    async fn create_new_connection(
        &self,
        addr: &str,
        sni: &str,
    ) -> color_eyre::eyre::Result<PooledConnection> {
        let sni_host = sni.split(':').next().unwrap();

        let stream = timeout(self.connection_timeout, TcpStream::connect(addr)).await??;

        // Use shared TLS configuration for better performance
        let config = get_shared_tls_config();
        let connector = TlsConnector::from(config);
        let domain = ServerName::try_from(sni_host.to_string())
            .map_err(|_| color_eyre::eyre::eyre!("Invalid domain name: {}", sni_host))?;

        let tls_stream = connector.connect(domain, stream).await?;
        let io = TokioIo::new(tls_stream);

        let (sender, conn) = hyper::client::conn::http1::handshake(io).await?;

        // Spawn the connection task
        tokio::task::spawn(async move {
            if let Err(err) = conn.await {
                warn!("Connection task failed: {err:#?}");
            }
        });

        Ok(sender)
    }

    /// Clean up dead connections periodically
    /// Should be called by a background task every few minutes
    #[tracing::instrument(name = "connection_pool_cleanup", skip(self))]
    pub async fn cleanup_dead_connections(&self) {
        for entry in self.pools.iter() {
            let pool = entry.value();
            let mut connections = pool.lock().await;
            let initial_count = connections.len();

            // Optimized cleanup: retain only healthy connections
            // This is more efficient than the previous remove/insert approach
            let mut healthy_connections = Vec::with_capacity(connections.len());

            for mut conn in connections.drain(..) {
                if conn.ready().now_or_never().is_some_and(|r| r.is_ok()) {
                    healthy_connections.push(conn);
                }
                // Dead connections are automatically dropped
            }

            *connections = healthy_connections;

            let removed = initial_count - connections.len();
            if removed > 0 {
                debug!(
                    "Cleaned up {} dead connections for {:?}",
                    removed,
                    entry.key()
                );
            }
        }
    }

    /// Get the total number of pooled connections across all keys
    pub fn len(&self) -> usize {
        self.pools.len()
    }

    /// Check if the pool is empty
    pub fn is_empty(&self) -> bool {
        self.pools.is_empty()
    }

    /// Get statistics about the connection pool
    pub async fn stats(&self) -> ConnectionPoolStats {
        let mut total_connections = 0;
        let mut pools_count = 0;

        for pool in self.pools.iter() {
            pools_count += 1;
            let connections = pool.lock().await;
            total_connections += connections.len();
        }

        ConnectionPoolStats {
            pools_count,
            total_connections,
            max_connections_per_key: self.max_connections_per_key,
        }
    }

    /// Get total number of connections across all pools
    fn total_connections(&self) -> usize {
        let mut total = 0;
        for entry in self.pools.iter() {
            if let Ok(connections) = entry.value().try_lock() {
                total += connections.len();
            }
        }
        total
    }

    /// Check if we can create a new connection without exceeding limits
    fn can_create_connection(&self) -> bool {
        self.total_connections() < self.max_total_connections
    }

    /// Force cleanup of excess connections if memory limits are exceeded
    async fn enforce_memory_limits(&self) {
        let total = self.total_connections();
        if total > self.max_total_connections {
            let excess = total - self.max_total_connections;
            let mut removed = 0;

            // Remove connections from pools, starting with largest pools
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
                debug!(
                    "Enforced memory limits: removed {} excess connections",
                    removed
                );
            }
        }
    }
}

impl Default for ConnectionPool {
    fn default() -> Self {
        Self::new(5, 5) // 5 connections per key, 5 second timeout
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionPoolStats {
    pub pools_count: usize,
    pub total_connections: usize,
    pub max_connections_per_key: usize,
}
