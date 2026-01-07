use crate::optimization::get_shared_tls_config;
use bytes::Bytes;
use dashmap::DashMap;
use futures::FutureExt;
use http_body_util::Empty;
use hyper::client::conn::http1::SendRequest;
use hyper_util::rt::TokioIo;
use rustls_pki_types::ServerName;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::{Duration, timeout};
use tokio_rustls::TlsConnector;

type ConnectionKey = (Arc<str>, Arc<str>); // (addr, sni) - use Arc<str> for better memory efficiency
type PooledConnection = SendRequest<Empty<Bytes>>;

/// Track per-client connection usage to prevent DoS attacks
#[derive(Debug)]
struct ClientUsage {
    connection_count: AtomicUsize,
    last_request: AtomicU64, // Unix timestamp
    rate_limit_tokens: AtomicU32,
}

impl ClientUsage {
    fn new() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Self {
            connection_count: AtomicUsize::new(0),
            last_request: AtomicU64::new(now),
            rate_limit_tokens: AtomicU32::new(10), // Start with 10 tokens
        }
    }
}

/// Connection pool for reusing HTTP/1.1 connections with custom SNI
/// This helps avoid repeated TCP handshakes and TLS negotiations
/// Now includes per-client limits to prevent DoS attacks
#[derive(Clone)]
pub struct ConnectionPool {
    pools: Arc<DashMap<ConnectionKey, Arc<Mutex<Vec<PooledConnection>>>>>,
    client_usage: Arc<DashMap<String, ClientUsage>>, // Track per-client usage
    max_connections_per_key: usize,
    max_total_connections: usize,
    max_connections_per_client: usize, // NEW: Per-client limit
    connection_timeout: Duration,
}

impl ConnectionPool {
    pub fn new(max_connections_per_key: usize, connection_timeout_secs: u64) -> Self {
        Self::new_with_limits(
            max_connections_per_key,
            max_connections_per_key * 2,
            connection_timeout_secs,
        )
    }

    pub fn new_with_limits(
        max_connections_per_key: usize,
        max_connections_per_client: usize,
        connection_timeout_secs: u64,
    ) -> Self {
        Self {
            pools: Arc::new(DashMap::new()),
            client_usage: Arc::new(DashMap::new()),
            max_connections_per_key,
            max_total_connections: max_connections_per_key * 20, // Reasonable total limit
            max_connections_per_client,
            connection_timeout: Duration::from_secs(connection_timeout_secs),
        }
    }

    /// Get a connection from the pool or create a new one (backward compatibility)
    #[tracing::instrument(name = "connection_pool_get", skip(self), fields(addr = %addr, sni = %sni))]
    pub async fn get_connection(
        &self,
        addr: &str,
        sni: &str,
    ) -> color_eyre::eyre::Result<PooledConnection> {
        // Use "anonymous" as default client ID for backward compatibility
        self.get_connection_with_client_id(addr, sni, "anonymous")
            .await
    }

    /// Get a connection from the pool or create a new one
    /// Now includes per-client limits to prevent DoS attacks
    #[tracing::instrument(name = "connection_pool_get", skip(self), fields(addr = %addr, sni = %sni, client_id = %client_id))]
    pub async fn get_connection_with_client_id(
        &self,
        addr: &str,
        sni: &str,
        client_id: &str, // IP address or request identifier
    ) -> color_eyre::eyre::Result<PooledConnection> {
        // Check per-client limits first
        if !self.can_client_create_connection(client_id) {
            return Err(color_eyre::eyre::eyre!("Client connection limit exceeded"));
        }

        // Apply rate limiting
        if !self.apply_rate_limit(client_id) {
            return Err(color_eyre::eyre::eyre!("Rate limit exceeded"));
        }

        let key = (Arc::from(addr), Arc::from(sni));

        // Try to get an existing connection from the pool
        if let Some(pool) = self.pools.get(&key) {
            let mut connections = pool.lock().await;
            while let Some(mut conn) = connections.pop() {
                // Test if connection is still alive
                if conn.ready().await.is_ok() {
                    tracing::debug!(
                        name = "connection_pool.reuse",
                        target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                        addr = %addr,
                        sni = %sni,
                        client_id = %client_id,
                        message = "Reusing pooled connection"
                    );
                    self.increment_client_usage(client_id);
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
        tracing::debug!(
            name = "connection_pool.create",
            target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            addr = %addr,
            sni = %sni,
            client_id = %client_id,
            message = "Creating new pooled connection"
        );
        let conn = self.create_new_connection(addr, sni).await?;
        self.increment_client_usage(client_id);
        Ok(conn)
    }

    /// Return a connection to the pool for reuse
    #[tracing::instrument(name = "connection_pool_return", skip(self, conn), fields(addr = %addr, sni = %sni, client_id = %client_id))]
    pub async fn return_connection(
        &self,
        addr: &str,
        sni: &str,
        client_id: &str,
        mut conn: PooledConnection,
    ) {
        let key = (Arc::from(addr), Arc::from(sni));

        // Only return connection if it's still ready
        if conn.ready().now_or_never().is_some_and(|r| r.is_ok()) {
            let pool = self.pools.entry(key).or_insert_with(|| {
                Arc::new(Mutex::new(Vec::with_capacity(self.max_connections_per_key)))
            });

            let mut connections = pool.lock().await;
            if connections.len() < self.max_connections_per_key {
                connections.push(conn);
                tracing::debug!(
                    name = "connection_pool.returned",
                    target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                    addr = %addr,
                    sni = %sni,
                    message = "Returned connection to pool"
                );
            }
        }

        // Decrement client usage when connection is returned to pool or dropped
        self.decrement_client_usage(client_id);
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
                tracing::warn!(
                    name = "connection_pool.conn_task_failed",
                    target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                    error = ?err,
                    message = "Connection task failed"
                );
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
                tracing::debug!(
                    name = "connection_pool.cleanup_removed",
                    target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                    removed = removed,
                    pool_key = ?entry.key(),
                    message = "Cleaned up dead connections"
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

    /// Check if a client can create another connection
    fn can_client_create_connection(&self, client_id: &str) -> bool {
        if let Some(usage) = self.client_usage.get(client_id) {
            usage.connection_count.load(Ordering::Relaxed) < self.max_connections_per_client
        } else {
            true
        }
    }

    /// Apply rate limiting to prevent abuse
    fn apply_rate_limit(&self, client_id: &str) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let usage = self
            .client_usage
            .entry(client_id.to_string())
            .or_insert_with(ClientUsage::new);

        let last_request = usage.last_request.load(Ordering::Relaxed);
        let time_passed = now.saturating_sub(last_request);

        // Refill tokens (1 token per second, max 10)
        let tokens_to_add = (time_passed as u32).min(10);
        let current_tokens = usage.rate_limit_tokens.load(Ordering::Relaxed);
        let new_tokens = (current_tokens + tokens_to_add).min(10);
        usage.rate_limit_tokens.store(new_tokens, Ordering::Relaxed);
        usage.last_request.store(now, Ordering::Relaxed);

        // Consume a token if available
        if new_tokens > 0 {
            usage
                .rate_limit_tokens
                .store(new_tokens - 1, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Increment client connection usage
    fn increment_client_usage(&self, client_id: &str) {
        let usage = self
            .client_usage
            .entry(client_id.to_string())
            .or_insert_with(ClientUsage::new);
        usage.connection_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement client connection usage when connection is returned
    fn decrement_client_usage(&self, client_id: &str) {
        if let Some(usage) = self.client_usage.get(client_id) {
            usage.connection_count.fetch_sub(1, Ordering::Relaxed);
        }
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
                tracing::debug!(
                    name = "connection_pool.enforce_memory_limits",
                    target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                    removed = removed,
                    message = "Enforced memory limits: removed excess connections"
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
