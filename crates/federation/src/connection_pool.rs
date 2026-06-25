use crate::federation::certificate::extract_certificate_info;
use crate::response::Certificate;
use crate::tls::{shared_tls_config, shared_tls_config_with_alpn};
use bytes::Bytes;
use dashmap::DashMap;
use futures::FutureExt;
use http_body_util::Empty;
use hyper::body::Incoming;
use hyper::client::conn::{http1, http2};
use hyper::{Request, Response};
use hyper_util::client::pool::singleton::Singleton;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls_pki_types::ServerName;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::{Duration, timeout};
use tokio_rustls::TlsConnector;
use tower::Service;
use tower::ServiceExt;

type ConnectionKey = (Arc<str>, Arc<str>); // (addr, sni)
type H1IdleSlot = Arc<Mutex<Option<(http1::SendRequest<Empty<Bytes>>, Arc<TlsConnectionInfo>)>>>;

/// Application-layer protocol negotiated via ALPN.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum HttpVersion {
    #[default]
    H1,
    H2,
}

/// TLS and HTTP protocol metadata captured at connection-establishment time.
#[derive(Debug, Clone, Default)]
pub struct TlsConnectionInfo {
    /// TLS version string, e.g. `"TlsV1_3"`.
    pub protocol: String,
    pub cipher_suite: String,
    pub certificates: Vec<Certificate>,
    pub http_version: HttpVersion,
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
    // In HTTP/2 the :authority pseudo-header is derived from the URI above.
    // Keeping an explicit Host header alongside it causes nginx (and others) to
    // reject the request with HTTP 400 "duplicate authority".
    parts.headers.remove(hyper::header::HOST);
    Request::from_parts(parts, body)
}

// ──────────────────────────────────────────────────────────────────────────────
// H2 pool via hyper_util::client::pool::Singleton
// ──────────────────────────────────────────────────────────────────────────────

/// A `tower::Service` wrapper for `http2::SendRequest`.
///
/// Required so that `Singled<H2Sender>` satisfies the `Service<Request<B>>`
/// bound — `hyper::http2::SendRequest` is not itself a `tower::Service`.
/// Clone delegates to hyper's multiplexed-sender clone (cheap, shares connection).
#[derive(Clone)]
struct H2Sender(http2::SendRequest<Empty<Bytes>>);

impl Service<Request<Empty<Bytes>>> for H2Sender {
    type Response = Response<Incoming>;
    type Error = hyper::Error;
    type Future = Pin<Box<dyn Future<Output = hyper::Result<Response<Incoming>>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), hyper::Error>> {
        // Delegates to hyper's H2 capacity check.
        // When the connection dies, this returns Poll::Ready(Err(_)), which
        // Singled observes and uses to clear the Singleton state back to Empty.
        self.0.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Empty<Bytes>>) -> Self::Future {
        Box::pin(self.0.send_request(req))
    }
}

/// A make-service that establishes a single multiplexed HTTP/2 connection.
#[derive(Clone)]
struct H2Maker {
    addr: String,
    sni_host: String,
    /// Populated during the TLS handshake; read by the pool after the future resolves.
    tls_info_cell: Arc<std::sync::Mutex<Option<Arc<TlsConnectionInfo>>>>,
    connection_timeout: Duration,
}

impl Service<()> for H2Maker {
    type Response = H2Sender;
    type Error = crate::error::FetchError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _: ()) -> Self::Future {
        let addr = self.addr.clone();
        let sni_host = self.sni_host.clone();
        let tls_info_cell = Arc::clone(&self.tls_info_cell);
        let conn_timeout = self.connection_timeout;
        Box::pin(connect_h2(addr, sni_host, tls_info_cell, conn_timeout))
    }
}

async fn connect_h2(
    addr: String,
    sni_host: String,
    tls_info_cell: Arc<std::sync::Mutex<Option<Arc<TlsConnectionInfo>>>>,
    conn_timeout: Duration,
) -> Result<H2Sender, crate::error::FetchError> {
    let stream = timeout(conn_timeout, TcpStream::connect(&addr))
        .await
        .map_err(|_| crate::error::FetchError::Timeout(conn_timeout))
        .and_then(|r| r.map_err(|e| crate::error::FetchError::Network(e.to_string())))?;

    let config = shared_tls_config_with_alpn();
    let connector = TlsConnector::from(config);
    let domain = ServerName::try_from(sni_host.clone())
        .map_err(|_| crate::error::FetchError::InvalidDomain(sni_host.clone()))?;

    let tls_stream = connector
        .connect(domain, stream)
        .await
        .map_err(|e| crate::error::FetchError::Tls(e.to_string()))?;

    let (_, conn_info) = tls_stream.get_ref();
    let is_h2 = conn_info.alpn_protocol() == Some(b"h2");
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
        http_version: if is_h2 {
            HttpVersion::H2
        } else {
            HttpVersion::H1
        },
    });
    *tls_info_cell.lock().unwrap() = Some(Arc::clone(&tls_info));

    if !is_h2 {
        return Err(crate::error::FetchError::Network(
            "server does not support H2 (H1 detected via ALPN)".into(),
        ));
    }

    let io = TokioIo::new(tls_stream);
    let (sender, conn) = http2::handshake(TokioExecutor::new(), io)
        .await
        .map_err(|e| crate::error::FetchError::Network(e.to_string()))?;
    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            tracing::warn!(?err, "H2 connection driver ended");
        }
    });
    Ok(H2Sender(sender))
}

struct H2PoolEntry {
    singleton: Singleton<H2Maker, ()>,
    tls_info_cell: Arc<std::sync::Mutex<Option<Arc<TlsConnectionInfo>>>>,
    known_h1: bool,
}

impl H2PoolEntry {
    fn new(addr: &str, sni_host: &str, connection_timeout: Duration) -> Self {
        let tls_info_cell = Arc::new(std::sync::Mutex::new(None));
        let maker = H2Maker {
            addr: addr.to_string(),
            sni_host: sni_host.to_string(),
            tls_info_cell: Arc::clone(&tls_info_cell),
            connection_timeout,
        };
        Self {
            singleton: Singleton::new(maker),
            tls_info_cell,
            known_h1: false,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// NegotiatingService: combined H2 + H1 per-target service
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct NegotiatingService {
    h2_entry: Arc<Mutex<H2PoolEntry>>,
    h1_idle: H1IdleSlot,
    addr: Arc<str>,
    sni_host: Arc<str>,
    connection_timeout: Duration,
}

impl NegotiatingService {
    fn new(addr: Arc<str>, sni_host: Arc<str>, connection_timeout: Duration) -> Self {
        let h2_pool_entry = H2PoolEntry::new(&addr, &sni_host, connection_timeout);
        Self {
            h2_entry: Arc::new(Mutex::new(h2_pool_entry)),
            h1_idle: Arc::new(Mutex::new(None)),
            addr,
            sni_host,
            connection_timeout,
        }
    }

    async fn cleanup(&self) {
        {
            let mut entry = self.h2_entry.lock().await;
            entry.singleton.retain(|sender| {
                let mut probe = sender.0.clone();
                !matches!(probe.ready().now_or_never(), Some(Err(_)))
            });
        }
        {
            let mut slot = self.h1_idle.lock().await;
            if let Some((ref mut sender, _)) = *slot
                && matches!(sender.ready().now_or_never(), Some(Err(_)))
            {
                *slot = None;
            }
        }
    }
}

impl Service<Request<Empty<Bytes>>> for NegotiatingService {
    type Response = (Response<Incoming>, Arc<TlsConnectionInfo>);
    type Error = crate::error::FetchError;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Empty<Bytes>>) -> Self::Future {
        let h2_entry = Arc::clone(&self.h2_entry);
        let h1_idle = Arc::clone(&self.h1_idle);
        let addr = Arc::clone(&self.addr);
        let sni_host = Arc::clone(&self.sni_host);
        let conn_timeout = self.connection_timeout;

        Box::pin(async move {
            let h1_req = clone_request(&req);
            if let Some(result) = try_h2_send(&h2_entry, req, &addr).await {
                return Ok(result);
            }
            send_h1(&h1_idle, &addr, &sni_host, conn_timeout, h1_req).await
        })
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Free functions used by NegotiatingService
// ──────────────────────────────────────────────────────────────────────────────

/// Try to send `req` over H2. Returns `Some` on success, `None` to fall back to H1.
async fn try_h2_send(
    h2_entry: &Arc<Mutex<H2PoolEntry>>,
    req: Request<Empty<Bytes>>,
    addr: &str,
) -> Option<(Response<Incoming>, Arc<TlsConnectionInfo>)> {
    let (singleton_future, tls_info_arc) = {
        let mut entry = h2_entry.lock().await;
        if entry.known_h1 {
            return None;
        }
        (
            Service::call(&mut entry.singleton, ()),
            Arc::clone(&entry.tls_info_cell),
        )
        // Lock released here.
    };

    let singled = match singleton_future.await {
        Ok(s) => s,
        Err(e) => {
            on_h2_singleton_failure(h2_entry, &tls_info_arc, e, addr).await;
            return None;
        }
    };

    let tls_info = tls_info_arc.lock().unwrap().clone().unwrap_or_default();
    dispatch_h2_request(singled, to_absolute_uri(req), tls_info, addr).await
}

async fn on_h2_singleton_failure(
    h2_entry: &Arc<Mutex<H2PoolEntry>>,
    tls_info_arc: &Arc<std::sync::Mutex<Option<Arc<TlsConnectionInfo>>>>,
    err: impl std::fmt::Display,
    addr: &str,
) {
    let is_h1 = tls_info_arc
        .lock()
        .unwrap()
        .as_ref()
        .map(|ti| ti.http_version == HttpVersion::H1)
        .unwrap_or(false);
    if is_h1 {
        h2_entry.lock().await.known_h1 = true;
        tracing::debug!(addr, "H1 detected via ALPN");
    } else {
        tracing::debug!(addr, error = %err, "H2 Singleton failed; falling back to H1");
    }
}

async fn dispatch_h2_request<S>(
    mut singled: S,
    req: Request<Empty<Bytes>>,
    tls_info: Arc<TlsConnectionInfo>,
    addr: &str,
) -> Option<(Response<Incoming>, Arc<TlsConnectionInfo>)>
where
    S: tower::Service<Request<Empty<Bytes>>, Response = Response<Incoming>, Error = hyper::Error>,
    S::Future: Send,
{
    if let Err(e) = singled.ready().await {
        tracing::debug!(addr, error = %e, "H2 connection died; falling back to H1");
        return None;
    }
    match singled.call(req).await {
        Ok(resp) => Some((resp, tls_info)),
        Err(e) => {
            tracing::debug!(addr, error = %e, "H2 send failed; falling back to H1");
            None
        }
    }
}

/// Send `req` over H1, reusing an idle connection when available.
async fn send_h1(
    h1_idle: &H1IdleSlot,
    addr: &str,
    sni_host: &str,
    conn_timeout: Duration,
    req: Request<Empty<Bytes>>,
) -> Result<(Response<Incoming>, Arc<TlsConnectionInfo>), crate::error::FetchError> {
    let (mut sender, tls_info) = match take_idle_h1(h1_idle).await {
        Some(entry) => entry,
        None => {
            tracing::debug!(addr, "opening new H1 connection");
            make_fresh_h1_connection(addr, sni_host, conn_timeout).await?
        }
    };
    let resp = sender
        .send_request(req)
        .await
        .map_err(|e| crate::error::FetchError::Network(e.to_string()))?;
    return_h1_if_alive(h1_idle, sender, Arc::clone(&tls_info)).await;
    Ok((resp, tls_info))
}

async fn take_idle_h1(
    h1_idle: &H1IdleSlot,
) -> Option<(http1::SendRequest<Empty<Bytes>>, Arc<TlsConnectionInfo>)> {
    let mut slot = h1_idle.lock().await;
    if let Some((mut s, ti)) = slot.take()
        && s.ready().now_or_never().is_some_and(|r| r.is_ok())
    {
        return Some((s, ti));
    }
    None
}

async fn return_h1_if_alive(
    h1_idle: &H1IdleSlot,
    mut sender: http1::SendRequest<Empty<Bytes>>,
    tls_info: Arc<TlsConnectionInfo>,
) {
    if sender.ready().now_or_never().is_some_and(|r| r.is_ok()) {
        let mut slot = h1_idle.lock().await;
        if slot.is_none() {
            *slot = Some((sender, tls_info));
        }
    }
}

fn clone_request(req: &Request<Empty<Bytes>>) -> Request<Empty<Bytes>> {
    let mut builder = Request::builder()
        .method(req.method().clone())
        .uri(req.uri().clone())
        .version(req.version());
    for (name, value) in req.headers() {
        builder = builder.header(name, value);
    }
    builder.body(Empty::new()).expect("valid request parts")
}

// ──────────────────────────────────────────────────────────────────────────────
// Connection pool
// ──────────────────────────────────────────────────────────────────────────────

/// A pool of reusable TLS connections keyed by `(addr, sni)`.
///
/// Each entry holds a [`NegotiatingService`] that manages H2 (via `Singleton`)
/// with a single idle H1 slot for keep-alive fallback.
#[derive(Clone)]
pub struct ConnectionPool {
    services: Arc<DashMap<ConnectionKey, NegotiatingService>>,
    connection_timeout: Duration,
}

impl ConnectionPool {
    /// Create a pool with the given connect timeout.
    pub fn new(connection_timeout_secs: u64) -> Self {
        Self {
            services: Arc::new(DashMap::new()),
            connection_timeout: Duration::from_secs(connection_timeout_secs),
        }
    }

    /// Send `req` to `(addr, sni)`, reusing or creating a connection as needed.
    pub async fn send(
        &self,
        addr: &str,
        sni: &str,
        req: Request<Empty<Bytes>>,
    ) -> Result<(Response<Incoming>, Arc<TlsConnectionInfo>), crate::error::FetchError> {
        let sni_host = extract_sni_host(sni);
        let key: ConnectionKey = (Arc::from(addr), Arc::from(sni));
        let mut svc = {
            let e = self.services.entry(key).or_insert_with(|| {
                NegotiatingService::new(
                    Arc::from(addr),
                    Arc::from(sni_host.as_str()),
                    self.connection_timeout,
                )
            });
            e.clone()
        };
        svc.call(req).await
    }

    /// Evict dead idle connections. Should be called periodically by a background task.
    pub async fn cleanup_dead_connections(&self) {
        let entries: Vec<NegotiatingService> =
            self.services.iter().map(|e| e.value().clone()).collect();
        for svc in entries {
            svc.cleanup().await;
        }
    }

    /// Number of distinct target endpoints with pooled connections.
    pub fn pool_count(&self) -> usize {
        self.services.len()
    }

    /// Pool statistics snapshot for the debug endpoint.
    pub async fn stats(&self) -> ConnectionPoolStats {
        let entries: Vec<NegotiatingService> =
            self.services.iter().map(|e| e.value().clone()).collect();
        let mut h1_idle_connections = 0;
        for svc in entries {
            if svc.h1_idle.lock().await.is_some() {
                h1_idle_connections += 1;
            }
        }
        ConnectionPoolStats {
            pool_entries: self.services.len(),
            h1_idle_connections,
        }
    }
}

impl Default for ConnectionPool {
    fn default() -> Self {
        Self::new(5)
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionPoolStats {
    pub pool_entries: usize,
    pub h1_idle_connections: usize,
}

// ──────────────────────────────────────────────────────────────────────────────
// Free functions
// ──────────────────────────────────────────────────────────────────────────────

/// Strip brackets and port from an SNI string.
/// `"[::1]:8448"` → `"::1"`, `"1.2.3.4:8448"` → `"1.2.3.4"`, `"host:port"` → `"host"`
fn extract_sni_host(sni: &str) -> String {
    if sni.starts_with('[') {
        sni[1..sni.find(']').unwrap_or(sni.len())].to_string()
    } else {
        sni.split(':').next().unwrap_or(sni).to_string()
    }
}

/// Open a fresh TLS connection that speaks HTTP/1.1 (no H2 ALPN offered).
async fn make_fresh_h1_connection(
    addr: &str,
    sni_host: &str,
    conn_timeout: Duration,
) -> Result<(http1::SendRequest<Empty<Bytes>>, Arc<TlsConnectionInfo>), crate::error::FetchError> {
    let stream = timeout(conn_timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| crate::error::FetchError::Timeout(conn_timeout))
        .and_then(|r| r.map_err(|e| crate::error::FetchError::Network(e.to_string())))?;

    let config = shared_tls_config();
    let connector = TlsConnector::from(config);
    let domain = ServerName::try_from(sni_host.to_string())
        .map_err(|_| crate::error::FetchError::InvalidDomain(sni_host.to_string()))?;

    let tls_stream = connector
        .connect(domain, stream)
        .await
        .map_err(|e| crate::error::FetchError::Tls(e.to_string()))?;

    let (_, conn_info) = tls_stream.get_ref();
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
        http_version: HttpVersion::H1,
    });

    let (sender, conn) = http1::handshake(TokioIo::new(tls_stream))
        .await
        .map_err(|e| crate::error::FetchError::Network(e.to_string()))?;
    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            tracing::warn!(?err, "H1 connection driver ended");
        }
    });
    Ok((sender, tls_info))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_creates_pool_with_given_timeout() {
        let pool = ConnectionPool::new(10);
        assert_eq!(pool.connection_timeout, Duration::from_secs(10));
    }

    #[test]
    fn default_creates_pool_with_5_second_timeout() {
        let pool = ConnectionPool::default();
        assert_eq!(pool.connection_timeout, Duration::from_secs(5));
    }

    #[test]
    fn pool_count_starts_at_zero() {
        let pool = ConnectionPool::new(5);
        assert_eq!(pool.pool_count(), 0);
    }

    #[tokio::test]
    async fn stats_returns_zero_counts_for_empty_pool() {
        let pool = ConnectionPool::new(5);
        let stats = pool.stats().await;
        assert_eq!(stats.pool_entries, 0);
        assert_eq!(stats.h1_idle_connections, 0);
    }

    #[tokio::test]
    async fn cleanup_dead_connections_noop_when_empty() {
        let pool = ConnectionPool::new(5);
        pool.cleanup_dead_connections().await;
    }

    #[test]
    fn clone_request_preserves_method_uri_and_headers() {
        let req = Request::builder()
            .uri("/_matrix/federation/v1/version")
            .header(hyper::header::HOST, "example.com")
            .header(hyper::header::USER_AGENT, "test/1.0")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let cloned = clone_request(&req);
        assert_eq!(cloned.method(), req.method());
        assert_eq!(cloned.uri(), req.uri());
        assert_eq!(
            cloned.headers().get(hyper::header::HOST),
            req.headers().get(hyper::header::HOST)
        );
        assert_eq!(
            cloned.headers().get(hyper::header::USER_AGENT),
            req.headers().get(hyper::header::USER_AGENT)
        );
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
        // Host header must be removed — H2 uses :authority from the URI instead.
        assert!(converted.headers().get(hyper::header::HOST).is_none());
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
        assert!(converted.headers().get(hyper::header::HOST).is_none());
    }

    /// Regression: servers running nginx reject HTTP/2 requests that contain both
    /// `:authority` (derived from the absolute URI) and an explicit `Host` header,
    /// returning HTTP 400. `to_absolute_uri` must strip `Host` after promoting the URI.
    #[test]
    fn to_absolute_uri_removes_host_header_to_prevent_h2_400() {
        let req = Request::builder()
            .uri("/_matrix/key/v2/server")
            .header(hyper::header::HOST, "synapse.example.com")
            .header(hyper::header::USER_AGENT, "matrix-federation-checker/0.1")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let converted = to_absolute_uri(req);
        assert_eq!(
            converted.uri().to_string(),
            "https://synapse.example.com/_matrix/key/v2/server",
            ":authority must be set in URI"
        );
        assert!(
            converted.headers().get(hyper::header::HOST).is_none(),
            "Host header must be absent — duplicate authority causes nginx HTTP 400"
        );
        assert!(converted.headers().get(hyper::header::USER_AGENT).is_some());
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

    #[test]
    fn extract_sni_host_strips_port() {
        assert_eq!(extract_sni_host("example.com:8448"), "example.com");
    }

    #[test]
    fn extract_sni_host_strips_ipv6_brackets_and_port() {
        assert_eq!(extract_sni_host("[::1]:8448"), "::1");
    }

    #[test]
    fn extract_sni_host_no_port() {
        assert_eq!(extract_sni_host("example.com"), "example.com");
    }
}
