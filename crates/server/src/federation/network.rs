use crate::connection_pool::{ConnectionPool, PooledSender, TlsConnectionInfo};
use crate::error::FetchError;
use crate::federation::certificate::extract_certificate_info;
use crate::federation::config::FederationConfig;
use crate::response::Certificate;
use crate::tls::shared_tls_config;
use bytes::Bytes;
use http_body_util::Empty;
use hyper::Request;
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use rustls_pki_types::ServerName;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

#[derive(Debug)]
pub struct FullResponse {
    pub response: Option<hyper::Response<Incoming>>,
    pub protocol: String,
    pub cipher_suite: String,
    pub certificates: Vec<Certificate>,
}

#[tracing::instrument(skip(pool, config))]
pub async fn fetch_url_custom_sni_host(
    path: &str,
    addr: &str,
    host: &str,
    sni: &str,
    pool: Option<&ConnectionPool>,
    config: &FederationConfig,
) -> Result<FullResponse, FetchError> {
    // Strip brackets and port: "[::1]:8448" → "::1", "1.2.3.4:8448" → "1.2.3.4", "host:port" → "host"
    let sni_host = if sni.starts_with('[') {
        &sni[1..sni.find(']').unwrap_or(sni.len())]
    } else {
        sni.split(':').next().unwrap_or(sni)
    };
    let host_host = if host.starts_with('[') {
        &host[1..host.find(']').unwrap_or(host.len())]
    } else {
        host.split(':').next().unwrap_or(host)
    };
    tracing::debug!(
        name = "federation.fetch_url_custom_sni_host.start",
        target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
        message = "Fetching URL with custom SNI",
        path = %path,
        addr = %addr,
        sni_host = %sni_host,
        host = %host_host
    );

    // Try pool first — avoids a TLS handshake when the connection is warm.
    if let Some(pool) = pool
        && let Ok((mut sender, tls_info)) = pool.get_connection(addr, sni).await
    {
        let req = Request::builder()
            .uri(path)
            .header(hyper::header::USER_AGENT, "matrix-federation-checker/0.1")
            .header(hyper::header::HOST, host_host)
            .body(Empty::<Bytes>::new())
            .map_err(|e| FetchError::Network(e.to_string()))?;
        match sender.send_request(req).await {
            Ok(resp) => {
                pool.return_connection(addr, sni, sender, Arc::clone(&tls_info))
                    .await;
                return Ok(FullResponse {
                    response: Some(resp),
                    protocol: tls_info.protocol.clone(),
                    cipher_suite: tls_info.cipher_suite.clone(),
                    certificates: tls_info.certificates.clone(),
                });
            }
            Err(e) => {
                tracing::debug!(
                    name = "federation.fetch_url_custom_sni_host.pooled_send_failed",
                    target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                    error = ?e,
                    message = "Pooled connection send failed; falling back to fresh TLS connection"
                );
            }
        }
    }

    // Pool miss or send failure: do a fresh TCP + TLS connection.
    let t = config.network_timeout;
    let stream = timeout(t, TcpStream::connect(addr))
        .await
        .map_err(|_| FetchError::Timeout(t))
        .and_then(|r| r.map_err(|e| FetchError::Network(e.to_string())))?;

    let config = shared_tls_config();
    let connector = TlsConnector::from(config);
    let domain = ServerName::try_from(sni_host.to_string())
        .map_err(|_| FetchError::InvalidDomain(sni_host.to_string()))?;

    let tls_stream = connector
        .connect(domain, stream)
        .await
        .map_err(|e| FetchError::Tls(e.to_string()))?;

    // Capture TLS metadata before consuming the stream.
    let (_, connection_info) = tls_stream.get_ref();
    let protocol_version = connection_info
        .protocol_version()
        .map(|v| format!("{v:?}"))
        .unwrap_or_default();
    let cipher_suite = connection_info
        .negotiated_cipher_suite()
        .map(|c| c.suite().as_str().unwrap_or("unknown"))
        .unwrap_or("unknown");
    let certificates: Vec<Certificate> = connection_info
        .peer_certificates()
        .map(|certs| certs.iter().filter_map(extract_certificate_info).collect())
        .unwrap_or_default();

    let tls_info = Arc::new(TlsConnectionInfo {
        protocol: protocol_version.clone(),
        cipher_suite: cipher_suite.to_string(),
        certificates: certificates.clone(),
        http_version: crate::connection_pool::HttpVersion::H1,
    });

    let stream = TokioIo::new(tls_stream);

    let (mut h1_sender, conn) = hyper::client::conn::http1::handshake(stream)
        .await
        .map_err(|e| FetchError::Network(e.to_string()))?;
    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            tracing::error!(
                name = "federation.fetch_url_custom_sni_host.conn_failed",
                target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                error = ?err,
                message = "Connection failed while performing HTTP handshake"
            );
        }
    });

    let req = Request::builder()
        .uri(path)
        .header(hyper::header::USER_AGENT, "matrix-federation-checker/0.1")
        .header(hyper::header::HOST, host_host)
        .body(Empty::<Bytes>::new())
        .map_err(|e| FetchError::Network(e.to_string()))?;

    let res = h1_sender
        .send_request(req)
        .await
        .map_err(|e| FetchError::Network(e.to_string()))?;

    if let Some(pool) = pool {
        pool.return_connection(addr, sni, PooledSender::H1(h1_sender), tls_info)
            .await;
    }

    Ok(FullResponse {
        response: Some(res),
        protocol: protocol_version,
        cipher_suite: cipher_suite.to_string(),
        certificates,
    })
}
