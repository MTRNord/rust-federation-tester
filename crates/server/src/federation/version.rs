use crate::connection_pool::ConnectionPool;
use crate::error::FetchError;
use crate::federation::well_known::NETWORK_TIMEOUT_SECS;
use crate::optimization::get_shared_tls_config;
use crate::response::Version;
use bytes::Bytes;
use http_body_util::BodyExt;
use http_body_util::Empty;
use hyper::Request;
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use rustls_pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};
use tokio_rustls::TlsConnector;

#[derive(Default, Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct VersionResp {
    pub server: Version,
}

#[tracing::instrument(name = "query_server_version_pooled", skip(connection_pool))]
pub async fn query_server_version_pooled(
    addr: &str,
    server_name: &str,
    sni: &str,
    connection_pool: &ConnectionPool,
) -> color_eyre::eyre::Result<Option<(Version, bool)>> {
    let timeout_duration = Duration::from_secs(NETWORK_TIMEOUT_SECS);
    let response_result = timeout(
        timeout_duration,
        fetch_url_pooled_simple(
            "/_matrix/federation/v1/version",
            addr,
            server_name,
            sni,
            connection_pool,
        ),
    )
    .await
    .map_err(|_| color_eyre::eyre::eyre!(FetchError::Timeout(timeout_duration).to_string()))?;
    let response_option = response_result.map_err(|e| color_eyre::eyre::eyre!(e.to_string()))?;
    let http_response = match response_option {
        Some(r) => r,
        None => return Ok(Some((Version::default(), false))),
    };
    let status = http_response.status();
    let headers = http_response.headers().clone();
    let body = http_response
        .into_body()
        .collect()
        .await
        .map_err(|e| color_eyre::eyre::eyre!(FetchError::Network(e.to_string()).to_string()))?
        .to_bytes();
    if !status.is_success() {
        return Ok(Some((Version::default(), false)));
    }
    if let Some(ct) = headers.get("Content-Type") {
        if !ct.to_str().unwrap_or("").contains("application/json") {
            return Ok(Some((Version::default(), false)));
        }
    } else {
        return Ok(Some((Version::default(), false)));
    }
    match serde_json::from_slice::<VersionResp>(&body) {
        Ok(v) => Ok(Some((v.server, true))),
        Err(_) => Ok(Some((Version::default(), false))),
    }
}

#[tracing::instrument(
    name = "fetch_url_pooled_simple",
    level = "debug",
    skip(path, connection_pool)
)]
pub async fn fetch_url_pooled_simple(
    path: &str,
    addr: &str,
    host: &str,
    sni: &str,
    connection_pool: &ConnectionPool,
) -> Result<Option<hyper::Response<Incoming>>, FetchError> {
    let sni_host = sni.split(':').next().unwrap();
    let host_host = host.split(':').next().unwrap();
    tracing::debug!(
        name = "federation.fetch_url_pooled_simple.start",
        target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
        message = "Fetching with connection pool",
        path = %path,
        addr = %addr,
        sni_host = %sni_host,
        host = %host_host,
        using_connection_pool = true
    );
    match connection_pool.get_connection(addr, sni).await {
        Ok(mut sender) => {
            let req = Request::builder()
                .uri(path)
                .header(hyper::header::USER_AGENT, "matrix-federation-checker/0.1")
                .header(hyper::header::HOST, host_host)
                .body(Empty::<Bytes>::new())
                .map_err(|e| FetchError::Network(e.to_string()))?;
            match sender.send_request(req).await {
                Ok(response) => {
                    connection_pool
                        .return_connection(addr, sni, "anonymous", sender)
                        .await;
                    return Ok(Some(response));
                }
                Err(e) => {
                    tracing::debug!(
                        name = "federation.fetch_url_pooled_simple.pooled_send_failed",
                        target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                        error = ?e,
                        message = "Pooled connection send failed; falling back to fresh connection"
                    );
                }
            }
        }
        Err(e) => {
            tracing::debug!(
                name = "federation.fetch_url_pooled_simple.pool_get_connection_failed",
                target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                error = ?e,
                message = "Connection pool get_connection failed; falling back to fresh connection"
            );
        }
    }
    tracing::debug!(
        name = "federation.fetch_url_pooled_simple.create_fresh_connection",
        target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
        message = "Creating fresh connection",
        path = %path,
        addr = %addr
    );
    let stream = timeout(
        Duration::from_secs(NETWORK_TIMEOUT_SECS),
        TcpStream::connect(addr),
    )
    .await
    .map_err(|_| FetchError::Timeout(Duration::from_secs(NETWORK_TIMEOUT_SECS)))
    .and_then(|r| r.map_err(|e| FetchError::Network(e.to_string())))?;

    // Use shared TLS configuration for better performance
    let config = get_shared_tls_config();
    let connector = TlsConnector::from(config);
    let domain = ServerName::try_from(sni_host.to_string())
        .map_err(|_| FetchError::InvalidDomain(sni_host.to_string()))?;
    let tls_stream = connector
        .connect(domain, stream)
        .await
        .map_err(|e| FetchError::Tls(e.to_string()))?;
    let io = TokioIo::new(tls_stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| FetchError::Network(e.to_string()))?;
    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            tracing::debug!(
                name = "federation.fetch_url_pooled_simple.fresh_conn_task_ended",
                target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                error = ?err,
                message = "Fresh connection task ended"
            );
        }
    });
    let req = Request::builder()
        .uri(path)
        .header(hyper::header::USER_AGENT, "matrix-federation-checker/0.1")
        .header(hyper::header::HOST, host_host)
        .body(Empty::<Bytes>::new())
        .map_err(|e| FetchError::Network(e.to_string()))?;
    let response = sender
        .send_request(req)
        .await
        .map_err(|e| FetchError::Network(e.to_string()))?;
    connection_pool
        .return_connection(addr, sni, "anonymous", sender)
        .await;
    Ok(Some(response))
}
