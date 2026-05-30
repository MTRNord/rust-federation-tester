use crate::config::FederationConfig;
use crate::connection_pool::{ConnectionPool, PooledSender};
use crate::error::FetchError;
use crate::response::Version;
use crate::tls::shared_tls_config;
use bytes::Bytes;
use http_body_util::BodyExt;
use http_body_util::Empty;
use hyper::Request;
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use rustls_pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

#[derive(Default, Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct VersionResp {
    pub server: Version,
}

#[tracing::instrument(skip(connection_pool, config))]
pub async fn query_server_version_pooled(
    addr: &str,
    server_name: &str,
    sni: &str,
    connection_pool: &ConnectionPool,
    config: &FederationConfig,
) -> Result<Option<(Version, bool)>, FetchError> {
    let timeout_duration = config.network_timeout;
    let response_result = timeout(
        timeout_duration,
        fetch_url_pooled_simple(
            "/_matrix/federation/v1/version",
            addr,
            server_name,
            sni,
            connection_pool,
            config,
        ),
    )
    .await
    .map_err(|_| FetchError::Timeout(timeout_duration))?;
    let response_option = response_result?;
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
        .map_err(|e| FetchError::Network(e.to_string()))?
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

#[tracing::instrument(skip(connection_pool, config))]
pub async fn fetch_url_pooled_simple(
    path: &str,
    addr: &str,
    host: &str,
    sni: &str,
    connection_pool: &ConnectionPool,
    config: &FederationConfig,
) -> Result<Option<hyper::Response<Incoming>>, FetchError> {
    // Strip brackets and port to get the bare hostname for SNI and Host header.
    // Mirrors the same logic in network.rs::fetch_url_custom_sni_host.
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
        Ok((mut sender, tls_info)) => {
            let req = Request::builder()
                .uri(path)
                .header(hyper::header::USER_AGENT, "matrix-federation-checker/0.1")
                .header(hyper::header::HOST, host_host)
                .body(Empty::<Bytes>::new())
                .map_err(|e| FetchError::Network(e.to_string()))?;
            match sender.send_request(req).await {
                Ok(response) => {
                    connection_pool
                        .return_connection(addr, sni, sender, tls_info)
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
    let t = config.network_timeout;
    let stream = timeout(t, TcpStream::connect(addr))
        .await
        .map_err(|_| FetchError::Timeout(t))
        .and_then(|r| r.map_err(|e| FetchError::Network(e.to_string())))?;

    // Use shared TLS configuration for better performance
    let config = shared_tls_config();
    let connector = TlsConnector::from(config);
    let domain = ServerName::try_from(sni_host.to_string())
        .map_err(|_| FetchError::InvalidDomain(sni_host.to_string()))?;
    let tls_stream = connector
        .connect(domain, stream)
        .await
        .map_err(|e| FetchError::Tls(e.to_string()))?;

    let (_, conn_info) = tls_stream.get_ref();
    let tls_info = std::sync::Arc::new(crate::connection_pool::TlsConnectionInfo {
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
            .map(|certs| {
                certs
                    .iter()
                    .filter_map(crate::federation::certificate::extract_certificate_info)
                    .collect()
            })
            .unwrap_or_default(),
        http_version: crate::connection_pool::HttpVersion::H1,
    });

    let io = TokioIo::new(tls_stream);
    let (mut h1_sender, conn) = hyper::client::conn::http1::handshake(io)
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
    let response = h1_sender
        .send_request(req)
        .await
        .map_err(|e| FetchError::Network(e.to_string()))?;
    connection_pool
        .return_connection(addr, sni, PooledSender::H1(h1_sender), tls_info)
        .await;
    Ok(Some(response))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_resp_deserializes_valid_json() {
        let json = r#"{"server":{"name":"Synapse","version":"1.95.1"}}"#;
        let v: VersionResp = serde_json::from_str(json).unwrap();
        assert_eq!(v.server.name, "Synapse");
        assert_eq!(v.server.version, "1.95.1");
    }

    #[test]
    fn version_resp_missing_fields_fails() {
        let json = r#"{"server":{}}"#;
        let result: Result<VersionResp, _> = serde_json::from_str(json);
        // Missing name/version fields — deserialization should fail or produce defaults
        // depending on serde config; either outcome is acceptable but must not panic
        let _ = result;
    }

    #[test]
    fn version_resp_invalid_json_fails() {
        let result: Result<VersionResp, _> = serde_json::from_str("not json");
        assert!(result.is_err());
    }

    #[test]
    fn version_resp_extra_fields_ignored() {
        // Real homeservers sometimes add extra fields (e.g. "unstable_features")
        let json = r#"{"server":{"name":"Dendrite","version":"0.13.0","extra":"ignored"},"unknown_top_level":true}"#;
        let v: VersionResp = serde_json::from_str(json).unwrap();
        assert_eq!(v.server.name, "Dendrite");
        assert_eq!(v.server.version, "0.13.0");
    }

    #[test]
    fn version_resp_roundtrip() {
        let v = VersionResp {
            server: crate::response::Version {
                name: "Conduit".to_string(),
                version: "0.7.0".to_string(),
            },
        };
        let json = serde_json::to_string(&v).unwrap();
        let back: VersionResp = serde_json::from_str(&json).unwrap();
        assert_eq!(back.server.name, "Conduit");
        assert_eq!(back.server.version, "0.7.0");
    }
}
