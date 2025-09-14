use crate::error::FetchError;
use crate::federation::certificate::extract_certificate_info;
use crate::optimization::get_shared_tls_config;
use crate::response::Certificate;
use bytes::Bytes;
use http_body_util::Empty;
use hyper::Request;
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use rustls_pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};
use tokio_rustls::TlsConnector;
use tracing::{debug, error};

use crate::federation::well_known::NETWORK_TIMEOUT_SECS;

#[derive(Debug)]
pub struct FullResponse {
    pub response: Option<hyper::Response<Incoming>>,
    pub protocol: String,
    pub cipher_suite: String,
    pub certificates: Vec<Certificate>,
}

#[tracing::instrument(name = "fetch_url_custom_sni_host", level = "debug", skip(path))]
pub async fn fetch_url_custom_sni_host(
    path: &str,
    addr: &str,
    host: &str,
    sni: &str,
) -> Result<FullResponse, FetchError> {
    let sni_host = sni.split(':').next().unwrap();
    let host_host = host.split(':').next().unwrap();
    debug!(
        "[fetch_url_custom_sni_host] Fetching {path} from {addr} with SNI {sni_host} and host {host_host}"
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

    let (_io, connection_info) = tls_stream.get_ref();
    let protocol_version = connection_info
        .protocol_version()
        .map(|v| format!("{v:?}"))
        .unwrap_or_default();
    let cipher_suite = connection_info
        .negotiated_cipher_suite()
        .map(|c| c.suite().as_str().unwrap_or("unknown"))
        .unwrap_or("unknown");

    let certificates = if let Some(peer_certs) = connection_info.peer_certificates() {
        peer_certs
            .iter()
            .filter_map(extract_certificate_info)
            .collect()
    } else {
        Vec::new()
    };

    let stream = TokioIo::new(tls_stream);

    let mut response = FullResponse {
        response: None,
        protocol: protocol_version,
        cipher_suite: cipher_suite.to_string(),
        certificates,
    };

    let (mut sender, conn) = hyper::client::conn::http1::handshake(stream)
        .await
        .map_err(|e| FetchError::Network(e.to_string()))?;
    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            error!("Connection failed: {err:#?}");
        }
    });

    let req = Request::builder()
        .uri(path)
        .header(hyper::header::USER_AGENT, "matrix-federation-checker/0.1")
        .header(hyper::header::HOST, host_host)
        .body(Empty::<Bytes>::new())
        .map_err(|e| FetchError::Network(e.to_string()))?;

    let res = sender
        .send_request(req)
        .await
        .map_err(|e| FetchError::Network(e.to_string()))?;
    response.response = Some(res);
    Ok(response)
}
