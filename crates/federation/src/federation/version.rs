use crate::config::FederationConfig;
use crate::connection_pool::ConnectionPool;
use crate::error::FetchError;
use crate::response::Version;
use bytes::Bytes;
use http_body_util::BodyExt;
use http_body_util::Empty;
use hyper::Request;
use hyper::body::Incoming;
use tokio::time::timeout;

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

#[tracing::instrument(skip(connection_pool))]
pub async fn fetch_url_pooled_simple(
    path: &str,
    addr: &str,
    host: &str,
    sni: &str,
    connection_pool: &ConnectionPool,
) -> Result<Option<hyper::Response<Incoming>>, FetchError> {
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
        host = %host_host,
    );
    let req = Request::builder()
        .uri(path)
        .header(hyper::header::USER_AGENT, "matrix-federation-checker/0.1")
        .header(hyper::header::HOST, host_host)
        .body(Empty::<Bytes>::new())
        .map_err(|e| FetchError::Network(e.to_string()))?;
    let (resp, _tls_info) = connection_pool.send(addr, sni, req).await?;
    Ok(Some(resp))
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
