use crate::config::FederationConfig;
use crate::connection_pool::ConnectionPool;
use crate::federation::keys::verify_keys;
use crate::federation::{fetch_keys, query_server_version_pooled};
use crate::response::{ConnectionReportData, Error, ErrorCode};
use tokio::time::{Duration, sleep};

#[tracing::instrument(skip(connection_pool, config))]
pub async fn connection_check(
    addr: &str,
    server_name: &str,
    server_host: &str,
    sni: &str,
    connection_pool: &ConnectionPool,
    config: &FederationConfig,
) -> Result<ConnectionReportData, Error> {
    let mut report = ConnectionReportData::default();
    let addr_c = addr.to_string();
    let server_host_c = server_host.to_string();
    let sni_c = sni.to_string();
    let pool_c = connection_pool.clone();

    // First attempt: run version and keys fetches in parallel.
    let (v_first, k_first) = tokio::join!(
        query_server_version_pooled(&addr_c, &server_host_c, &sni_c, &pool_c, config),
        fetch_keys(&addr_c, &server_host_c, &sni_c, &pool_c, config)
    );
    let (v_err, k_err) = (v_first.is_err(), k_first.is_err());

    // Retry on transient failure: one retry after 500 ms (single sleep covers both).
    // If the retry succeeds, mark `required_retry` so callers know the endpoint is
    // exhibiting instability that federation peers may also encounter.
    let (version_result, key_result, version_retried, keys_retried) = if !v_err && !k_err {
        (v_first, k_first, false, false)
    } else {
        sleep(Duration::from_millis(500)).await;
        let (v, k) = tokio::join!(
            async {
                if v_err {
                    query_server_version_pooled(&addr_c, &server_host_c, &sni_c, &pool_c, config)
                        .await
                } else {
                    v_first
                }
            },
            async {
                if k_err {
                    fetch_keys(&addr_c, &server_host_c, &sni_c, &pool_c, config).await
                } else {
                    k_first
                }
            },
        );
        (v, k, v_err, k_err)
    };

    // Flag: a retry was performed AND that retry succeeded (transient instability).
    report.required_retry =
        (version_retried && version_result.is_ok()) || (keys_retried && key_result.is_ok());

    match version_result {
        Ok(version_data) => {
            if let Some((version, parses)) = version_data {
                report.version = version;
                report.checks.server_version_parses = parses;
            }
        }
        Err(e) => {
            return Err(Error {
                error: format!("Error fetching server version from {addr}: {e}"),
                error_code: ErrorCode::Unknown,
            });
        }
    }

    let key_resp = match key_result {
        Ok(key_resp) => {
            report.keys = key_resp.keys.clone();
            report.cipher.version = key_resp.protocol.clone();
            report.cipher.cipher_suite = key_resp.cipher_suite.clone();
            report.certificates = key_resp.certificates.clone();
            report.checks.valid_certificates = !report.certificates.is_empty();
            key_resp
        }
        Err(e) => {
            tracing::error!(
                name = "federation.connection.fetch_keys_failed",
                target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                addr = %addr,
                error = ?e,
                message = "Error fetching keys from server"
            );
            return Err(Error {
                error: format!("Error fetching keys from {addr}: {e}"),
                error_code: ErrorCode::Unknown,
            });
        }
    };

    let kv = verify_keys(server_name, &report.keys, &key_resp.keys_string);
    report.checks.future_valid_until_ts = kv.future_valid_until_ts;
    report.checks.valid_until_ts_within_7_days = kv.valid_until_ts_within_7_days;
    report.checks.valid_until_ts_not_expiring_soon = kv.valid_until_ts_not_expiring_soon;
    report.checks.has_ed25519key = kv.has_ed25519key;
    report.checks.all_ed25519checks_ok = kv.all_ed25519checks_ok;
    report.checks.matching_server_name = kv.matching_server_name;
    report.checks.ed25519checks = kv.ed25519checks;
    report.checks.keys_content_type_ok = key_resp.content_type_ok;
    report.checks.tls_version_ok = matches!(key_resp.protocol.as_str(), "TLSv1_2" | "TLSv1_3");
    // valid_until_ts_within_7_days is a SHOULD NOT (not MUST NOT) for servers per spec,
    // so excluded from all_checks_ok to avoid false failures for compliant servers.
    report.checks.all_checks_ok = report.checks.has_ed25519key
        && report.checks.all_ed25519checks_ok
        && report.checks.valid_certificates
        && report.checks.matching_server_name
        && report.checks.future_valid_until_ts
        && report.checks.server_version_parses
        && report.checks.keys_content_type_ok;
    report.ed25519verify_keys = kv.ed25519_verify_keys;
    Ok(report)
}
