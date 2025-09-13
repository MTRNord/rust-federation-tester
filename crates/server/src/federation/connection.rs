use crate::cache::VersionCache;
use crate::connection_pool::ConnectionPool;
use crate::federation::keys::verify_keys;
use crate::federation::{fetch_keys, query_server_version_pooled};
use crate::response::{ConnectionReportData, Error, ErrorCode, Version}; // internal helper
// Removed unused imports after refactor
use tracing::error;

#[tracing::instrument(name = "connection_check", skip(connection_pool, version_cache), fields(addr = %addr, server_name = %server_name, sni = %sni, use_cache = use_cache))]
pub async fn connection_check(
    addr: &str,
    server_name: &str,
    server_host: &str,
    sni: &str,
    connection_pool: &ConnectionPool,
    version_cache: &VersionCache,
    use_cache: bool,
) -> Result<ConnectionReportData, Error> {
    let mut report = ConnectionReportData::default();
    let version_cache_key = format!("{addr}:{server_host}");
    let cached_version = if use_cache {
        version_cache
            .get_cached(&version_cache_key, use_cache)
            .and_then(|s| serde_json::from_str::<Version>(&s).ok())
    } else {
        None
    };

    let (version_result, key_result) = if let Some(cached_version) = cached_version {
        report.version = cached_version;
        report.checks.server_version_parses = true;
        let key_resp = fetch_keys(addr, server_host, sni).await;
        (Ok(None), key_resp)
    } else {
        let addr_c = addr.to_string();
        let server_host_c = server_host.to_string();
        let sni_c = sni.to_string();
        let pool_c = connection_pool.clone();
        tokio::join!(
            query_server_version_pooled(&addr_c, &server_host_c, &sni_c, &pool_c),
            fetch_keys(&addr_c, &server_host_c, &sni_c)
        )
    };

    match version_result {
        Ok(version_data) => {
            if let Some((version, parses)) = version_data {
                report.version = version;
                report.checks.server_version_parses = parses;
                if use_cache
                    && report.checks.server_version_parses
                    && let Ok(v_json) = serde_json::to_string(&report.version)
                {
                    version_cache.insert(version_cache_key, v_json);
                }
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
            error!("Error fetching keys from {addr}: {e:#?}");
            return Err(Error {
                error: format!("Error fetching keys from {addr}: {e}"),
                error_code: ErrorCode::Unknown,
            });
        }
    };

    let (
        future_valid_until_ts,
        has_ed25519_key,
        all_ed25519checks_ok,
        ed25519_checks,
        ed25519_verify_keys,
        matching_server_name,
    ) = verify_keys(server_name, &report.keys, &key_resp.keys_string);
    report.checks.future_valid_until_ts = future_valid_until_ts;
    report.checks.has_ed25519key = has_ed25519_key;
    report.checks.all_ed25519checks_ok = all_ed25519checks_ok;
    report.checks.matching_server_name = matching_server_name;
    report.checks.ed25519checks = ed25519_checks;
    report.checks.all_checks_ok = report.checks.has_ed25519key
        && report.checks.all_ed25519checks_ok
        && report.checks.valid_certificates
        && report.checks.matching_server_name
        && report.checks.future_valid_until_ts
        && report.checks.server_version_parses;
    report.ed25519verify_keys = ed25519_verify_keys;
    Ok(report)
}
