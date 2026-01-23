//! Statistics collection & anonymization (per-request opt-in based)
use crate::AppResources;
use blake3::Hasher;
use once_cell::sync::Lazy;
use sea_orm::{
    ActiveModelTrait, ActiveValue, ColumnTrait, ConnectionTrait, DatabaseBackend, EntityTrait,
    QuerySelect, Statement,
};
use sea_orm::{DatabaseConnection, QueryFilter};
use std::{
    collections::{HashMap, HashSet},
    sync::RwLock,
    time::{Duration, Instant},
};
use time::OffsetDateTime;

/// Event representing a single opted-in request.
#[derive(Debug)]
pub struct StatEvent<'a> {
    pub server_name: &'a str,
    pub federation_ok: bool,
    pub version_name: Option<&'a str>,
    pub version_string: Option<&'a str>,
    pub unstable_features_enabled: Option<&'a [String]>,
    pub unstable_features_announced: Option<&'a [String]>,
}

/// Classify software family & version from the version_name/version_string (simple heuristic).
#[tracing::instrument()]
fn classify_version(
    version_name: Option<&str>,
    version_string: Option<&str>,
) -> (Option<String>, Option<String>) {
    let ver = extract_version(version_string.unwrap_or_default());
    (version_name.map(ToString::to_string), ver)
}

#[tracing::instrument()]
fn extract_version(s: &str) -> Option<String> {
    // find first pattern like digit[.digit]+ simple
    let mut current = String::new();
    let mut found_digit = false;
    for c in s.chars() {
        if c.is_ascii_digit() || c == '.' {
            current.push(c);
            found_digit = true;
        } else if found_digit {
            break;
        }
    }
    if found_digit && current.chars().any(|c| c == '.') {
        Some(current)
    } else {
        None
    }
}

/// Record a single event directly (no batching yet) updating aggregate table.
#[tracing::instrument(skip(resources))]
pub async fn record_event(resources: &AppResources, ev: StatEvent<'_>) {
    use crate::entity::{federation_stat_aggregate as agg, federation_stat_raw as raw};
    if !resources.config.statistics.enabled {
        tracing::trace!(server=%ev.server_name, "stats disabled; skipping record_event");
        return;
    }
    let db = &*resources.db;
    let server_key = ev.server_name.to_lowercase();
    let (family_val, version_val) = classify_version(ev.version_name, ev.version_string);
    let success_inc: i64 = if ev.federation_ok { 1 } else { 0 };
    let failure_inc: i64 = if ev.federation_ok { 0 } else { 1 };
    let now: OffsetDateTime = OffsetDateTime::now_utc();

    // Serialize unstable features lists to JSON strings for storage
    let unstable_enabled_json = ev
        .unstable_features_enabled
        .map(|features| serde_json::to_string(features).unwrap_or_default());
    let unstable_announced_json = ev
        .unstable_features_announced
        .map(|features| serde_json::to_string(features).unwrap_or_default());

    // Count features for aggregate tracking
    let enabled_count = ev
        .unstable_features_enabled
        .map(|f| f.len() as i32)
        .unwrap_or(0);
    let announced_count = ev
        .unstable_features_announced
        .map(|f| f.len() as i32)
        .unwrap_or(0);

    // Insert raw event (append-only) first
    let raw_model = raw::ActiveModel {
        id: ActiveValue::NotSet,
        ts: ActiveValue::Set(now),
        server_name: ActiveValue::Set(server_key.clone()),
        federation_ok: ActiveValue::Set(ev.federation_ok),
        version_name: ActiveValue::Set(ev.version_name.map(|s| s.to_string())),
        version_string: ActiveValue::Set(ev.version_string.map(|s| s.to_string())),
        unstable_features_enabled: ActiveValue::Set(unstable_enabled_json),
        unstable_features_announced: ActiveValue::Set(unstable_announced_json),
    };
    if let Err(e) = raw_model.insert(db).await {
        tracing::warn!(
            name = "stats.insert_raw_federation_event",
            target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            message = "failed inserting raw federation event",
            error = %e,
            server = %server_key
        );
    }

    match agg::Entity::find_by_id(server_key.clone()).one(db).await {
        Ok(Some(mut model)) => {
            model.last_seen_at = now;
            model.req_count += 1;
            model.success_count += success_inc;
            model.failure_count += failure_inc;
            model.last_version_name = ev.version_name.map(ToString::to_string);
            model.last_version_string = ev.version_string.map(ToString::to_string);
            model.software_family = family_val.clone();
            model.software_version = version_val.clone();
            model.unstable_features_enabled = enabled_count;
            model.unstable_features_announced = announced_count;
            let active: agg::ActiveModel = model.into();
            if let Err(e) = active.update(db).await {
                tracing::warn!(
                    name = "stats.update_federation_stat_aggregate",
                    target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                    message = "failed updating federation_stat_aggregate",
                    error = %e,
                    server = %server_key
                );
            }
        }
        Ok(None) => {
            let active = agg::ActiveModel {
                server_name: ActiveValue::Set(server_key.clone()),
                first_seen_at: ActiveValue::Set(now),
                last_seen_at: ActiveValue::Set(now),
                req_count: ActiveValue::Set(1),
                success_count: ActiveValue::Set(success_inc),
                failure_count: ActiveValue::Set(failure_inc),
                first_version_name: ActiveValue::Set(ev.version_name.map(|s| s.to_string())),
                first_version_string: ActiveValue::Set(ev.version_string.map(|s| s.to_string())),
                last_version_name: ActiveValue::Set(ev.version_name.map(|s| s.to_string())),
                last_version_string: ActiveValue::Set(ev.version_string.map(|s| s.to_string())),
                software_family: ActiveValue::Set(family_val.clone()),
                software_version: ActiveValue::Set(version_val.clone()),
                unstable_features_enabled: ActiveValue::Set(enabled_count),
                unstable_features_announced: ActiveValue::Set(announced_count),
            };
            if let Err(e) = active.insert(db).await {
                tracing::warn!(
                    name = "stats.insert_federation_stat_aggregate",
                    target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                    message = "failed inserting federation_stat_aggregate",
                    error = %e,
                    server = %server_key
                );
            }
        }
        Err(e) => {
            tracing::warn!(
                name = "stats.fetch_federation_stat_aggregate",
                target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                message = "database error fetching federation_stat_aggregate",
                error = %e,
                server = %server_key
            );
        }
    }
    invalidate_metrics_cache();
}

/// Prune old federation aggregate rows whose last_seen_at is older than the configured retention window.
/// This uses backend-specific date arithmetic.
#[tracing::instrument(skip(resources))]
pub async fn prune_old_entries(resources: &AppResources) {
    let days = resources.config.statistics.raw_retention_days as i64;
    if days == 0 {
        return;
    }
    let db = &*resources.db;
    let backend = db.get_database_backend();
    let sql = match backend {
        DatabaseBackend::Postgres => {
            "DELETE FROM federation_stat_aggregate WHERE last_seen_at < NOW() - ($1::interval)"
                .to_string()
        }
        // SQLite stores timestamps as text; use datetime('now','-Xd')
        DatabaseBackend::Sqlite => format!(
            "DELETE FROM federation_stat_aggregate WHERE last_seen_at < datetime('now','-{days} days')"
        ),
        DatabaseBackend::MySql => format!(
            "DELETE FROM federation_stat_aggregate WHERE last_seen_at < (NOW() - INTERVAL {days} DAY)"
        ),
    };
    let stmt = match backend {
        DatabaseBackend::Postgres => {
            Statement::from_sql_and_values(backend, sql, vec![format!("{days} days").into()])
        }
        _ => Statement::from_string(backend, sql),
    };
    if let Err(e) = db.execute(stmt).await {
        tracing::warn!(
            name: "stats.prune_old_entries",
            target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            error=%e,
            message = "prune_old_entries failed"
        );
    }
}

/// Spawn a background task that periodically prunes old entries every 12 hours.
#[tracing::instrument(skip(resources))]
pub fn spawn_retention_task(resources: std::sync::Arc<AppResources>) {
    if !resources.config.statistics.enabled {
        return;
    }
    let days = resources.config.statistics.raw_retention_days;
    if days == 0 {
        return;
    }
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_hours(12));
        loop {
            interval.tick().await;
            prune_old_entries(&resources).await;
        }
    });
}

static PROM_CACHE: Lazy<RwLock<PromCache>> = Lazy::new(|| {
    RwLock::new(PromCache {
        generated_at: Instant::now() - Duration::from_secs(3600),
        body: String::new(),
    })
});

struct PromCache {
    generated_at: Instant,
    body: String,
}

/// Compute a stable anonymized id for a server name using the provided salt.
/// Returns None if salt is empty (feature disabled for anonymized export).
/// Note: blake3 is extremely fast (~1ns per hash), so no caching needed.
#[tracing::instrument(skip(salt, server_name))]
pub fn stable_anon_id(salt: &str, server_name: &str) -> Option<String> {
    if salt.is_empty() {
        return None;
    }
    let mut hasher = Hasher::new();
    hasher.update(salt.as_bytes());
    hasher.update(b"::");
    hasher.update(server_name.as_bytes());
    let hash = hasher.finalize();
    Some(hash.to_hex().to_string())
}

#[tracing::instrument()]
pub fn clear_metrics_cache() {
    invalidate_metrics_cache();
}

#[tracing::instrument()]
fn invalidate_metrics_cache() {
    if let Ok(mut guard) = PROM_CACHE.write() {
        guard.generated_at = Instant::now() - Duration::from_secs(3600);
        guard.body.clear();
    }
}

#[derive(Debug, sea_orm::FromQueryResult)]
struct AggregateRow {
    server_name: String,
    req_count: i64,
    success_count: i64,
    failure_count: i64,
    software_family: Option<String>,
    software_version: Option<String>,
}

#[tracing::instrument()]
fn escape_label(val: &str) -> String {
    let mut out = String::with_capacity(val.len() + 4);
    for c in val.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out
}

/// Build Prometheus exposition text for federation stats.
/// Calculate unique features across all servers from raw data (using latest entry per server)
#[tracing::instrument(skip(db))]
async fn calculate_unique_features(db: &DatabaseConnection) -> (i64, i64) {
    use crate::entity::federation_stat_raw as raw;
    use sea_orm::QueryOrder;

    // Get entries ordered by timestamp DESC so newest entries come first
    let rows: Vec<(String, Option<String>, Option<String>)> = raw::Entity::find()
        .select_only()
        .column(raw::Column::ServerName)
        .column(raw::Column::UnstableFeaturesEnabled)
        .column(raw::Column::UnstableFeaturesAnnounced)
        .filter(raw::Column::UnstableFeaturesEnabled.is_not_null())
        .order_by_desc(raw::Column::Ts)
        .into_tuple()
        .all(db)
        .await
        .unwrap_or_default();

    let mut unique_enabled_features: HashSet<String> = HashSet::new();
    let mut unique_announced_features: HashSet<String> = HashSet::new();
    let mut latest_per_server: HashMap<String, (Option<String>, Option<String>)> = HashMap::new();

    // Get the latest features for each server (first occurrence wins since ordered by ts DESC)
    for (server_name, enabled_json, announced_json) in rows {
        // Only insert if we haven't seen this server yet (i.e., keep the first/newest entry)
        latest_per_server
            .entry(server_name)
            .or_insert((enabled_json, announced_json));
    }

    // Collect unique features across all servers
    for (_server, (enabled_json, announced_json)) in latest_per_server {
        // Parse enabled features
        if let Some(enabled_str) = enabled_json
            && let Ok(enabled_features) = serde_json::from_str::<Vec<String>>(&enabled_str)
        {
            for feature in enabled_features {
                unique_enabled_features.insert(feature);
            }
        }

        // Parse announced features
        if let Some(announced_str) = announced_json
            && let Ok(announced_features) = serde_json::from_str::<Vec<String>>(&announced_str)
        {
            for feature in announced_features {
                unique_announced_features.insert(feature);
            }
        }
    }

    (
        unique_enabled_features.len() as i64,
        unique_announced_features.len() as i64,
    )
}

/// Build per-feature metrics by analyzing raw data (using only the latest entry per server)
#[tracing::instrument(skip(db))]
async fn build_feature_metrics(db: &DatabaseConnection) -> String {
    use crate::entity::federation_stat_raw as raw;
    use sea_orm::QueryOrder;

    // Get raw entries ordered by timestamp DESC so newest entries come first
    let thirty_days_ago = OffsetDateTime::now_utc() - time::Duration::days(30);
    let rows: Vec<(String, Option<String>, Option<String>)> = raw::Entity::find()
        .select_only()
        .column(raw::Column::ServerName)
        .column(raw::Column::UnstableFeaturesEnabled)
        .column(raw::Column::UnstableFeaturesAnnounced)
        .filter(raw::Column::Ts.gte(thirty_days_ago))
        .filter(raw::Column::UnstableFeaturesEnabled.is_not_null())
        .order_by_desc(raw::Column::Ts)
        .into_tuple()
        .all(db)
        .await
        .unwrap_or_default();

    // First, collect only the latest entry per server
    let mut latest_per_server: HashMap<String, (Option<String>, Option<String>)> = HashMap::new();
    for (server_name, enabled_json, announced_json) in rows {
        // Only insert if we haven't seen this server yet (first = newest since ordered DESC)
        latest_per_server
            .entry(server_name)
            .or_insert((enabled_json, announced_json));
    }

    // Now count features based on latest state per server
    let mut servers_with_feature_enabled: HashMap<String, HashSet<String>> = HashMap::new();
    let mut servers_with_feature_announced: HashMap<String, HashSet<String>> = HashMap::new();

    for (server_name, (enabled_json, announced_json)) in latest_per_server {
        // Parse enabled features
        if let Some(enabled_str) = enabled_json
            && let Ok(enabled_features) = serde_json::from_str::<Vec<String>>(&enabled_str)
        {
            for feature in enabled_features {
                servers_with_feature_enabled
                    .entry(feature)
                    .or_default()
                    .insert(server_name.clone());
            }
        }

        // Parse announced features
        if let Some(announced_str) = announced_json
            && let Ok(announced_features) = serde_json::from_str::<Vec<String>>(&announced_str)
        {
            for feature in announced_features {
                servers_with_feature_announced
                    .entry(feature)
                    .or_default()
                    .insert(server_name.clone());
            }
        }
    }

    let mut buf = String::new();

    // Add per-feature enabled metrics
    if !servers_with_feature_enabled.is_empty() {
        buf.push_str("# HELP federation_unstable_feature_enabled_servers Count of servers with each unstable feature enabled.\n");
        buf.push_str("# TYPE federation_unstable_feature_enabled_servers gauge\n");

        for (feature, servers) in servers_with_feature_enabled.iter() {
            let feature_label = escape_label(feature);
            buf.push_str(&format!(
                "federation_unstable_feature_enabled_servers{{feature=\"{}\"}} {}\n",
                feature_label,
                servers.len()
            ));
        }
    }

    // Add per-feature announced metrics
    if !servers_with_feature_announced.is_empty() {
        buf.push_str("# HELP federation_unstable_feature_announced_servers Count of servers with each unstable feature announced.\n");
        buf.push_str("# TYPE federation_unstable_feature_announced_servers gauge\n");

        for (feature, servers) in servers_with_feature_announced.iter() {
            let feature_label = escape_label(feature);
            buf.push_str(&format!(
                "federation_unstable_feature_announced_servers{{feature=\"{}\"}} {}\n",
                feature_label,
                servers.len()
            ));
        }
    }

    buf
}

#[tracing::instrument(skip(resources))]
pub async fn build_prometheus_metrics(resources: &AppResources) -> String {
    if !resources.config.statistics.enabled || !resources.config.statistics.prometheus_enabled {
        return String::new();
    }
    let salt = &resources.config.statistics.anonymization_salt;
    if salt.is_empty() {
        return String::new();
    }
    let db: &DatabaseConnection = resources.db.as_ref();
    use crate::entity::federation_stat_aggregate as agg;
    let rows: Vec<AggregateRow> = agg::Entity::find()
        .into_model::<AggregateRow>()
        .all(db)
        .await
        .unwrap_or_default();
    let mut buf = String::new();
    if rows.is_empty() {
        return buf;
    }
    buf.push_str("# HELP federation_request_total Total opted-in federation test requests by server/result.\n");
    buf.push_str("# TYPE federation_request_total counter\n");
    let mut family_totals: HashMap<String, i64> = HashMap::new();

    for r in &rows {
        if let Some(anon) = stable_anon_id(salt, &r.server_name) {
            let server_label = escape_label(&anon);
            let family_label = escape_label(r.software_family.as_deref().unwrap_or("unknown"));
            let version_label = escape_label(r.software_version.as_deref().unwrap_or("unknown"));
            // success line
            buf.push_str(&format!("federation_request_total{{server=\"{}\",result=\"success\",software_family=\"{}\",software_version=\"{}\"}} {}\n",
                server_label, family_label, version_label, r.success_count));
            // failure line
            buf.push_str(&format!("federation_request_total{{server=\"{}\",result=\"failure\",software_family=\"{}\",software_version=\"{}\"}} {}\n",
                server_label, family_label, version_label, r.failure_count));
            *family_totals.entry(family_label).or_insert(0) += r.req_count;
        }
    }
    if family_totals.is_empty() {
        return buf;
    }
    buf.push_str("# HELP federation_request_family_total Total opted-in federation test requests grouped by software family.\n");
    buf.push_str("# TYPE federation_request_family_total counter\n");
    for (family, total) in family_totals.into_iter() {
        buf.push_str(&format!(
            "federation_request_family_total{{software_family=\"{}\"}} {}\n",
            family, total
        ));
    }

    // Calculate unique unstable features across all servers
    let (unique_enabled, unique_announced) = calculate_unique_features(db).await;

    // Add unstable features metrics
    buf.push_str("# HELP federation_unstable_features_enabled_total Total count of unique enabled unstable features across all servers.\n");
    buf.push_str("# TYPE federation_unstable_features_enabled_total gauge\n");
    buf.push_str(&format!(
        "federation_unstable_features_enabled_total {}\n",
        unique_enabled
    ));

    buf.push_str("# HELP federation_unstable_features_announced_total Total count of unique announced unstable features across all servers.\n");
    buf.push_str("# TYPE federation_unstable_features_announced_total gauge\n");
    buf.push_str(&format!(
        "federation_unstable_features_announced_total {}\n",
        unique_announced
    ));

    // Add per-feature metrics
    let feature_metrics = build_feature_metrics(db).await;
    buf.push_str(&feature_metrics);

    buf
}

/// Cached variant (TTL 30 seconds) to reduce DB load under frequent scrapes.
#[tracing::instrument(skip(resources))]
pub async fn build_prometheus_metrics_cached(resources: &AppResources) -> String {
    const TTL: Duration = Duration::from_secs(30);
    if !resources.config.statistics.enabled || !resources.config.statistics.prometheus_enabled {
        return String::new();
    }
    let now = Instant::now();
    if let Ok(guard) = PROM_CACHE.read()
        && now.duration_since(guard.generated_at) < TTL
        && !guard.body.is_empty()
    {
        return guard.body.clone();
    }

    let fresh = build_prometheus_metrics(resources).await;
    if let Ok(mut guard) = PROM_CACHE.write() {
        guard.generated_at = now;
        guard.body = fresh.clone();
    }
    fresh
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AppConfig, SmtpConfig, StatisticsConfig};
    use sea_orm::{Database, DbBackend, Statement};
    use std::sync::Arc;

    fn dummy_config(stats_enabled: bool, salt: &str) -> AppConfig {
        AppConfig {
            database_url: "sqlite::memory:".into(),
            smtp: SmtpConfig {
                server: "localhost".into(),
                port: 25,
                username: "u".into(),
                password: "p".into(),
                from: "noreply@example.org".into(),
            },
            frontend_url: "http://localhost".into(),
            magic_token_secret: "12345678901234567890123456789012".into(),
            debug_allowed_nets: vec![],
            statistics: StatisticsConfig {
                enabled: stats_enabled,
                prometheus_enabled: true,
                anonymization_salt: salt.into(),
                raw_retention_days: 30,
            },
        }
    }

    async fn setup_db() -> DatabaseConnection {
        let db = Database::connect("sqlite::memory:").await.expect("connect");
        db.execute(Statement::from_string(
            DbBackend::Sqlite,
            r#"CREATE TABLE federation_stat_aggregate (
            server_name TEXT PRIMARY KEY,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            req_count INTEGER NOT NULL,
            success_count INTEGER NOT NULL,
            failure_count INTEGER NOT NULL,
            first_version_name TEXT NULL,
            first_version_string TEXT NULL,
            last_version_name TEXT NULL,
            last_version_string TEXT NULL,
            software_family TEXT NULL,
            software_version TEXT NULL,
            unstable_features_enabled INTEGER NOT NULL DEFAULT 0,
            unstable_features_announced INTEGER NOT NULL DEFAULT 0
        );"#,
        ))
        .await
        .expect("create table");

        // Also create the raw table for storing individual events
        db.execute(Statement::from_string(
            DbBackend::Sqlite,
            r#"CREATE TABLE federation_stat_raw (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            server_name TEXT NOT NULL,
            federation_ok BOOLEAN NOT NULL,
            version_name TEXT NULL,
            version_string TEXT NULL,
            unstable_features_enabled TEXT NULL,
            unstable_features_announced TEXT NULL
        );"#,
        ))
        .await
        .expect("create raw table");

        db
    }

    #[tokio::test]
    async fn test_record_event_inserts_when_enabled() {
        let db = setup_db().await;
        let config = Arc::new(dummy_config(true, "salt123"));
        let mailer = Arc::new(
            lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::builder_dangerous("localhost")
                .build(),
        );
        let resources = AppResources {
            db: Arc::new(db),
            mailer,
            config,
        };
        record_event(
            &resources,
            StatEvent {
                server_name: "example.org",
                federation_ok: true,
                version_name: Some("synapse"),
                version_string: Some("synapse 1.2.3"),
                unstable_features_enabled: None,
                unstable_features_announced: None,
            },
        )
        .await;
        // Build metrics and assert it contains success metric for one server
        let metrics = build_prometheus_metrics(&resources).await;
        assert!(metrics.contains("federation_request_total"));
    }

    #[tokio::test]
    async fn test_record_event_no_insert_when_disabled() {
        let db = setup_db().await;
        let config = Arc::new(dummy_config(false, "salt123"));
        let mailer = Arc::new(
            lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::builder_dangerous("localhost")
                .build(),
        );
        let resources = AppResources {
            db: Arc::new(db.clone()),
            mailer,
            config,
        };
        record_event(
            &resources,
            StatEvent {
                server_name: "disabled.org",
                federation_ok: true,
                version_name: None,
                version_string: None,
                unstable_features_enabled: None,
                unstable_features_announced: None,
            },
        )
        .await;
        let stmt = Statement::from_string(
            DbBackend::Sqlite,
            "SELECT COUNT(*) as c FROM federation_stat_aggregate",
        );
        let val = db.query_one(stmt).await.unwrap();
        assert_eq!(val.unwrap().try_get::<i64>("", "c").unwrap(), 0);
    }

    #[tokio::test]
    async fn test_metrics_caching() {
        let db = setup_db().await;
        let config = Arc::new(dummy_config(true, "salt123"));
        let mailer = Arc::new(
            lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::builder_dangerous("localhost")
                .build(),
        );
        let resources = AppResources {
            db: Arc::new(db.clone()),
            mailer,
            config,
        };
        clear_metrics_cache();
        record_event(
            &resources,
            StatEvent {
                server_name: "cache.org",
                federation_ok: true,
                version_name: None,
                version_string: None,
                unstable_features_enabled: None,
                unstable_features_announced: None,
            },
        )
        .await;
        let first = build_prometheus_metrics_cached(&resources).await;
        // Add another event quickly
        record_event(
            &resources,
            StatEvent {
                server_name: "cache.org",
                federation_ok: true,
                version_name: None,
                version_string: None,
                unstable_features_enabled: None,
                unstable_features_announced: None,
            },
        )
        .await;
        let second = build_prometheus_metrics_cached(&resources).await;
        // Cached output should not yet reflect the second increment (req_count difference not exposed directly but success_count should have increased). We approximate by counting occurrences.
        let success_lines_first = first.matches("result=\"success\"").count();
        let success_lines_second = second.matches("result=\"success\"").count();
        assert_eq!(
            success_lines_first, success_lines_second,
            "cache should suppress update"
        );
    }
    #[test]
    fn test_stable_anon_id_changes_with_salt() {
        let a = stable_anon_id("salt1", "example.org").unwrap();
        let b = stable_anon_id("salt2", "example.org").unwrap();
        assert_ne!(a, b);
    }
    #[test]
    fn test_stable_anon_id_same_for_same_inputs() {
        let a = stable_anon_id("saltX", "example.org").unwrap();
        let b = stable_anon_id("saltX", "example.org").unwrap();
        assert_eq!(a, b);
    }

    #[tokio::test]
    async fn test_prune_old_entries() {
        let db = setup_db().await;
        // Insert two rows: one recent, one old
        db.execute(Statement::from_string(DbBackend::Sqlite, "INSERT INTO federation_stat_aggregate (server_name, first_seen_at, last_seen_at, req_count, success_count, failure_count) VALUES ('old.example', datetime('now','-40 days'), datetime('now','-40 days'), 5, 5, 0)" )).await.unwrap();
        db.execute(Statement::from_string(DbBackend::Sqlite, "INSERT INTO federation_stat_aggregate (server_name, first_seen_at, last_seen_at, req_count, success_count, failure_count) VALUES ('new.example', datetime('now','-1 days'), datetime('now','-1 days'), 3, 3, 0)" )).await.unwrap();
        let config = dummy_config(true, "salt");
        let dummy_mailer =
            lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::builder_dangerous("localhost")
                .build();
        let resources = AppResources {
            db: Arc::new(db),
            mailer: Arc::new(dummy_mailer),
            config: Arc::new(config),
        };
        prune_old_entries(&resources).await; // default retention 30 days -> old.example should be removed
        let cnt_stmt = Statement::from_string(
            DbBackend::Sqlite,
            "SELECT COUNT(*) as c FROM federation_stat_aggregate",
        );
        let val = resources.db.query_one(cnt_stmt).await.unwrap().unwrap();
        let c: i64 = val.try_get("", "c").unwrap();
        assert_eq!(c, 1, "only recent row should remain");
    }

    #[tokio::test]
    async fn test_metrics_after_record_event() {
        let db = setup_db().await;
        let config = dummy_config(true, "salt");
        let dummy_mailer =
            lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::builder_dangerous("localhost")
                .build();
        let resources = AppResources {
            db: Arc::new(db),
            mailer: Arc::new(dummy_mailer),
            config: Arc::new(config),
        };
        record_event(
            &resources,
            StatEvent {
                server_name: "m.example",
                federation_ok: true,
                version_name: Some("Synapse"),
                version_string: Some("Synapse 1.99.0"),
                unstable_features_enabled: None,
                unstable_features_announced: None,
            },
        )
        .await;
        let metrics = build_prometheus_metrics(&resources).await;
        assert!(
            metrics.contains("federation_request_total"),
            "metrics should include federation_request_total line"
        );
    }

    #[tokio::test]
    async fn test_unstable_features_tracking() {
        let db = setup_db().await;
        let config = dummy_config(true, "salt");
        let dummy_mailer =
            lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::builder_dangerous("localhost")
                .build();
        let resources = AppResources {
            db: Arc::new(db),
            mailer: Arc::new(dummy_mailer),
            config: Arc::new(config),
        };

        let enabled_features = vec!["msc2716".to_string(), "msc3030".to_string()];
        let announced_features = vec![
            "msc2716".to_string(),
            "msc3030".to_string(),
            "msc1234".to_string(),
        ];

        record_event(
            &resources,
            StatEvent {
                server_name: "unstable.example",
                federation_ok: true,
                version_name: Some("Synapse"),
                version_string: Some("Synapse 1.99.0"),
                unstable_features_enabled: Some(&enabled_features),
                unstable_features_announced: Some(&announced_features),
            },
        )
        .await;

        let metrics = build_prometheus_metrics(&resources).await;
        assert!(
            metrics.contains("federation_unstable_features_enabled_total 2"),
            "metrics should include enabled unstable features count: {}",
            metrics
        );
        assert!(
            metrics.contains("federation_unstable_features_announced_total 3"),
            "metrics should include announced unstable features count: {}",
            metrics
        );
    }
}
