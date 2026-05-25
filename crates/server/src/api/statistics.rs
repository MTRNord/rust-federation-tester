//! Statistics API endpoints.

use crate::AppResources;
use axum::{Extension, Json};
use hyper::StatusCode;
use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};
use serde::Serialize;

pub const STATISTICS_TAG: &str = "Statistics API";

#[derive(Serialize, Debug, utoipa::ToSchema)]
pub struct DailyPoint {
    /// ISO date string (YYYY-MM-DD, UTC)
    pub date: String,
    /// Number of successful federation tests on this day
    pub pass: i64,
    /// Number of failed federation tests on this day
    pub fail: i64,
}

#[derive(Serialize, Debug, utoipa::ToSchema)]
pub struct DailyStatsResponse {
    /// Daily pass/fail counts, ordered ascending, covering the last 14 days
    pub days: Vec<DailyPoint>,
}

/// Returns daily pass/fail counts for opted-in servers over the last 14 days.
#[tracing::instrument(skip(resources))]
#[utoipa::path(
    get,
    path = "/api/statistics/daily",
    tag = STATISTICS_TAG,
    operation_id = "Daily Statistics",
    summary = "Daily federation test outcomes (last 14 days)",
    description = "Returns per-day pass and fail counts for opted-in federation test requests over \
                   the last 14 days. Requires `statistics.enabled` to be `true` in server config.",
    responses(
        (status = 200, description = "Daily statistics", body = DailyStatsResponse),
        (status = 404, description = "Statistics disabled on this instance")
    )
)]
pub async fn daily_stats(
    Extension(resources): Extension<AppResources>,
) -> Result<Json<DailyStatsResponse>, StatusCode> {
    if !resources.config.statistics.enabled {
        return Err(StatusCode::NOT_FOUND);
    }

    let db = &*resources.db;
    let backend = db.get_database_backend();

    let sql = match backend {
        DatabaseBackend::Postgres => "SELECT \
                TO_CHAR(DATE_TRUNC('day', ts AT TIME ZONE 'UTC'), 'YYYY-MM-DD') AS day, \
                SUM(CASE WHEN federation_ok THEN 1 ELSE 0 END)::bigint AS pass, \
                SUM(CASE WHEN NOT federation_ok THEN 1 ELSE 0 END)::bigint AS fail \
             FROM federation_stat_raw \
             WHERE ts >= NOW() - INTERVAL '14 days' \
             GROUP BY DATE_TRUNC('day', ts AT TIME ZONE 'UTC') \
             ORDER BY day ASC"
            .to_string(),
        DatabaseBackend::Sqlite => "SELECT \
                date(ts) AS day, \
                SUM(CASE WHEN federation_ok = 1 THEN 1 ELSE 0 END) AS pass, \
                SUM(CASE WHEN federation_ok = 0 THEN 1 ELSE 0 END) AS fail \
             FROM federation_stat_raw \
             WHERE ts >= datetime('now', '-14 days') \
             GROUP BY date(ts) \
             ORDER BY day ASC"
            .to_string(),
        DatabaseBackend::MySql => "SELECT \
                DATE_FORMAT(ts, '%Y-%m-%d') AS day, \
                SUM(CASE WHEN federation_ok = 1 THEN 1 ELSE 0 END) AS pass, \
                SUM(CASE WHEN federation_ok = 0 THEN 1 ELSE 0 END) AS fail \
             FROM federation_stat_raw \
             WHERE ts >= NOW() - INTERVAL 14 DAY \
             GROUP BY DATE(ts) \
             ORDER BY day ASC"
            .to_string(),
    };

    let rows = db
        .query_all(Statement::from_string(backend, sql))
        .await
        .map_err(|e| {
            tracing::warn!("daily_stats query failed: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let days = rows
        .iter()
        .filter_map(|row| {
            let date: String = row.try_get("", "day").ok()?;
            let pass: i64 = row.try_get("", "pass").ok()?;
            let fail: i64 = row.try_get("", "fail").ok()?;
            Some(DailyPoint { date, pass, fail })
        })
        .collect();

    Ok(Json(DailyStatsResponse { days }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use axum_test::TestServer;
    use migration::{Migrator, MigratorTrait};
    use sea_orm::Database;
    use std::sync::Arc;

    async fn make_server(stats_enabled: bool) -> TestServer {
        let db = Arc::new(Database::connect("sqlite::memory:").await.unwrap());
        Migrator::up(db.as_ref(), None).await.unwrap();

        let config = Arc::new(crate::config::AppConfig {
            database_url: "sqlite::memory:".to_string(),
            listen_addr: None,
            smtp: Default::default(),
            frontend_url: "https://app.example.com".to_string(),
            magic_token_secret: "s".to_string(),
            debug_allowed_nets: vec![],
            trusted_proxy_nets: vec![],
            statistics: crate::config::StatisticsConfig {
                enabled: stats_enabled,
                ..Default::default()
            },
            oauth2: Default::default(),
            federation_timeout_secs: 3,
            allow_private_targets: false,
            redis: Default::default(),
            environment_name: None,
            github_sponsors_url: None,
            liberapay_url: None,
            email_log_retention_days: 7,
            release_sources: Default::default(),
            max_webhooks_per_alert: None,
        });

        let resources = crate::AppResources {
            db,
            mailer: None,
            config,
            email_guard: crate::distributed::EmailGuard::Noop,
            release_cache: Arc::new(dashmap::DashMap::new()),
            http_client: Arc::new(reqwest::Client::new()),
        };

        let app = axum::Router::new()
            .route("/api/statistics/daily", get(daily_stats))
            .layer(axum::Extension(resources));
        TestServer::new(app)
    }

    #[tokio::test]
    async fn daily_stats_returns_404_when_disabled() {
        let server = make_server(false).await;
        let resp = server.get("/api/statistics/daily").await;
        assert_eq!(resp.status_code(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn daily_stats_returns_200_with_empty_days_when_enabled() {
        let server = make_server(true).await;
        let resp = server.get("/api/statistics/daily").await;
        assert_eq!(resp.status_code(), StatusCode::OK);
        let body: serde_json::Value = resp.json();
        assert!(body["days"].as_array().unwrap().is_empty());
    }
}
