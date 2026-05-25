//! Retention pruning for the email notification log.

use crate::AppResources;
use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};
use std::time::Duration;

/// Delete `email_log` rows older than `email_log_retention_days` days.
///
/// Rows are also deleted when the owning user deletes their account, so this
/// task only needs to clean up orphaned rows (e.g. after an alert is deleted
/// without account deletion).
#[tracing::instrument(skip(resources))]
pub async fn prune_old_email_log_entries(resources: &AppResources) {
    let days = resources.config.email_log_retention_days as i64;
    if days == 0 {
        return;
    }
    let db = &*resources.db;
    let backend = db.get_database_backend();
    let sql = match backend {
        DatabaseBackend::Postgres => {
            "DELETE FROM email_log WHERE sent_at < NOW() - ($1::interval)".to_string()
        }
        DatabaseBackend::Sqlite => {
            format!("DELETE FROM email_log WHERE sent_at < datetime('now','-{days} days')")
        }
        DatabaseBackend::MySql => {
            format!("DELETE FROM email_log WHERE sent_at < (NOW() - INTERVAL {days} DAY)")
        }
    };
    let stmt = match backend {
        DatabaseBackend::Postgres => {
            Statement::from_sql_and_values(backend, sql, vec![format!("{days} days").into()])
        }
        _ => Statement::from_string(backend, sql),
    };
    if let Err(e) = db.execute(stmt).await {
        tracing::warn!(
            name: "alerts.prune_email_log",
            target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            error = %e,
            message = "prune_old_email_log_entries failed",
        );
    }
}

/// Spawn a background task that prunes old email log entries every 24 hours.
#[tracing::instrument(skip(resources))]
pub fn spawn_email_log_retention_task(resources: std::sync::Arc<AppResources>) {
    let days = resources.config.email_log_retention_days;
    if days == 0 {
        return;
    }
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_hours(24));
        loop {
            interval.tick().await;
            prune_old_email_log_entries(&resources).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use migration::{Migrator, MigratorTrait};
    use sea_orm::{ActiveModelTrait, ActiveValue::Set, Database, EntityTrait};
    use std::sync::Arc;
    use time::OffsetDateTime;

    async fn make_resources(retention_days: u32) -> Arc<AppResources> {
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
            statistics: Default::default(),
            oauth2: Default::default(),
            federation_timeout_secs: 3,
            allow_private_targets: false,
            redis: Default::default(),
            environment_name: None,
            github_sponsors_url: None,
            liberapay_url: None,
            email_log_retention_days: retention_days,
            release_sources: Default::default(),
            max_webhooks_per_alert: None,
        });
        Arc::new(AppResources {
            db,
            mailer: None,
            config,
            email_guard: crate::distributed::EmailGuard::Noop,
            release_cache: Arc::new(dashmap::DashMap::new()),
            http_client: Arc::new(reqwest::Client::new()),
        })
    }

    async fn insert_email_log_row(resources: &AppResources, days_ago: i64) {
        use crate::entity::email_log;
        use sea_orm::ActiveValue::NotSet;
        let sent_at = OffsetDateTime::now_utc() - time::Duration::days(days_ago);
        email_log::ActiveModel {
            id: NotSet,
            alert_id: Set(1),
            email: Set("a@example.com".to_string()),
            email_type: Set("failure".to_string()),
            server_name: Set("s.example.com".to_string()),
            sent_at: Set(sent_at),
            failure_count: Set(None),
        }
        .insert(resources.db.as_ref())
        .await
        .unwrap();
    }

    async fn email_log_count(resources: &AppResources) -> usize {
        crate::entity::email_log::Entity::find()
            .all(resources.db.as_ref())
            .await
            .unwrap()
            .len()
    }

    #[tokio::test]
    async fn prune_skips_when_days_is_zero() {
        let resources = make_resources(0).await;
        insert_email_log_row(&resources, 100).await;
        prune_old_email_log_entries(&resources).await;
        assert_eq!(
            email_log_count(&resources).await,
            1,
            "should not prune when days=0"
        );
    }

    #[tokio::test]
    async fn prune_deletes_old_rows() {
        let resources = make_resources(7).await;
        insert_email_log_row(&resources, 10).await; // 10 days ago — should be deleted
        insert_email_log_row(&resources, 1).await; // 1 day ago — should be kept
        assert_eq!(email_log_count(&resources).await, 2);
        prune_old_email_log_entries(&resources).await;
        assert_eq!(
            email_log_count(&resources).await,
            1,
            "old row should be pruned"
        );
    }

    #[tokio::test]
    async fn prune_keeps_recent_rows() {
        let resources = make_resources(7).await;
        insert_email_log_row(&resources, 1).await;
        prune_old_email_log_entries(&resources).await;
        assert_eq!(
            email_log_count(&resources).await,
            1,
            "recent row should remain"
        );
    }

    #[tokio::test]
    async fn spawn_task_does_not_panic_when_days_zero() {
        let resources = make_resources(0).await;
        // days=0 → early return, no spawn, no panic
        spawn_email_log_retention_task(resources);
    }
}
