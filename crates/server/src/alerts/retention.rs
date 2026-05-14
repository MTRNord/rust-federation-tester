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
