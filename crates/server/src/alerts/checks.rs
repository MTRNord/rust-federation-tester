//! Recurring federation check execution.
//!
//! Contains the main background loop for checking federation status
//! and the state machine logic for determining when to send emails.

use crate::AppResources;
use crate::alerts::email::{REMINDER_EMAIL_INTERVAL, send_failure_email, send_recovery_email};
use crate::alerts::task_manager::AlertTaskManager;
use crate::connection_pool::ConnectionPool;
use crate::entity::{alert, alert_status_history};
use crate::response::generate_json_report;
use hickory_resolver::Resolver;
use hickory_resolver::name_server::ConnectionProvider;
use sea_orm::{ActiveModelTrait, ActiveValue, ColumnTrait, EntityTrait, QueryFilter};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use time::OffsetDateTime;
use tokio::time::Duration;

/// Check interval - how frequently each alert is checked.
pub const CHECK_INTERVAL: Duration = Duration::from_secs(5 * 60); // 5 minutes

/// Stability window for flap detection. If a server recovered less than this
/// duration ago, a new failure is treated as flapping rather than a new incident.
pub const FLAP_STABILITY_WINDOW: Duration = Duration::from_secs(30 * 60); // 30 minutes

/// Determine if we should send a failure email based on alert state and timing.
#[tracing::instrument(skip_all)]
pub fn should_send_failure_email(alert: &alert::Model, now: OffsetDateTime) -> bool {
    // If server just started failing (transition from OK)
    if !alert.is_currently_failing {
        // Check if we recently recovered - if so, this is flapping
        if let Some(last_recovery) = alert.last_recovery_at {
            let time_since_recovery = now - last_recovery;
            let stability_window: time::Duration = FLAP_STABILITY_WINDOW.try_into().unwrap();
            if time_since_recovery < stability_window {
                // Flapping - don't treat as new incident.
                // Use last_email_sent_at to decide on reminder timing instead.
                if let Some(last_email) = alert.last_email_sent_at {
                    let time_since_last_email = now - last_email;
                    let reminder_threshold: time::Duration =
                        REMINDER_EMAIL_INTERVAL.try_into().unwrap();
                    return time_since_last_email >= reminder_threshold;
                }
                // Never sent an email, send now
                return true;
            }
        }
        // Not flapping - genuine new failure
        return true;
    }

    // Already failing - check reminder interval
    let Some(last_email) = alert.last_email_sent_at else {
        return true;
    };

    let time_since_last_email = now - last_email;
    let reminder_threshold: time::Duration = REMINDER_EMAIL_INTERVAL.try_into().unwrap();
    time_since_last_email >= reminder_threshold
}

/// Log a status event to the alert_status_history table.
async fn log_status_event(
    db: &sea_orm::DatabaseConnection,
    alert_id: i32,
    server_name: &str,
    event_type: &str,
    federation_ok: bool,
    failure_count: i32,
    details: Option<String>,
) {
    let entry = alert_status_history::ActiveModel {
        id: ActiveValue::NotSet,
        alert_id: ActiveValue::Set(alert_id),
        server_name: ActiveValue::Set(server_name.to_string()),
        event_type: ActiveValue::Set(event_type.to_string()),
        federation_ok: ActiveValue::Set(federation_ok),
        failure_count: ActiveValue::Set(failure_count),
        created_at: ActiveValue::Set(OffsetDateTime::now_utc()),
        details: ActiveValue::Set(details),
    };

    if let Err(e) = entry.insert(db).await {
        tracing::error!(
            name = "alerts.status_history.insert_failed",
            target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            error = %e,
            alert_id = alert_id,
            server_name = %server_name,
            event_type = %event_type,
            message = "Failed to log status event to alert_status_history"
        );
    }
}

/// Main loop for recurring alert checks.
///
/// This function runs indefinitely, periodically checking all verified alerts
/// and spawning individual check tasks for each one.
#[tracing::instrument(skip_all)]
pub async fn recurring_alert_checks<P: ConnectionProvider + Send + Sync + 'static>(
    resources: Arc<AppResources>,
    task_manager: Arc<AlertTaskManager>,
    resolver: Arc<Resolver<P>>,
    connection_pool: ConnectionPool,
) {
    loop {
        // 1. Load all verified alerts
        let alerts = alert::Entity::find()
            .filter(alert::Column::Verified.eq(true))
            .all(resources.db.as_ref())
            .await
            .unwrap_or_default();

        // 2. Start or restart a task for each verified alert
        // Distribute the checks over the CHECK_INTERVAL to avoid all checking at once
        let total_alerts = alerts.len();
        let stagger_interval = if total_alerts > 1 {
            CHECK_INTERVAL.as_secs() / total_alerts as u64
        } else {
            0
        };

        for (index, a) in alerts.iter().enumerate() {
            let alert_id = a.id;

            // Skip if task is already running for this alert
            if task_manager.is_running(alert_id).await {
                continue;
            }

            let email = a.email.clone();
            let server_name = a.server_name.clone();
            let resolver = resolver.clone();
            let connection_pool = connection_pool.clone();
            let mailer = resources.mailer.clone();
            let config = resources.config.clone();
            let db = resources.db.clone();
            let initial_delay = Duration::from_secs(stagger_interval * index as u64);

            task_manager
                .start_or_restart_task(alert_id, move |flag| {
                    Box::pin(async move {
                        // Stagger the initial start time to distribute load (only on first start)
                        if initial_delay.as_secs() > 0 {
                            tracing::info!(
                                name = "alerts.task.initial_delay",
                                target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                                message = "Alert check scheduled",
                                server_name = %server_name,
                                delay_seconds = initial_delay.as_secs()
                            );
                            tokio::time::sleep(initial_delay).await;
                        }

                        while flag.load(Ordering::SeqCst) {
                            tracing::info!(
                                name = "alerts.check.running",
                                target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                                message = "Running recurring alert check",
                                server_name = %server_name,
                            );

                            // Perform the federation check
                            let report =
                                generate_json_report(&server_name, &resolver, &connection_pool)
                                    .await;

                            let now = OffsetDateTime::now_utc();

                            match report {
                                Ok(report) => {
                                    // Update alert state in database
                                    if let Ok(Some(alert_model)) =
                                        alert::Entity::find_by_id(alert_id).one(db.as_ref()).await
                                    {
                                        let mut alert_active: alert::ActiveModel =
                                            alert_model.clone().into();
                                        alert_active.last_check_at = ActiveValue::Set(Some(now));

                                        if !report.federation_ok {
                                            // Server is failing
                                            let send_email =
                                                should_send_failure_email(&alert_model, now);

                                            // Log the check failure
                                            log_status_event(
                                                db.as_ref(),
                                                alert_id,
                                                &server_name,
                                                "check_fail",
                                                false,
                                                alert_model.failure_count + 1,
                                                None,
                                            )
                                            .await;

                                            // Update failure state
                                            if !alert_model.is_currently_failing {
                                                // Transition from OK to FAILING
                                                alert_active.is_currently_failing =
                                                    ActiveValue::Set(true);
                                                alert_active.failure_count = ActiveValue::Set(1);
                                                alert_active.last_failure_at =
                                                    ActiveValue::Set(Some(now));
                                                tracing::info!(
                                                    name = "alerts.state.transition_to_failing",
                                                    target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                                                    message = "Server transitioned to failing state",
                                                    server_name = %server_name,
                                                    alert_id = alert_id
                                                );
                                            } else {
                                                // Still failing, increment counter
                                                alert_active.failure_count =
                                                    ActiveValue::Set(alert_model.failure_count + 1);
                                                alert_active.last_failure_at =
                                                    ActiveValue::Set(Some(now));
                                            }

                                            // Save state before potentially sending email
                                            if let Ok(updated_alert) =
                                                alert_active.update(db.as_ref()).await
                                                && send_email
                                            {
                                                // Determine email event type
                                                let email_event_type =
                                                    if updated_alert.failure_count > 1 {
                                                        "email_reminder"
                                                    } else {
                                                        "email_failure"
                                                    };

                                                send_failure_email(
                                                    &mailer,
                                                    &config,
                                                    &db,
                                                    &email,
                                                    &server_name,
                                                    alert_id,
                                                    updated_alert.failure_count,
                                                )
                                                .await;

                                                // Log the email event
                                                log_status_event(
                                                    db.as_ref(),
                                                    alert_id,
                                                    &server_name,
                                                    email_event_type,
                                                    false,
                                                    updated_alert.failure_count,
                                                    None,
                                                )
                                                .await;

                                                // Update last_email_sent_at
                                                let mut email_update: alert::ActiveModel =
                                                    updated_alert.into();
                                                email_update.last_email_sent_at =
                                                    ActiveValue::Set(Some(now));
                                                let _ = email_update.update(db.as_ref()).await;
                                            }
                                        } else {
                                            // Server is OK
                                            if alert_model.is_currently_failing {
                                                // Transition from FAILING to OK - send recovery email
                                                alert_active.is_currently_failing =
                                                    ActiveValue::Set(false);
                                                alert_active.last_success_at =
                                                    ActiveValue::Set(Some(now));
                                                alert_active.last_recovery_at =
                                                    ActiveValue::Set(Some(now));

                                                // Log the check success (recovery)
                                                log_status_event(
                                                    db.as_ref(),
                                                    alert_id,
                                                    &server_name,
                                                    "check_ok",
                                                    true,
                                                    alert_model.failure_count,
                                                    Some("recovered from failing state".to_string()),
                                                )
                                                .await;

                                                if alert_active.update(db.as_ref()).await.is_ok() {
                                                    send_recovery_email(
                                                        &mailer,
                                                        &config,
                                                        &db,
                                                        &email,
                                                        &server_name,
                                                        alert_id,
                                                    )
                                                    .await;

                                                    // Log the recovery email event
                                                    log_status_event(
                                                        db.as_ref(),
                                                        alert_id,
                                                        &server_name,
                                                        "email_recovery",
                                                        true,
                                                        alert_model.failure_count,
                                                        None,
                                                    )
                                                    .await;

                                                    // Update last_email_sent_at
                                                    if let Ok(Some(alert_for_update)) =
                                                        alert::Entity::find_by_id(alert_id)
                                                            .one(db.as_ref())
                                                            .await
                                                    {
                                                        let mut email_update: alert::ActiveModel =
                                                            alert_for_update.into();
                                                        email_update.last_email_sent_at =
                                                            ActiveValue::Set(Some(now));
                                                        let _ =
                                                            email_update.update(db.as_ref()).await;
                                                    }
                                                }
                                                tracing::info!(
                                                    name = "alerts.state.recovered",
                                                    target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                                                    message = "Server recovered to healthy state",
                                                    server_name = %server_name,
                                                    alert_id = alert_id
                                                );
                                            } else {
                                                // Still OK, just update check time and success time
                                                alert_active.last_success_at =
                                                    ActiveValue::Set(Some(now));
                                                let _ = alert_active.update(db.as_ref()).await;
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::error!(
                                        name = "alerts.recurring_check.error",
                                        target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                                        server_name = %server_name,
                                        error = ?e,
                                        message = "Federation check error"
                                    );
                                }
                            }

                            // Check every 5 minutes
                            tokio::time::sleep(CHECK_INTERVAL).await;
                        }
                        tracing::info!(
                            name = "alerts.task.stopped",
                            target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                            message = "Stopped recurring check for alert",
                            server_name = %server_name,
                        );
                    })
                })
                .await;
        }

        // 3. Remove tasks for alerts that no longer exist or are unverified
        let running = task_manager.running.write().await;
        let mut to_remove = Vec::new();
        for (alert_id, _) in running.iter() {
            if !alerts.iter().any(|a| &a.id == alert_id) {
                to_remove.push(*alert_id);
            }
        }
        drop(running);
        for alert_id in to_remove {
            task_manager.stop_task(alert_id).await;
        }

        // 4. Clean up unverified alerts older than 1 day
        let cutoff = OffsetDateTime::now_utc() - time::Duration::days(1);
        let _ = alert::Entity::delete_many()
            .filter(alert::Column::Verified.eq(false))
            .filter(alert::Column::CreatedAt.lt(cutoff))
            .exec(resources.db.as_ref())
            .await;

        // 5. Clean up old status history entries (keep 30 days)
        let history_cutoff = OffsetDateTime::now_utc() - time::Duration::days(30);
        let _ = alert_status_history::Entity::delete_many()
            .filter(alert_status_history::Column::CreatedAt.lt(history_cutoff))
            .exec(resources.db.as_ref())
            .await;

        // 6. Wait for a while before next full scan
        tokio::time::sleep(Duration::from_secs(300)).await; // 5 min
    }
}
