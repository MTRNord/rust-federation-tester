//! Alert management module for recurring federation checks.
//!
//! This module handles:
//! - Background batch loops for alert checks (healthy 5-min / active 1-min)
//! - Email notifications (failure, recovery)
//! - State machine for alert status tracking
//!
//! ## Submodules
//!
//! - `email` - Email sending for notifications
//! - `checks` - Two batch check loops and reminder logic

pub mod change_checks;
pub mod checks;
pub mod email;
pub mod retention;
pub mod webhook;

// Re-export commonly used items
pub use checks::{
    ACTIVE_CHECK_INTERVAL, CHECK_INTERVAL, CONFIRMATION_THRESHOLD, active_check_loop,
    healthy_check_loop, should_send_reminder_email,
};
pub use email::{
    EmailError, REMINDER_EMAIL_INTERVAL, UnsubscribeHeader, generate_list_unsubscribe_url,
    send_failure_email, send_recovery_email,
};
pub use retention::spawn_email_log_retention_task;
pub use webhook::{
    compute_signature, enqueue_for_alert, enqueue_ping, spawn_worker as spawn_webhook_worker,
};
