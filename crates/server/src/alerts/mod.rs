//! Alert management module for recurring federation checks.
//!
//! This module handles:
//! - Background task management for alert checks
//! - Email notifications (failure, recovery)
//! - State machine for alert status tracking
//!
//! ## Submodules
//!
//! - `task_manager` - Task lifecycle management
//! - `email` - Email sending for notifications
//! - `checks` - Main check loop and state machine

pub mod checks;
pub mod email;
pub mod task_manager;

// Re-export commonly used items for backward compatibility
pub use checks::{CHECK_INTERVAL, recurring_alert_checks, should_send_failure_email};
pub use email::{
    REMINDER_EMAIL_INTERVAL, UnsubscribeHeader, generate_list_unsubscribe_url, send_failure_email,
    send_recovery_email,
};
pub use task_manager::{AlertCheckTask, AlertTaskManager};
