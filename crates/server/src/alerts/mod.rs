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

pub mod checks;
pub mod email;

// Re-export commonly used items
pub use checks::{
    ACTIVE_CHECK_INTERVAL, CHECK_INTERVAL, CONFIRMATION_THRESHOLD, ConfirmationRegistry,
    active_check_loop, healthy_check_loop, should_send_reminder_email,
};
pub use email::{
    EmailError, REMINDER_EMAIL_INTERVAL, UnsubscribeHeader, generate_list_unsubscribe_url,
    send_failure_email, send_recovery_email,
};
