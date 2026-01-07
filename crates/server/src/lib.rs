//! A library for testing Matrix federation compatibility of servers.
//!
//! This library allows checking Matrix federation compatibility for a given server
//! by validating DNS records, well-known configurations, and connection details.

use std::sync::Arc;

use lettre::{AsyncSmtpTransport, Tokio1Executor};
use sea_orm::DatabaseConnection;

use crate::config::AppConfig;

pub mod api;
pub mod client;
pub mod config;
pub mod connection_pool;
pub mod email_templates;
pub mod entity;
pub mod error;
pub mod federation;
pub mod logging;
pub mod optimization;
pub mod recurring_alerts;
pub mod response;
pub mod security;
pub mod stats;
pub mod validation;

#[derive(Clone, Debug)]
pub struct AppResources {
    pub db: Arc<DatabaseConnection>,
    pub mailer: Arc<AsyncSmtpTransport<Tokio1Executor>>,
    pub config: Arc<AppConfig>,
}
