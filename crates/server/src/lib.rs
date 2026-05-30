//! Matrix federation tester server — HTTP API, alerts, OAuth2, and persistence layer.
//!
//! Pure federation-checking logic lives in the `matrix-federation-tester` library crate.
//! This crate wraps it with an Axum web server, PostgreSQL persistence, email alerts,
//! and distributed coordination.

use std::sync::Arc;

use reqwest::Client as HttpClient;
use sea_orm::DatabaseConnection;

use crate::config::AppConfig;

// Re-export the core library so existing callers using `rust_federation_tester::*`
// continue to work unchanged.
pub use matrix_federation_tester::{
    FederationConfig, connection_pool, error, federation, response, security, tls, validation,
};

pub mod alerts;
pub mod api;
pub mod backends;
pub mod client;
pub mod config;
pub mod distributed;
pub mod email_outbox;
pub mod email_templates;
pub mod entity;
pub mod net;
pub mod oauth2;
pub mod release_notes;
pub mod stats;

pub use backends::EmailSender;

#[derive(Clone, Debug)]
pub struct AppResources {
    pub db: Arc<DatabaseConnection>,
    /// `None` when `smtp.enabled = false` in config — email delivery is disabled.
    pub mailer: Option<Arc<dyn EmailSender>>,
    pub config: Arc<AppConfig>,
    /// Email idempotency guard — prevents duplicate alert emails when running
    /// multiple instances. Uses Redis/Valkey when configured, no-op otherwise.
    pub email_guard: distributed::EmailGuard,
    /// In-memory cache for release notes fetched from GitHub/Forgejo APIs.
    pub release_cache: Arc<release_notes::ReleaseCache>,
    /// Shared HTTP client for outbound webhook delivery.
    pub http_client: Arc<HttpClient>,
}
