//! Pure library for testing Matrix server federation compliance.
//!
//! Call [`response::generate_json_report`] to run a full federation check
//! against a Matrix server name and receive a structured [`response::Root`] report.

pub mod config;
pub mod connection_pool;
pub mod error;
pub mod federation;
pub mod response;
pub mod security;
pub mod tls;
pub mod validation;

pub use config::FederationConfig;
pub use error::{FederationError, FetchError, WellKnownError};
pub use response::{Root, generate_json_report};
