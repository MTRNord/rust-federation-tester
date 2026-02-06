//! OAuth2 Authorization Server module.
//!
//! This module implements an OAuth2 authorization server using oxide-auth,
//! acting as the central identity manager for the federation tester.
//!
//! ## Supported Flows
//!
//! - Authorization Code with PKCE (recommended for SPAs and native apps)
//! - Refresh Token
//!
//! ## Endpoints
//!
//! - `GET /oauth2/authorize` - Authorization endpoint
//! - `POST /oauth2/token` - Token endpoint
//! - `POST /oauth2/revoke` - Token revocation
//! - `GET /oauth2/userinfo` - OpenID Connect UserInfo
//! - `GET /.well-known/openid-configuration` - OpenID Connect Discovery

pub mod consent;
pub mod endpoints;
pub mod identity;
pub mod login;
pub mod password;
pub mod register;
mod registrar;
mod state;

pub use endpoints::router;
pub use identity::IdentityService;
pub use password::{generate_verification_token, hash_password, verify_password};
pub use state::OAuth2State;

/// OpenAPI tag for OAuth2 endpoints
pub const OAUTH2_TAG: &str = "OAuth2";
