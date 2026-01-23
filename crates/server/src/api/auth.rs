//! Authentication extractors for dual-auth support.
//!
//! Provides Axum extractors that support OAuth2 access tokens for the v2 API.

use crate::AppResources;
use crate::entity::{oauth2_token, oauth2_user};
use axum::{
    Json,
    extract::FromRequestParts,
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response},
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Required scope for reading alerts
pub const SCOPE_ALERTS_READ: &str = "alerts:read";
/// Required scope for creating/modifying alerts
pub const SCOPE_ALERTS_WRITE: &str = "alerts:write";

/// Represents the authenticated identity from OAuth2.
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    /// User's email address
    pub email: String,
    /// OAuth2 user ID
    pub user_id: String,
    /// Scopes granted by the token
    pub scopes: Vec<String>,
    /// Whether the user's email is verified
    pub email_verified: bool,
}

impl AuthenticatedUser {
    /// Check if the user has a specific OAuth2 scope
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }
}

/// Error type for authentication failures
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AuthError {
    /// Error code (e.g., "invalid_token", "insufficient_scope")
    pub error: String,
    /// Human-readable error description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

impl AuthError {
    pub fn invalid_token(description: impl Into<String>) -> Self {
        Self {
            error: "invalid_token".to_string(),
            error_description: Some(description.into()),
        }
    }

    pub fn insufficient_scope(required_scope: &str) -> Self {
        Self {
            error: "insufficient_scope".to_string(),
            error_description: Some(format!("Token requires '{}' scope", required_scope)),
        }
    }

    pub fn forbidden(description: impl Into<String>) -> Self {
        Self {
            error: "forbidden".to_string(),
            error_description: Some(description.into()),
        }
    }

    pub fn not_found(description: impl Into<String>) -> Self {
        Self {
            error: "not_found".to_string(),
            error_description: Some(description.into()),
        }
    }

    pub fn bad_request(description: impl Into<String>) -> Self {
        Self {
            error: "bad_request".to_string(),
            error_description: Some(description.into()),
        }
    }

    pub fn server_error() -> Self {
        Self {
            error: "server_error".to_string(),
            error_description: None,
        }
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let status = match self.error.as_str() {
            "invalid_token" => StatusCode::UNAUTHORIZED,
            "insufficient_scope" | "forbidden" => StatusCode::FORBIDDEN,
            "not_found" => StatusCode::NOT_FOUND,
            "bad_request" | "alert_exists" => StatusCode::BAD_REQUEST,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, Json(self)).into_response()
    }
}

/// Axum extractor that validates OAuth2 Bearer tokens.
///
/// Extracts `Authorization: Bearer <token>` header and validates
/// against the oauth2_token table.
///
/// # Example
///
/// ```ignore
/// async fn handler(OAuth2Auth(user): OAuth2Auth) -> impl IntoResponse {
///     format!("Hello, {}", user.email)
/// }
/// ```
pub struct OAuth2Auth(pub AuthenticatedUser);

impl<S> FromRequestParts<S> for OAuth2Auth
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Get AppResources from extensions
        let resources = parts
            .extensions
            .get::<AppResources>()
            .cloned()
            .ok_or_else(|| {
                tracing::error!("AppResources not found in extensions");
                AuthError::server_error()
            })?;

        // Extract Bearer token from Authorization header
        let auth_header = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok());

        let access_token = match auth_header {
            Some(header) if header.starts_with("Bearer ") => &header[7..],
            Some(_) => {
                return Err(AuthError::invalid_token(
                    "Authorization header must use Bearer scheme",
                ));
            }
            None => {
                return Err(AuthError::invalid_token("Missing Authorization header"));
            }
        };

        // Validate token in database
        let token = oauth2_token::Entity::find()
            .filter(oauth2_token::Column::AccessToken.eq(access_token))
            .one(resources.db.as_ref())
            .await
            .map_err(|e| {
                tracing::error!("Database error looking up token: {}", e);
                AuthError::server_error()
            })?
            .ok_or_else(|| AuthError::invalid_token("Token not found"))?;

        // Check token validity (not expired, not revoked)
        if !token.is_valid() {
            if token.is_revoked() {
                return Err(AuthError::invalid_token("Token has been revoked"));
            }
            if token.is_access_token_expired() {
                return Err(AuthError::invalid_token("Token has expired"));
            }
            return Err(AuthError::invalid_token("Token is not valid"));
        }

        // Fetch user info
        let user = oauth2_user::Entity::find_by_id(&token.user_id)
            .one(resources.db.as_ref())
            .await
            .map_err(|e| {
                tracing::error!("Database error looking up user: {}", e);
                AuthError::server_error()
            })?
            .ok_or_else(|| {
                tracing::error!("User not found for token user_id: {}", token.user_id);
                AuthError::invalid_token("User not found")
            })?;

        Ok(OAuth2Auth(AuthenticatedUser {
            email: user.email,
            user_id: user.id,
            scopes: token.scopes_list(),
            email_verified: user.email_verified,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_error_status_codes() {
        let error = AuthError::invalid_token("test");
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let error = AuthError::insufficient_scope("test");
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let error = AuthError::forbidden("test");
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let error = AuthError::not_found("test");
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let error = AuthError::bad_request("test");
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let error = AuthError::server_error();
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_authenticated_user_has_scope() {
        let user = AuthenticatedUser {
            email: "test@example.com".to_string(),
            user_id: "user-123".to_string(),
            scopes: vec!["alerts:read".to_string(), "openid".to_string()],
            email_verified: true,
        };

        assert!(user.has_scope("alerts:read"));
        assert!(user.has_scope("openid"));
        assert!(!user.has_scope("alerts:write"));
    }
}
