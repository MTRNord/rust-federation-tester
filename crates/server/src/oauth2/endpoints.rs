//! OAuth2 HTTP endpoints.
//!
//! Implements the OAuth2 authorization server endpoints:
//! - Authorization endpoint
//! - Token endpoint
//! - Token revocation
//! - UserInfo (OpenID Connect)
//! - Discovery document

use crate::AppResources;
use crate::entity::{oauth2_client, oauth2_token, oauth2_user};
use crate::oauth2::{OAUTH2_TAG, state::OAuth2State};
use axum::{
    Extension, Form, Json,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

/// Creates the OAuth2 router.
pub fn router(state: OAuth2State) -> OpenApiRouter {
    OpenApiRouter::new()
        .routes(routes!(authorize))
        .routes(routes!(token))
        .routes(routes!(revoke))
        .routes(routes!(userinfo))
        .routes(routes!(openid_configuration))
        .with_state(state)
}

// =============================================================================
// Request/Response Types
// =============================================================================

/// OAuth2 authorization request parameters.
#[derive(Debug, Deserialize, ToSchema)]
pub struct AuthorizeRequest {
    /// Must be "code" for Authorization Code flow
    pub response_type: String,
    /// Client identifier issued during registration
    pub client_id: String,
    /// Redirect URI (must match registered URI)
    pub redirect_uri: Option<String>,
    /// Space-separated list of requested scopes
    pub scope: Option<String>,
    /// Opaque value for CSRF protection
    pub state: Option<String>,
    /// String for replay protection (included in ID token)
    pub nonce: Option<String>,
    /// PKCE code challenge (base64url-encoded)
    pub code_challenge: Option<String>,
    /// PKCE method: "S256" or "plain"
    pub code_challenge_method: Option<String>,
    /// Email hint to pre-fill login form
    pub login_hint: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    pub code_verifier: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    pub scope: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorResponse {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RevokeRequest {
    pub token: String,
    pub token_type_hint: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UserInfoResponse {
    pub sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct OpenIdConfiguration {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub revocation_endpoint: String,
    pub response_types_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub subject_types_supported: Vec<String>,
    pub scopes_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    pub code_challenge_methods_supported: Vec<String>,
}

// =============================================================================
// Endpoints
// =============================================================================

/// OAuth2 Authorization endpoint.
///
/// For this implementation, since we use magic links for authentication,
/// the authorization endpoint initiates the magic link flow and redirects
/// back with an authorization code after the user verifies their email.
#[tracing::instrument(skip(state, resources))]
#[utoipa::path(
    get,
    path = "/authorize",
    tag = OAUTH2_TAG,
    operation_id = "OAuth2 Authorize",
    summary = "Initiate OAuth2 authorization flow",
    description = "Starts the OAuth2 Authorization Code flow. The user is redirected to the login page \
                   where they verify their identity via email magic link. After verification, the user \
                   is redirected back to the client's redirect_uri with an authorization code.\n\n\
                   **PKCE Support:** For public clients (SPAs), use code_challenge and code_challenge_method \
                   parameters. S256 method is recommended.\n\n\
                   **Supported scopes:** `openid`, `profile`, `email`",
    params(
        ("response_type" = String, Query, description = "OAuth2 response type. Must be `code` for Authorization Code flow."),
        ("client_id" = String, Query, description = "The client identifier issued during client registration."),
        ("redirect_uri" = Option<String>, Query, description = "URI to redirect the user after authorization. Must match a registered redirect URI for the client."),
        ("scope" = Option<String>, Query, description = "Space-separated list of requested scopes (e.g., `openid profile email`)."),
        ("state" = Option<String>, Query, description = "Opaque value for CSRF protection. Returned unchanged in the redirect."),
        ("nonce" = Option<String>, Query, description = "String value for replay protection. Included in the ID token if provided."),
        ("code_challenge" = Option<String>, Query, description = "PKCE code challenge. Required for public clients. Base64url-encoded SHA256 hash of code_verifier."),
        ("code_challenge_method" = Option<String>, Query, description = "PKCE challenge method. Either `S256` (recommended) or `plain`."),
        ("login_hint" = Option<String>, Query, description = "Email address hint to pre-fill the login form."),
    ),
    responses(
        (status = 303, description = "Redirect to login page or back to client with authorization code"),
        (status = 400, description = "Invalid request parameters (e.g., unknown client_id, invalid redirect_uri)", body = ErrorResponse),
    )
)]
pub async fn authorize(
    State(state): State<OAuth2State>,
    Extension(resources): Extension<AppResources>,
    Query(params): Query<AuthorizeRequest>,
) -> Response {
    // Validate response_type
    if params.response_type != "code" {
        return error_redirect(
            params.redirect_uri.as_deref(),
            params.state.as_deref(),
            "unsupported_response_type",
            Some("Only 'code' response type is supported"),
        );
    }

    // Validate client exists
    let client = match oauth2_client::Entity::find_by_id(&params.client_id)
        .one(state.db.as_ref())
        .await
    {
        Ok(Some(c)) => c,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid_client".to_string(),
                    error_description: Some("Client not found".to_string()),
                }),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("Database error looking up client: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: None,
                }),
            )
                .into_response();
        }
    };

    // Validate redirect_uri
    let redirect_uri = match &params.redirect_uri {
        Some(uri) => {
            if !client.is_redirect_uri_allowed(uri) {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "invalid_request".to_string(),
                        error_description: Some("Invalid redirect_uri".to_string()),
                    }),
                )
                    .into_response();
            }
            uri.clone()
        }
        None => {
            let uris = client.redirect_uris_list();
            match uris.first() {
                Some(uri) => uri.clone(),
                None => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(ErrorResponse {
                            error: "invalid_request".to_string(),
                            error_description: Some("No redirect_uri configured".to_string()),
                        }),
                    )
                        .into_response();
                }
            }
        }
    };

    // Build login URL with all authorization context
    // login_hint is passed to pre-populate the email field (OIDC Core 1.0 Section 3.1.2.1)
    // nonce is stored and will be included in the ID token for replay attack prevention
    let mut login_url = format!(
        "{}/oauth2/login?client_id={}&redirect_uri={}&scope={}&state={}",
        resources.config.frontend_url,
        urlencoding::encode(&params.client_id),
        urlencoding::encode(&redirect_uri),
        urlencoding::encode(params.scope.as_deref().unwrap_or("openid")),
        urlencoding::encode(params.state.as_deref().unwrap_or("")),
    );

    // Add PKCE parameters if present
    if let Some(ref code_challenge) = params.code_challenge {
        login_url.push_str(&format!(
            "&code_challenge={}&code_challenge_method={}",
            urlencoding::encode(code_challenge),
            urlencoding::encode(params.code_challenge_method.as_deref().unwrap_or("plain"))
        ));
    }

    // Add nonce for OIDC session binding (OIDC Core 1.0 Section 3.1.2.1)
    if let Some(ref nonce) = params.nonce {
        login_url.push_str(&format!("&nonce={}", urlencoding::encode(nonce)));
    }

    // Add login_hint to pre-populate email field (OIDC Core 1.0 Section 3.1.2.1)
    if let Some(ref hint) = params.login_hint {
        login_url.push_str(&format!("&login_hint={}", urlencoding::encode(hint)));
    }

    Redirect::to(&login_url).into_response()
}

/// OAuth2 Token endpoint.
#[tracing::instrument(skip(state, headers, params))]
#[utoipa::path(
    post,
    path = "/token",
    tag = OAUTH2_TAG,
    operation_id = "OAuth2 Token",
    summary = "Exchange authorization code or refresh token for access token",
    description = "Exchanges an authorization code for tokens, or refreshes an existing access token.\n\n\
                   **Supported grant types:**\n\
                   - `authorization_code`: Exchange an authorization code for access and refresh tokens\n\
                   - `refresh_token`: Use a refresh token to obtain a new access token\n\n\
                   **Client authentication:**\n\
                   - Public clients: Include `client_id` in the request body\n\
                   - Confidential clients: Use HTTP Basic auth or include `client_id` and `client_secret` in the body\n\n\
                   **PKCE:** If the authorization request included a code_challenge, you must provide the code_verifier.",
    request_body(
        content = TokenRequest,
        content_type = "application/x-www-form-urlencoded",
        description = "Token request parameters"
    ),
    responses(
        (status = 200, description = "Tokens issued successfully", body = TokenResponse),
        (status = 400, description = "Invalid request (missing parameters, invalid code, PKCE mismatch)", body = ErrorResponse),
        (status = 401, description = "Invalid client credentials or unknown client", body = ErrorResponse),
    )
)]
pub async fn token(
    State(state): State<OAuth2State>,
    headers: HeaderMap,
    Form(params): Form<TokenRequest>,
) -> Response {
    // Extract client credentials from Basic auth or form body
    let (client_id, client_secret) = extract_client_credentials(&headers, &params);

    let client_id = match client_id {
        Some(id) => id,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid_request".to_string(),
                    error_description: Some("client_id is required".to_string()),
                }),
            )
                .into_response();
        }
    };

    // Validate client
    let client = match oauth2_client::Entity::find_by_id(&client_id)
        .one(state.db.as_ref())
        .await
    {
        Ok(Some(c)) => c,
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "invalid_client".to_string(),
                    error_description: None,
                }),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: None,
                }),
            )
                .into_response();
        }
    };

    // Validate client secret for confidential clients
    if !client.is_public {
        match (&client.secret, client_secret) {
            (Some(stored), Some(provided)) if stored == &provided => {}
            _ => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(ErrorResponse {
                        error: "invalid_client".to_string(),
                        error_description: None,
                    }),
                )
                    .into_response();
            }
        }
    }

    match params.grant_type.as_str() {
        "authorization_code" => handle_authorization_code_grant(state, client, params)
            .await
            .into_response(),
        "refresh_token" => handle_refresh_token_grant(state, client, params)
            .await
            .into_response(),
        _ => (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "unsupported_grant_type".to_string(),
                error_description: None,
            }),
        )
            .into_response(),
    }
}

/// Token revocation endpoint (RFC 7009).
///
/// Uses `token_type_hint` to optimize lookup - tries the hinted type first,
/// then falls back to the other type if not found.
#[tracing::instrument(skip(state, _headers, params))]
#[utoipa::path(
    post,
    path = "/revoke",
    tag = OAUTH2_TAG,
    operation_id = "OAuth2 Revoke Token",
    summary = "Revoke an access or refresh token",
    description = "Revokes an access token or refresh token, preventing further use. \
                   Implements RFC 7009 (OAuth 2.0 Token Revocation).\n\n\
                   **Behavior:**\n\
                   - Returns 200 OK even if the token was already revoked or doesn't exist (per RFC 7009)\n\
                   - When `token_type_hint` is provided, tries that token type first for efficiency\n\
                   - Unknown `token_type_hint` values are ignored per RFC 7009\n\n\
                   **Note:** Revoking a refresh token also invalidates associated access tokens.",
    request_body(
        content = RevokeRequest,
        content_type = "application/x-www-form-urlencoded",
        description = "Token revocation request"
    ),
    responses(
        (status = 200, description = "Token revoked successfully (or was already invalid)"),
        (status = 400, description = "Invalid request (missing token parameter)", body = ErrorResponse),
    )
)]
pub async fn revoke(
    State(state): State<OAuth2State>,
    _headers: HeaderMap,
    Form(params): Form<RevokeRequest>,
) -> Response {
    use sea_orm::ActiveValue::Set;

    // Per RFC 7009 Section 2.1: Use token_type_hint to optimize lookup
    // Try the hinted type first, then fall back to the other type
    let token = match params.token_type_hint.as_deref() {
        Some("refresh_token") => {
            // Try refresh_token first, then access_token
            let result = oauth2_token::Entity::find()
                .filter(oauth2_token::Column::RefreshToken.eq(&params.token))
                .one(state.db.as_ref())
                .await;

            if matches!(&result, Ok(None)) {
                // Not found as refresh token, try access token
                oauth2_token::Entity::find()
                    .filter(oauth2_token::Column::AccessToken.eq(&params.token))
                    .one(state.db.as_ref())
                    .await
            } else {
                result
            }
        }
        Some("access_token") | None => {
            // Try access_token first (default), then refresh_token
            let result = oauth2_token::Entity::find()
                .filter(oauth2_token::Column::AccessToken.eq(&params.token))
                .one(state.db.as_ref())
                .await;

            if matches!(&result, Ok(None)) {
                // Not found as access token, try refresh token
                oauth2_token::Entity::find()
                    .filter(oauth2_token::Column::RefreshToken.eq(&params.token))
                    .one(state.db.as_ref())
                    .await
            } else {
                result
            }
        }
        Some(unknown_hint) => {
            // RFC 7009 Section 2.1: Server SHOULD ignore unrecognized hints
            tracing::debug!(
                hint = unknown_hint,
                "Unknown token_type_hint, treating as access_token"
            );
            oauth2_token::Entity::find()
                .filter(
                    oauth2_token::Column::AccessToken
                        .eq(&params.token)
                        .or(oauth2_token::Column::RefreshToken.eq(&params.token)),
                )
                .one(state.db.as_ref())
                .await
        }
    };

    match token {
        Ok(Some(t)) => {
            let mut active: oauth2_token::ActiveModel = t.into();
            active.revoked_at = Set(Some(time::OffsetDateTime::now_utc()));
            if let Err(e) = active.update(state.db.as_ref()).await {
                tracing::error!("Failed to revoke token: {}", e);
            }
        }
        Ok(None) => {
            // Per RFC 7009 Section 2.2: Return success even if token doesn't exist
            // This prevents token enumeration attacks
        }
        Err(e) => {
            tracing::error!("Database error during token revocation: {}", e);
            // Still return success per RFC 7009 - don't leak internal errors
        }
    }

    StatusCode::OK.into_response()
}

/// OpenID Connect UserInfo endpoint.
#[tracing::instrument(skip(state, headers))]
#[utoipa::path(
    get,
    path = "/userinfo",
    tag = OAUTH2_TAG,
    operation_id = "OpenID Connect UserInfo",
    summary = "Get authenticated user's profile information",
    description = "Returns claims about the authenticated user. Requires a valid access token with the `openid` scope.\n\n\
                   **Returned claims depend on granted scopes:**\n\
                   - `openid`: `sub` (subject identifier)\n\
                   - `email`: `email`, `email_verified`\n\
                   - `profile`: `name`\n\n\
                   **Authentication:** Include the access token as a Bearer token in the Authorization header.",
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "User profile information", body = UserInfoResponse),
        (status = 401, description = "Missing or invalid access token", body = ErrorResponse),
        (status = 403, description = "Token does not have required `openid` scope", body = ErrorResponse),
    )
)]
pub async fn userinfo(State(state): State<OAuth2State>, headers: HeaderMap) -> Response {
    // Extract Bearer token
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    let access_token = match auth_header {
        Some(token) => token,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "invalid_token".to_string(),
                    error_description: Some("Missing or invalid Authorization header".to_string()),
                }),
            )
                .into_response();
        }
    };

    // Find the token
    let token = match oauth2_token::Entity::find()
        .filter(oauth2_token::Column::AccessToken.eq(access_token))
        .one(state.db.as_ref())
        .await
    {
        Ok(Some(t)) if t.is_valid() => t,
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "invalid_token".to_string(),
                    error_description: None,
                }),
            )
                .into_response();
        }
    };

    // Check for openid scope
    if !token.has_scope("openid") {
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "insufficient_scope".to_string(),
                error_description: Some("Token does not have 'openid' scope".to_string()),
            }),
        )
            .into_response();
    }

    // Fetch user
    let user = match oauth2_user::Entity::find_by_id(&token.user_id)
        .one(state.db.as_ref())
        .await
    {
        Ok(Some(u)) => u,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: None,
                }),
            )
                .into_response();
        }
    };

    let scopes = token.scopes_list();
    let mut response = UserInfoResponse {
        sub: user.id,
        email: None,
        email_verified: None,
        name: None,
    };

    if scopes.iter().any(|s| s == "email") {
        response.email = Some(user.email);
        response.email_verified = Some(user.email_verified);
    }

    if scopes.iter().any(|s| s == "profile") {
        response.name = user.name;
    }

    (StatusCode::OK, Json(response)).into_response()
}

/// OpenID Connect Discovery document.
#[tracing::instrument(skip(state))]
#[utoipa::path(
    get,
    path = "/.well-known/openid-configuration",
    tag = OAUTH2_TAG,
    operation_id = "OpenID Connect Discovery",
    summary = "OpenID Connect Discovery document",
    description = "Returns the OpenID Connect Discovery document containing metadata about the OAuth2/OIDC provider.\n\n\
                   This document provides:\n\
                   - Endpoint URLs (authorization, token, userinfo, revocation)\n\
                   - Supported grant types and response types\n\
                   - Supported scopes and claims\n\
                   - Supported authentication methods\n\
                   - PKCE support information\n\n\
                   Clients should use this endpoint to dynamically discover the provider's capabilities.",
    responses(
        (status = 200, description = "OpenID Connect configuration document", body = OpenIdConfiguration),
    )
)]
pub async fn openid_configuration(State(state): State<OAuth2State>) -> Json<OpenIdConfiguration> {
    Json(OpenIdConfiguration {
        issuer: state.issuer_url.clone(),
        authorization_endpoint: format!("{}/oauth2/authorize", state.issuer_url),
        token_endpoint: format!("{}/oauth2/token", state.issuer_url),
        userinfo_endpoint: format!("{}/oauth2/userinfo", state.issuer_url),
        revocation_endpoint: format!("{}/oauth2/revoke", state.issuer_url),
        response_types_supported: vec!["code".to_string()],
        grant_types_supported: vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ],
        subject_types_supported: vec!["public".to_string()],
        scopes_supported: vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
        ],
        token_endpoint_auth_methods_supported: vec![
            "client_secret_basic".to_string(),
            "client_secret_post".to_string(),
            "none".to_string(),
        ],
        code_challenge_methods_supported: vec!["S256".to_string(), "plain".to_string()],
    })
}

// =============================================================================
// Helper Functions
// =============================================================================

fn extract_client_credentials(
    headers: &HeaderMap,
    params: &TokenRequest,
) -> (Option<String>, Option<String>) {
    // Try Basic auth first
    if let Some(auth) = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic "))
        && let Ok(decoded) =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, auth)
        && let Ok(creds) = String::from_utf8(decoded)
        && let Some((id, secret)) = creds.split_once(':')
    {
        return (Some(id.to_string()), Some(secret.to_string()));
    }

    // Fall back to form body
    (params.client_id.clone(), params.client_secret.clone())
}

async fn handle_authorization_code_grant(
    state: OAuth2State,
    client: oauth2_client::Model,
    params: TokenRequest,
) -> Response {
    use crate::entity::oauth2_authorization;

    let code = match params.code {
        Some(c) => c,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid_request".to_string(),
                    error_description: Some("code is required".to_string()),
                }),
            )
                .into_response();
        }
    };

    // Find and validate authorization code
    let auth = match oauth2_authorization::Entity::find_by_id(&code)
        .one(state.db.as_ref())
        .await
    {
        Ok(Some(a)) => a,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid_grant".to_string(),
                    error_description: Some("Authorization code not found".to_string()),
                }),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: None,
                }),
            )
                .into_response();
        }
    };

    // Validate code hasn't expired
    if auth.is_expired() {
        // Delete expired code
        let _ = oauth2_authorization::Entity::delete_by_id(&code)
            .exec(state.db.as_ref())
            .await;
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_grant".to_string(),
                error_description: Some("Authorization code expired".to_string()),
            }),
        )
            .into_response();
    }

    // Validate client_id matches
    if auth.client_id != client.id {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_grant".to_string(),
                error_description: Some("Client ID mismatch".to_string()),
            }),
        )
            .into_response();
    }

    // Validate redirect_uri matches
    if let Some(ref uri) = params.redirect_uri
        && &auth.redirect_uri != uri
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_grant".to_string(),
                error_description: Some("Redirect URI mismatch".to_string()),
            }),
        )
            .into_response();
    }

    // Validate PKCE if present
    if auth.code_challenge.is_some() {
        match params.code_verifier {
            Some(ref verifier) => {
                if !auth.verify_pkce(verifier) {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(ErrorResponse {
                            error: "invalid_grant".to_string(),
                            error_description: Some("PKCE verification failed".to_string()),
                        }),
                    )
                        .into_response();
                }
            }
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "invalid_request".to_string(),
                        error_description: Some("code_verifier is required".to_string()),
                    }),
                )
                    .into_response();
            }
        }
    }

    // Delete the authorization code (one-time use)
    let _ = oauth2_authorization::Entity::delete_by_id(&code)
        .exec(state.db.as_ref())
        .await;

    // Issue tokens
    let now = time::OffsetDateTime::now_utc();
    let access_token = OAuth2State::generate_token();
    let refresh_token = OAuth2State::generate_token();
    let access_expires = now + time::Duration::seconds(state.access_token_lifetime);
    let refresh_expires = now + time::Duration::seconds(state.refresh_token_lifetime);

    let token = oauth2_token::ActiveModel {
        id: sea_orm::ActiveValue::Set(uuid::Uuid::new_v4().to_string()),
        access_token: sea_orm::ActiveValue::Set(access_token.clone()),
        refresh_token: sea_orm::ActiveValue::Set(Some(refresh_token.clone())),
        token_type: sea_orm::ActiveValue::Set("Bearer".to_string()),
        client_id: sea_orm::ActiveValue::Set(client.id),
        user_id: sea_orm::ActiveValue::Set(auth.user_id),
        scope: sea_orm::ActiveValue::Set(auth.scope.clone()),
        access_token_expires_at: sea_orm::ActiveValue::Set(access_expires),
        refresh_token_expires_at: sea_orm::ActiveValue::Set(Some(refresh_expires)),
        created_at: sea_orm::ActiveValue::Set(now),
        revoked_at: sea_orm::ActiveValue::Set(None),
    };

    if let Err(e) = token.insert(state.db.as_ref()).await {
        tracing::error!("Failed to store token: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "server_error".to_string(),
                error_description: None,
            }),
        )
            .into_response();
    }

    (
        StatusCode::OK,
        Json(TokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: state.access_token_lifetime,
            refresh_token: Some(refresh_token),
            scope: auth.scope,
        }),
    )
        .into_response()
}

async fn handle_refresh_token_grant(
    state: OAuth2State,
    client: oauth2_client::Model,
    params: TokenRequest,
) -> Response {
    let refresh_token = match params.refresh_token {
        Some(t) => t,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid_request".to_string(),
                    error_description: Some("refresh_token is required".to_string()),
                }),
            )
                .into_response();
        }
    };

    // Find the token
    let existing = match oauth2_token::Entity::find()
        .filter(oauth2_token::Column::RefreshToken.eq(&refresh_token))
        .one(state.db.as_ref())
        .await
    {
        Ok(Some(t)) => t,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid_grant".to_string(),
                    error_description: Some("Refresh token not found".to_string()),
                }),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: None,
                }),
            )
                .into_response();
        }
    };

    // Validate token belongs to client
    if existing.client_id != client.id {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_grant".to_string(),
                error_description: Some("Token does not belong to this client".to_string()),
            }),
        )
            .into_response();
    }

    // Check if revoked or expired
    if existing.is_revoked() || existing.is_refresh_token_expired() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_grant".to_string(),
                error_description: Some("Refresh token is invalid or expired".to_string()),
            }),
        )
            .into_response();
    }

    // Revoke old token
    let mut old_active: oauth2_token::ActiveModel = existing.clone().into();
    old_active.revoked_at = sea_orm::ActiveValue::Set(Some(time::OffsetDateTime::now_utc()));
    if let Err(e) = old_active.update(state.db.as_ref()).await {
        tracing::error!("Failed to revoke old token: {}", e);
    }

    // Issue new tokens
    let now = time::OffsetDateTime::now_utc();
    let new_access_token = OAuth2State::generate_token();
    let new_refresh_token = OAuth2State::generate_token();
    let access_expires = now + time::Duration::seconds(state.access_token_lifetime);
    let refresh_expires = now + time::Duration::seconds(state.refresh_token_lifetime);

    // Use requested scope or keep original
    let scope = params.scope.unwrap_or(existing.scope.clone());

    let new_token = oauth2_token::ActiveModel {
        id: sea_orm::ActiveValue::Set(uuid::Uuid::new_v4().to_string()),
        access_token: sea_orm::ActiveValue::Set(new_access_token.clone()),
        refresh_token: sea_orm::ActiveValue::Set(Some(new_refresh_token.clone())),
        token_type: sea_orm::ActiveValue::Set("Bearer".to_string()),
        client_id: sea_orm::ActiveValue::Set(client.id),
        user_id: sea_orm::ActiveValue::Set(existing.user_id),
        scope: sea_orm::ActiveValue::Set(scope.clone()),
        access_token_expires_at: sea_orm::ActiveValue::Set(access_expires),
        refresh_token_expires_at: sea_orm::ActiveValue::Set(Some(refresh_expires)),
        created_at: sea_orm::ActiveValue::Set(now),
        revoked_at: sea_orm::ActiveValue::Set(None),
    };

    if let Err(e) = new_token.insert(state.db.as_ref()).await {
        tracing::error!("Failed to store refreshed token: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "server_error".to_string(),
                error_description: None,
            }),
        )
            .into_response();
    }

    (
        StatusCode::OK,
        Json(TokenResponse {
            access_token: new_access_token,
            token_type: "Bearer".to_string(),
            expires_in: state.access_token_lifetime,
            refresh_token: Some(new_refresh_token),
            scope,
        }),
    )
        .into_response()
}

fn error_redirect(
    redirect_uri: Option<&str>,
    state: Option<&str>,
    error: &str,
    description: Option<&str>,
) -> Response {
    match redirect_uri {
        Some(uri) => {
            let mut redirect_url = match url::Url::parse(uri) {
                Ok(u) => u,
                Err(_) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(ErrorResponse {
                            error: error.to_string(),
                            error_description: description.map(String::from),
                        }),
                    )
                        .into_response();
                }
            };

            redirect_url.query_pairs_mut().append_pair("error", error);
            if let Some(desc) = description {
                redirect_url
                    .query_pairs_mut()
                    .append_pair("error_description", desc);
            }
            if let Some(s) = state {
                redirect_url.query_pairs_mut().append_pair("state", s);
            }

            Redirect::to(redirect_url.as_str()).into_response()
        }
        None => (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: error.to_string(),
                error_description: description.map(String::from),
            }),
        )
            .into_response(),
    }
}
