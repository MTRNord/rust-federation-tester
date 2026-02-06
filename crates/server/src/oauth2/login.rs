//! OAuth2 Login endpoints.
//!
//! Implements user authentication for the OAuth2 authorization flow:
//! - Login page (GET)
//! - Login submission (POST)
//! - Magic link initiation (POST)

use crate::entity::{oauth2_client, oauth2_user};
use crate::oauth2::{state::OAuth2State, verify_password};
use askama::Template;
use axum::{
    Form,
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde::Deserialize;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

/// Scope information for display on the login page.
#[derive(Debug, Clone)]
pub struct ScopeInfo {
    pub name: String,
    pub description: String,
}

/// Get human-readable scope information.
fn get_scope_info(scope: &str) -> ScopeInfo {
    match scope {
        "openid" => ScopeInfo {
            name: "OpenID".to_string(),
            description: "Verify your identity".to_string(),
        },
        "email" => ScopeInfo {
            name: "Email".to_string(),
            description: "Access your email address".to_string(),
        },
        "profile" => ScopeInfo {
            name: "Profile".to_string(),
            description: "Access your profile information".to_string(),
        },
        "alerts:read" => ScopeInfo {
            name: "Read Alerts".to_string(),
            description: "View your alert subscriptions".to_string(),
        },
        "alerts:write" => ScopeInfo {
            name: "Write Alerts".to_string(),
            description: "Create and delete alert subscriptions".to_string(),
        },
        _ => ScopeInfo {
            name: scope.to_string(),
            description: format!("Access to {}", scope),
        },
    }
}

/// Login page template.
#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate {
    // OAuth2 flow parameters
    response_type: String,
    client_id: String,
    redirect_uri: String,
    scope: String,
    state: String,
    nonce: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    // Display information
    email: String,
    error: Option<String>,
    message: Option<String>,
    client_name: Option<String>,
    scopes: Vec<ScopeInfo>,
}

/// Query parameters for the login page.
#[derive(Debug, Deserialize)]
pub struct LoginQuery {
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub login_hint: Option<String>,
    pub error: Option<String>,
    pub message: Option<String>,
}

/// Form data for login submission.
#[derive(Debug, Deserialize, ToSchema)]
pub struct LoginForm {
    // OAuth2 flow parameters
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: String,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    // Login credentials
    pub email: String,
    pub password: Option<String>,
}

/// Creates the login router.
pub fn router() -> OpenApiRouter<OAuth2State> {
    OpenApiRouter::new()
        .routes(routes!(login_page))
        .routes(routes!(login_submit))
}

/// Display the login page.
#[tracing::instrument(skip(state))]
#[utoipa::path(
    get,
    path = "/login",
    tag = super::OAUTH2_TAG,
    operation_id = "OAuth2 Login Page",
    summary = "Display the OAuth2 login page",
    description = "Renders the login form for the OAuth2 authorization flow. The user authenticates with their email and password.\n\n\
                   This endpoint is typically redirected to from the `/authorize` endpoint.",
    params(
        ("client_id" = String, Query, description = "The client identifier."),
        ("redirect_uri" = String, Query, description = "URI to redirect after authorization."),
        ("scope" = Option<String>, Query, description = "Space-separated list of requested scopes."),
        ("state" = Option<String>, Query, description = "Opaque value for CSRF protection."),
        ("nonce" = Option<String>, Query, description = "String value for replay protection."),
        ("code_challenge" = Option<String>, Query, description = "PKCE code challenge."),
        ("code_challenge_method" = Option<String>, Query, description = "PKCE challenge method."),
        ("login_hint" = Option<String>, Query, description = "Email address to pre-fill."),
        ("error" = Option<String>, Query, description = "Error message to display."),
        ("message" = Option<String>, Query, description = "Info message to display."),
    ),
    responses(
        (status = 200, description = "Login page HTML"),
        (status = 500, description = "Internal server error"),
    )
)]
async fn login_page(
    State(state): State<OAuth2State>,
    Query(params): Query<LoginQuery>,
) -> Response {
    // Look up client for display name
    let client_name = match oauth2_client::Entity::find_by_id(&params.client_id)
        .one(state.db.as_ref())
        .await
    {
        Ok(Some(c)) => Some(c.name),
        _ => None,
    };

    // Parse scopes for display
    let scope_str = params.scope.as_deref().unwrap_or("openid");
    let scopes: Vec<ScopeInfo> = scope_str.split_whitespace().map(get_scope_info).collect();

    let template = LoginTemplate {
        response_type: "code".to_string(),
        client_id: params.client_id,
        redirect_uri: params.redirect_uri,
        scope: scope_str.to_string(),
        state: params.state.unwrap_or_default(),
        nonce: params.nonce,
        code_challenge: params.code_challenge,
        code_challenge_method: params.code_challenge_method,
        email: params.login_hint.unwrap_or_default(),
        error: params.error,
        message: params.message,
        client_name,
        scopes,
    };

    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!("Failed to render login template: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
        }
    }
}

/// Handle login form submission.
#[tracing::instrument(skip(state, form), fields(email = %form.email))]
#[utoipa::path(
    post,
    path = "/login",
    tag = super::OAUTH2_TAG,
    operation_id = "OAuth2 Login Submit",
    summary = "Submit OAuth2 login credentials",
    description = "Authenticates the user with email and password. On success, creates an authorization code \
                   and redirects back to the client's redirect_uri.\n\n\
                   If the user has no password set (magic link only account), an appropriate error is shown.",
    request_body(
        content = LoginForm,
        content_type = "application/x-www-form-urlencoded",
        description = "Login credentials and OAuth2 flow parameters"
    ),
    responses(
        (status = 303, description = "Redirect to client with authorization code, or back to login with error"),
    )
)]
async fn login_submit(State(state): State<OAuth2State>, Form(form): Form<LoginForm>) -> Response {
    let email = form.email.trim().to_lowercase();

    // Validate email format
    if email.is_empty() || !email.contains('@') {
        return redirect_to_login_with_error(&form, "Please enter a valid email address");
    }

    // Look up user
    let user = match oauth2_user::Entity::find()
        .filter(oauth2_user::Column::Email.eq(&email))
        .one(state.db.as_ref())
        .await
    {
        Ok(Some(u)) => u,
        Ok(None) => {
            // User doesn't exist - show generic error (don't reveal whether email exists)
            return redirect_to_login_with_error(&form, "Invalid email or password");
        }
        Err(e) => {
            tracing::error!("Database error looking up user: {}", e);
            return redirect_to_login_with_error(&form, "An error occurred. Please try again.");
        }
    };

    // Check password
    let password = form.password.as_deref().unwrap_or("");

    if password.is_empty() {
        // No password provided - could be magic link flow or user forgot password
        return redirect_to_login_with_error(&form, "Please enter your password");
    }

    // Verify password if user has one set
    match &user.password_hash {
        Some(hash) => {
            if !verify_password(password, hash) {
                return redirect_to_login_with_error(&form, "Invalid email or password");
            }
        }
        None => {
            // User doesn't have a password set (magic link only account)
            return redirect_to_login_with_error(
                &form,
                "This account uses magic link authentication. Click 'Sign in with Magic Link' below.",
            );
        }
    }

    // Check if email is verified (required for password login)
    if !user.email_verified {
        return redirect_to_login_with_error(
            &form,
            "Please verify your email address before signing in. Check your inbox for the verification link.",
        );
    }

    // Authentication successful - redirect to consent screen
    tracing::info!(email = %email, client_id = %form.client_id, "User authenticated successfully");

    let consent_url = super::consent::create_consent_redirect(
        &user,
        &form.client_id,
        &form.redirect_uri,
        &form.scope,
        &form.state,
        form.nonce.as_deref(),
        form.code_challenge.as_deref(),
        form.code_challenge_method.as_deref(),
    );

    Redirect::to(&consent_url).into_response()
}

/// Redirect back to login page with an error message.
fn redirect_to_login_with_error(form: &LoginForm, error: &str) -> Response {
    let mut url = format!(
        "/oauth2/login?client_id={}&redirect_uri={}&scope={}&state={}&error={}",
        urlencoding::encode(&form.client_id),
        urlencoding::encode(&form.redirect_uri),
        urlencoding::encode(&form.scope),
        urlencoding::encode(&form.state),
        urlencoding::encode(error),
    );

    // Preserve email for convenience
    if !form.email.is_empty() {
        url.push_str(&format!("&login_hint={}", urlencoding::encode(&form.email)));
    }

    // Preserve PKCE parameters
    if let Some(ref challenge) = form.code_challenge {
        url.push_str(&format!(
            "&code_challenge={}",
            urlencoding::encode(challenge)
        ));
    }
    if let Some(ref method) = form.code_challenge_method {
        url.push_str(&format!(
            "&code_challenge_method={}",
            urlencoding::encode(method)
        ));
    }
    if let Some(ref nonce) = form.nonce {
        url.push_str(&format!("&nonce={}", urlencoding::encode(nonce)));
    }

    Redirect::to(&url).into_response()
}
