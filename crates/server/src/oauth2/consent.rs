//! OAuth2 Consent endpoints.
//!
//! Implements the user consent screen for OAuth2 authorization:
//! - Consent page (GET) - Shows what permissions the application is requesting
//! - Consent submission (POST) - Handles approve/deny

use crate::entity::{oauth2_authorization, oauth2_client, oauth2_user};
use crate::oauth2::{generate_verification_token, state::OAuth2State};
use askama::Template;
use axum::{
    Form,
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
};
use base64::Engine;
use sea_orm::{ActiveModelTrait, ActiveValue::Set, EntityTrait};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

/// Scope information for display.
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

/// Consent page template.
#[derive(Template)]
#[template(path = "consent.html")]
struct ConsentTemplate {
    user_email: String,
    client_name: String,
    scopes: Vec<ScopeInfo>,
    consent_token: String,
}

/// Data encoded in the consent token.
#[derive(Debug, Serialize, Deserialize)]
pub struct ConsentData {
    pub user_id: String,
    pub user_email: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: String,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub expires_at: i64,
}

impl ConsentData {
    /// Encode consent data to a base64 token.
    pub fn encode(&self) -> String {
        let json = serde_json::to_string(self).unwrap_or_default();
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json.as_bytes())
    }

    /// Decode consent data from a base64 token.
    pub fn decode(token: &str) -> Option<Self> {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(token)
            .ok()?;
        let json = String::from_utf8(bytes).ok()?;
        serde_json::from_str(&json).ok()
    }

    /// Check if the consent data has expired.
    pub fn is_expired(&self) -> bool {
        OffsetDateTime::now_utc().unix_timestamp() > self.expires_at
    }
}

/// Query parameters for the consent page.
#[derive(Debug, Deserialize)]
pub struct ConsentQuery {
    pub token: String,
}

/// Form data for consent submission.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ConsentForm {
    pub consent_token: String,
    pub action: String, // "approve" or "deny"
}

/// Creates the consent router.
pub fn router() -> OpenApiRouter<OAuth2State> {
    OpenApiRouter::new()
        .routes(routes!(consent_page))
        .routes(routes!(consent_submit))
}

/// Display the consent page.
#[tracing::instrument(skip(state))]
#[utoipa::path(
    get,
    path = "/consent",
    tag = super::OAUTH2_TAG,
    operation_id = "OAuth2 Consent Page",
    summary = "Display the OAuth2 consent page",
    description = "Renders the consent screen where users can approve or deny an application's request \
                   to access their account. Shows the application name and requested permissions.\n\n\
                   The consent token encodes all OAuth2 flow parameters and expires after 10 minutes.",
    params(
        ("token" = String, Query, description = "Base64-encoded consent token containing OAuth2 flow state."),
    ),
    responses(
        (status = 200, description = "Consent page HTML"),
        (status = 200, description = "Error page HTML if token is invalid or expired"),
    )
)]
async fn consent_page(
    State(state): State<OAuth2State>,
    Query(params): Query<ConsentQuery>,
) -> Response {
    // Decode and validate consent token
    let consent_data = match ConsentData::decode(&params.token) {
        Some(data) => data,
        None => {
            return render_error("Invalid consent request. Please try signing in again.");
        }
    };

    if consent_data.is_expired() {
        return render_error("This consent request has expired. Please try signing in again.");
    }

    // Look up client for display
    let client = match oauth2_client::Entity::find_by_id(&consent_data.client_id)
        .one(state.db.as_ref())
        .await
    {
        Ok(Some(c)) => c,
        Ok(None) => {
            return render_error("Unknown application. Please try signing in again.");
        }
        Err(e) => {
            tracing::error!("Database error looking up client: {}", e);
            return render_error("An error occurred. Please try again.");
        }
    };

    // Parse scopes for display
    let scopes: Vec<ScopeInfo> = consent_data
        .scope
        .split_whitespace()
        .map(get_scope_info)
        .collect();

    let template = ConsentTemplate {
        user_email: consent_data.user_email,
        client_name: client.name,
        scopes,
        consent_token: params.token,
    };

    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!("Failed to render consent template: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
        }
    }
}

/// Handle consent form submission.
#[tracing::instrument(skip(state, form))]
#[utoipa::path(
    post,
    path = "/consent",
    tag = super::OAUTH2_TAG,
    operation_id = "OAuth2 Consent Submit",
    summary = "Submit OAuth2 consent decision",
    description = "Handles the user's consent decision (approve or deny). On approval, creates an \
                   authorization code and redirects back to the client. On denial, redirects with \
                   an `access_denied` error.",
    request_body(
        content = ConsentForm,
        content_type = "application/x-www-form-urlencoded",
        description = "Consent decision and token"
    ),
    responses(
        (status = 303, description = "Redirect to client with authorization code or error"),
        (status = 200, description = "Error page HTML if token is invalid or expired"),
    )
)]
async fn consent_submit(
    State(state): State<OAuth2State>,
    Form(form): Form<ConsentForm>,
) -> Response {
    // Decode and validate consent token
    let consent_data = match ConsentData::decode(&form.consent_token) {
        Some(data) => data,
        None => {
            return render_error("Invalid consent request. Please try signing in again.");
        }
    };

    if consent_data.is_expired() {
        return render_error("This consent request has expired. Please try signing in again.");
    }

    // Handle deny action
    if form.action == "deny" {
        let mut redirect_url = consent_data.redirect_uri.clone();
        redirect_url.push_str(if redirect_url.contains('?') { "&" } else { "?" });
        redirect_url
            .push_str("error=access_denied&error_description=User%20denied%20the%20request");
        if !consent_data.state.is_empty() {
            redirect_url.push_str(&format!(
                "&state={}",
                urlencoding::encode(&consent_data.state)
            ));
        }
        return Redirect::to(&redirect_url).into_response();
    }

    // Handle approve action - create authorization code
    let code = generate_verification_token();
    let now = OffsetDateTime::now_utc();
    let expires_at = now + time::Duration::minutes(10);

    let auth_code = oauth2_authorization::ActiveModel {
        code: Set(code.clone()),
        client_id: Set(consent_data.client_id.clone()),
        user_id: Set(consent_data.user_id.clone()),
        redirect_uri: Set(consent_data.redirect_uri.clone()),
        scope: Set(consent_data.scope.clone()),
        state: Set(None),
        nonce: Set(consent_data.nonce.clone()),
        code_challenge: Set(consent_data.code_challenge.clone()),
        code_challenge_method: Set(consent_data.code_challenge_method.clone()),
        created_at: Set(now),
        expires_at: Set(expires_at),
    };

    if let Err(e) = auth_code.insert(state.db.as_ref()).await {
        tracing::error!("Failed to create authorization code: {}", e);
        return render_error("An error occurred. Please try again.");
    }

    // Update last login time
    if let Ok(Some(user)) = oauth2_user::Entity::find_by_id(&consent_data.user_id)
        .one(state.db.as_ref())
        .await
    {
        let mut active_user: oauth2_user::ActiveModel = user.into();
        active_user.last_login_at = Set(Some(now));
        if let Err(e) = active_user.update(state.db.as_ref()).await {
            tracing::warn!("Failed to update last_login_at: {}", e);
        }
    }

    // Redirect back to client with authorization code
    let mut redirect_url = consent_data.redirect_uri.clone();
    redirect_url.push_str(if redirect_url.contains('?') { "&" } else { "?" });
    redirect_url.push_str(&format!("code={}", urlencoding::encode(&code)));
    if !consent_data.state.is_empty() {
        redirect_url.push_str(&format!(
            "&state={}",
            urlencoding::encode(&consent_data.state)
        ));
    }

    tracing::info!(
        user_id = %consent_data.user_id,
        client_id = %consent_data.client_id,
        "User granted consent"
    );

    Redirect::to(&redirect_url).into_response()
}

/// Render a simple error page.
fn render_error(message: &str) -> Response {
    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en" class="govuk-template govuk-template--rebranded">
<head>
    <meta charset="utf-8">
    <title>Error - Federation Tester</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/govuk-frontend@5.14.0/dist/govuk/govuk-frontend.min.css">
</head>
<body class="govuk-template__body">
    <header class="govuk-header" data-module="govuk-header">
        <div class="govuk-header__container govuk-width-container">
            <div class="govuk-header__logo">
                <a href="/" class="govuk-header__link govuk-header__link--homepage">
                    <span class="govuk-header__logotype">
                        <span class="govuk-header__logotype-text">Federation Tester</span>
                    </span>
                </a>
            </div>
        </div>
    </header>
    <div class="govuk-width-container">
        <main class="govuk-main-wrapper" id="main-content">
            <div class="govuk-grid-row">
                <div class="govuk-grid-column-two-thirds">
                    <h1 class="govuk-heading-l">Something went wrong</h1>
                    <p class="govuk-body">{}</p>
                    <p class="govuk-body">
                        <a class="govuk-link" href="/">Return to homepage</a>
                    </p>
                </div>
            </div>
        </main>
    </div>
    <footer class="govuk-footer">
        <div class="govuk-width-container">
            <div class="govuk-footer__meta">
                <div class="govuk-footer__meta-item govuk-footer__meta-item--grow">
                    <span class="govuk-footer__licence-description">
                        Federation Tester is a community project for testing Matrix homeserver federation.
                    </span>
                </div>
            </div>
        </div>
    </footer>
</body>
</html>"#,
        message
    );
    Html(html).into_response()
}

/// Parameters for creating a consent redirect.
pub struct ConsentRedirectParams<'a> {
    pub user: &'a oauth2_user::Model,
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub scope: &'a str,
    pub state: &'a str,
    pub nonce: Option<&'a str>,
    pub code_challenge: Option<&'a str>,
    pub code_challenge_method: Option<&'a str>,
}

/// Helper to create a consent token and redirect URL for use after authentication.
pub fn create_consent_redirect(params: ConsentRedirectParams<'_>) -> String {
    let consent_data = ConsentData {
        user_id: params.user.id.clone(),
        user_email: params.user.email.clone(),
        client_id: params.client_id.to_string(),
        redirect_uri: params.redirect_uri.to_string(),
        scope: params.scope.to_string(),
        state: params.state.to_string(),
        nonce: params.nonce.map(String::from),
        code_challenge: params.code_challenge.map(String::from),
        code_challenge_method: params.code_challenge_method.map(String::from),
        expires_at: (OffsetDateTime::now_utc() + time::Duration::minutes(10)).unix_timestamp(),
    };

    format!("/oauth2/consent?token={}", consent_data.encode())
}
