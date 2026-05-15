//! OAuth2 Consent endpoints.
//!
//! Implements the user consent screen for OAuth2 authorization:
//! - Consent page (GET) - Shows what permissions the application is requesting
//! - Consent submission (POST) - Handles approve/deny

use crate::entity::{oauth2_authorization, oauth2_client, oauth2_token, oauth2_user};
use crate::oauth2::{generate_verification_token, state::OAuth2State};
use askama::Template;
use axum::{
    Form,
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
};
use base64::Engine;
use sea_orm::{ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

/// Scope information for display.
#[derive(Debug, Clone)]
pub struct ScopeInfo {
    pub name: String,
    pub description: String,
    pub scope_key: String,
}

/// Get human-readable scope information.
fn get_scope_info(scope: &str) -> ScopeInfo {
    let (name, description) = match scope {
        "openid" => (
            "Verify your identity",
            "Confirm who you are. Required for sign-in.",
        ),
        "email" => (
            "Read your email address",
            "See the email address associated with your account.",
        ),
        "profile" => (
            "Read your profile",
            "See your account email address and creation date. Cannot see your password.",
        ),
        "alerts:read" => (
            "Read alert state",
            "See which servers you watch and their current health status.",
        ),
        "alerts:write" => (
            "Manage your alerts",
            "Create, edit and delete alert subscriptions on your behalf.",
        ),
        _ => (scope, "Access to this resource."),
    };
    ScopeInfo {
        name: name.to_string(),
        description: description.to_string(),
        scope_key: scope.to_string(),
    }
}

/// Consent page template.
#[derive(Template)]
#[template(path = "consent.html")]
struct ConsentTemplate {
    user_email: String,
    client_name: String,
    client_initials: String,
    client_id: String,
    scopes: Vec<ScopeInfo>,
    consent_token: String,
    frontend_url: String,
    is_new_client: bool,
    has_write_scope: bool,
    github_sponsors_url: Option<String>,
    liberapay_url: Option<String>,
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

    let has_write_scope = scopes.iter().any(|s| s.scope_key.contains(":write"));

    let is_new_client = oauth2_token::Entity::find()
        .filter(oauth2_token::Column::UserId.eq(&consent_data.user_id))
        .filter(oauth2_token::Column::ClientId.eq(&consent_data.client_id))
        .one(state.db.as_ref())
        .await
        .unwrap_or(None)
        .is_none();

    let client_initials = client
        .name
        .chars()
        .take(2)
        .collect::<String>()
        .to_lowercase();
    let client_id = consent_data.client_id.clone();

    let template = ConsentTemplate {
        user_email: consent_data.user_email,
        client_name: client.name,
        client_initials,
        client_id,
        scopes,
        consent_token: params.token,
        frontend_url: format!("{}/", state.frontend_url.trim_end_matches('/')),
        is_new_client,
        has_write_scope,
        github_sponsors_url: state.github_sponsors_url.clone(),
        liberapay_url: state.liberapay_url.clone(),
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

/// Render an error page using the consent design system (navbar + footer).
fn render_error(message: &str) -> Response {
    let html = format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Error — Connectivity Tester</title>
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
  <style>
    *, *::before, *::after {{ box-sizing: border-box; }}
    html, body {{ margin: 0; padding: 0; }}
    :root {{
      --ink: #1b1714; --ink-2: #2f2a25; --ink-3: #4d4844; --ink-4: #6c6660;
      --surface: #f7f2e8; --surface-2: #efe9db; --line: #c9c2ae;
      --sans: system-ui, -apple-system, 'Segoe UI', sans-serif;
    }}
    body {{ font-family: var(--sans); background: var(--surface); color: var(--ink); line-height: 1.5; -webkit-font-smoothing: antialiased; }}
    a {{ color: var(--ink); text-underline-offset: 3px; }}
    .chrome {{ background: var(--surface); border-bottom: 1px solid var(--line); }}
    .chrome__inner {{ max-width: 1180px; margin: 0 auto; padding: 14px 32px; display: flex; align-items: center; gap: 16px; }}
    .chrome__nav {{ display: flex; gap: 28px; margin-left: auto; }}
    .chrome__nav a {{ color: var(--ink-2); text-decoration: none; font-weight: 500; font-size: 15px; padding: 6px 0; }}
    .wordmark {{ display: inline-flex; align-items: center; gap: 0.4em; font-weight: 600; letter-spacing: -0.025em; color: var(--ink); text-decoration: none; font-size: 20px; }}
    .wordmark__mark {{ display: inline-flex; align-items: center; gap: 0.18em; }}
    .wordmark__mark span {{ width: 0.18em; background: var(--ink); border-radius: 1px; transform: skewX(-12deg); }}
    .wordmark__mark span:nth-child(1) {{ height: 0.45em; opacity: 0.4; }}
    .wordmark__mark span:nth-child(2) {{ height: 0.65em; opacity: 0.7; }}
    .wordmark__mark span:nth-child(3) {{ height: 0.85em; }}
    .wordmark__name em {{ font-style: normal; font-weight: 700; }}
    .page {{ max-width: 640px; margin: 0 auto; padding: 48px 32px 64px; }}
    .error-card {{ background: #fff; border: 1px solid var(--line); border-radius: 8px; padding: 32px; margin-top: 24px; }}
    .footer {{ background: var(--ink); color: var(--surface); }}
    .footer__inner {{ max-width: 1180px; margin: 0 auto; padding: 48px 32px; }}
    .footer__cols {{ display: flex; gap: 32px; flex-wrap: wrap; align-items: flex-start; }}
    .footer__brand {{ flex: 0 0 280px; }}
    .footer__meta {{ font-size: 13px; color: var(--ink-4); margin-top: 16px; opacity: 0.85; line-height: 1.6; }}
    .footer__links {{ flex: 1; display: grid; grid-template-columns: repeat(3, 1fr); gap: 24px; }}
    .footer__group-title {{ font-weight: 600; font-size: 14px; margin-bottom: 12px; color: var(--surface); }}
    .footer__group a {{ display: block; color: var(--surface); font-size: 14px; opacity: 0.85; margin-bottom: 8px; text-decoration: none; }}
    .footer__group a:hover {{ opacity: 1; text-decoration: underline; }}
    @media (max-width: 600px) {{
      .chrome__inner {{ padding: 14px 16px; }}
      .page {{ padding: 32px 16px 48px; }}
      .footer__links {{ grid-template-columns: 1fr 1fr; }}
      .footer__inner {{ padding: 36px 16px; }}
    }}
  </style>
</head>
<body>
  <header class="chrome">
    <div class="chrome__inner">
      <a href="/" class="wordmark" aria-label="Connectivity Tester — home">
        <span class="wordmark__mark" aria-hidden="true"><span></span><span></span><span></span></span>
        <span class="wordmark__name">Connectivity <em>Tester</em></span>
      </a>
      <nav class="chrome__nav" aria-label="Primary navigation">
        <a href="/">Home</a>
        <a href="/alerts">Alerts</a>
        <a href="/docs">Docs</a>
      </nav>
    </div>
  </header>

  <main id="main" class="page">
    <h1 style="font: 800 36px/1.1 var(--sans); letter-spacing: -0.03em; margin-bottom: 12px;">Something went wrong</h1>
    <p style="font-size: 16px; color: var(--ink-2); margin-bottom: 24px; line-height: 1.7;">{}</p>
    <div class="error-card">
      <p style="margin: 0 0 16px; font-size: 15px; color: var(--ink-2);">
        If you were trying to sign in, please return to the application and try again.
        The authorisation request may have expired or been tampered with.
      </p>
      <a href="/" style="font-weight: 600; font-size: 15px;">Return to homepage →</a>
    </div>
  </main>

  <footer class="footer">
    <div class="footer__inner">
      <div class="footer__cols">
        <div class="footer__brand">
          <a href="/" class="wordmark" aria-label="Connectivity Tester — home" style="color: var(--surface);">
            <span class="wordmark__mark" aria-hidden="true">
              <span style="background: var(--surface);"></span>
              <span style="background: var(--surface);"></span>
              <span style="background: var(--surface);"></span>
            </span>
            <span class="wordmark__name">Connectivity <em>Tester</em></span>
          </a>
          <p class="footer__meta">A free, open-source diagnostic tool for Matrix homeserver operators. Self-hostable under AGPL-3.0.</p>
        </div>
        <div class="footer__links">
          <div class="footer__group">
            <div class="footer__group-title">Project</div>
            <a href="https://github.com/MTRNord/matrix-connection-tester-ui">UI source code</a>
            <a href="https://github.com/MTRNord/rust-federation-tester/">API source code</a>
            <a href="/docs">Documentation</a>
          </div>
          <div class="footer__group">
            <div class="footer__group-title">Matrix</div>
            <a href="https://matrix.org">Matrix.org</a>
            <a href="https://spec.matrix.org">Specification</a>
          </div>
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
