//! OAuth2 Magic Link login endpoints.
//!
//! Implements passwordless authentication for the OAuth2 authorization flow:
//! - Magic link request (POST) — signs a JWT with all OAuth2 params and sends it by email
//! - Magic link verify (GET)  — decodes the JWT, creates/updates the user, redirects to consent

use crate::AppResources;
use crate::email_outbox;
use crate::email_templates::MagicLinkEmailTemplate;
use crate::entity::oauth2_user;
use crate::oauth2::{OAUTH2_TAG, state::OAuth2State};
use askama::Template;
use axum::{
    Extension, Form,
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use sea_orm::{ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

// ---------------------------------------------------------------------------
// JWT claims
// ---------------------------------------------------------------------------

/// Claims embedded in the magic link JWT.
/// All OAuth2 flow parameters are included so the verify handler can resume
/// the flow without any server-side session storage.
#[derive(Debug, Serialize, Deserialize)]
struct MagicLinkClaims {
    /// Expiry (Unix timestamp, seconds)
    pub exp: usize,
    pub email: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: String,
    pub response_type: String,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

/// "Check your email" page template.
#[derive(Template)]
#[template(path = "magic_link_sent.html")]
struct MagicLinkSentTemplate {
    email: String,
    frontend_url: String,
}

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

/// Form data for requesting a magic link.
#[derive(Debug, Deserialize, ToSchema)]
pub struct MagicLinkForm {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: String,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub email: String,
}

/// Query params for the verify endpoint.
#[derive(Debug, Deserialize)]
pub struct MagicLinkVerifyQuery {
    pub token: String,
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> OpenApiRouter<OAuth2State> {
    OpenApiRouter::new()
        .routes(routes!(magic_link_request))
        .routes(routes!(magic_link_verify))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Request a magic link sign-in email.
#[tracing::instrument(skip(state, resources, form), fields(email = %form.email))]
#[utoipa::path(
    post,
    path = "/magic-link",
    tag = OAUTH2_TAG,
    operation_id = "OAuth2 Magic Link Request",
    summary = "Request a magic link sign-in email",
    description = "Sends a one-time sign-in link to the provided email address. \
                   Clicking the link authenticates the user without a password and \
                   continues the OAuth2 authorization flow.",
    request_body(
        content = MagicLinkForm,
        content_type = "application/x-www-form-urlencoded",
        description = "Email and OAuth2 flow parameters"
    ),
    responses(
        (status = 200, description = "\"Check your email\" confirmation page"),
    )
)]
async fn magic_link_request(
    State(state): State<OAuth2State>,
    Extension(resources): Extension<AppResources>,
    Form(form): Form<MagicLinkForm>,
) -> Response {
    let email = form.email.trim().to_lowercase();

    // Basic email format validation
    if email.is_empty() || !email.contains('@') {
        return render_error("Please enter a valid email address.");
    }

    // Sign a JWT containing the email and all OAuth2 flow parameters.
    // Expires in 1 hour — matches the email link validity window.
    let exp = (OffsetDateTime::now_utc() + time::Duration::hours(1)).unix_timestamp() as usize;
    let claims = MagicLinkClaims {
        exp,
        email: email.clone(),
        client_id: form.client_id.clone(),
        redirect_uri: form.redirect_uri.clone(),
        scope: form.scope.clone(),
        state: form.state.clone(),
        response_type: form.response_type.clone(),
        nonce: form.nonce.clone(),
        code_challenge: form.code_challenge.clone(),
        code_challenge_method: form.code_challenge_method.clone(),
    };

    let secret = resources.config.magic_token_secret.as_bytes();
    let token = match encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret),
    ) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("Failed to sign magic link JWT: {}", e);
            return render_error("An error occurred. Please try again.");
        }
    };

    // Build the verify URL
    let verify_url = format!(
        "{}/oauth2/magic-link/verify?token={}",
        resources.config.oauth2.issuer_url.trim_end_matches('/'),
        urlencoding::encode(&token)
    );

    // Enqueue via outbox — fast DB insert. Actual SMTP happens in the background
    // worker. The outbox entry carries the JWT expiry so stale links are not
    // delivered after the token expires.
    let jwt_expires_at = OffsetDateTime::from_unix_timestamp(exp as i64)
        .unwrap_or_else(|_| OffsetDateTime::now_utc());
    if let Err(e) = send_magic_link_email(&resources, &email, &verify_url, jwt_expires_at).await {
        tracing::error!(email = %email, "Failed to enqueue magic link email: {}", e);
        // Don't reveal failure to the user
    } else {
        tracing::info!(email = %email, client_id = %form.client_id, "Magic link email queued");
    }

    // Ensure the user record exists (create if new, leave as-is if existing).
    // Email verification happens at /verify time, not here.
    if let Err(e) = state.get_or_create_user(&email).await {
        tracing::warn!(email = %email, "Could not ensure user exists: {}", e);
    }

    // Render "check your email" confirmation
    let template = MagicLinkSentTemplate {
        email,
        frontend_url: state.frontend_url.clone(),
    };
    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!("Failed to render magic_link_sent template: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
        }
    }
}

/// Verify a magic link token and continue the OAuth2 flow.
#[tracing::instrument(skip(state, resources, params))]
#[utoipa::path(
    get,
    path = "/magic-link/verify",
    tag = OAUTH2_TAG,
    operation_id = "OAuth2 Magic Link Verify",
    summary = "Verify a magic link token",
    description = "Authenticates the user via the one-time token from their magic link email. \
                   On success, marks the email as verified and redirects to the OAuth2 consent page.",
    params(
        ("token" = String, Query, description = "The signed magic link JWT."),
    ),
    responses(
        (status = 303, description = "Redirect to consent page on success"),
        (status = 200, description = "Error page HTML on failure"),
    )
)]
async fn magic_link_verify(
    State(state): State<OAuth2State>,
    Extension(resources): Extension<AppResources>,
    Query(params): Query<MagicLinkVerifyQuery>,
) -> Response {
    // Decode and validate the JWT
    let secret = resources.config.magic_token_secret.as_bytes();
    let mut validation = Validation::default();
    validation.validate_exp = true;

    let claims = match decode::<MagicLinkClaims>(
        &params.token,
        &DecodingKey::from_secret(secret),
        &validation,
    ) {
        Ok(data) => data.claims,
        Err(e) => {
            tracing::warn!("Magic link token invalid: {}", e);
            return render_error(
                "This magic link is invalid or has expired. Please request a new one.",
            );
        }
    };

    // Find the user or create one
    let user = match oauth2_user::Entity::find()
        .filter(oauth2_user::Column::Email.eq(&claims.email))
        .one(state.db.as_ref())
        .await
    {
        Ok(Some(u)) => u,
        Ok(None) => {
            // Create a new, auto-verified user
            let now = OffsetDateTime::now_utc();
            let new_user = oauth2_user::ActiveModel {
                id: Set(uuid::Uuid::new_v4().to_string()),
                email: Set(claims.email.clone()),
                email_verified: Set(true),
                name: Set(None),
                receives_alerts: Set(true),
                created_at: Set(now),
                last_login_at: Set(Some(now)),
                password_hash: Set(None),
                email_verification_token: Set(None),
                email_verification_expires_at: Set(None),
            };
            match new_user.insert(state.db.as_ref()).await {
                Ok(u) => u,
                Err(e) => {
                    tracing::error!("Failed to create user via magic link: {}", e);
                    return render_error("An error occurred. Please try again.");
                }
            }
        }
        Err(e) => {
            tracing::error!("Database error during magic link verify: {}", e);
            return render_error("An error occurred. Please try again.");
        }
    };

    // Mark email verified and update last_login_at
    let now = OffsetDateTime::now_utc();
    let mut active: oauth2_user::ActiveModel = user.clone().into();
    active.email_verified = Set(true);
    active.last_login_at = Set(Some(now));
    if let Err(e) = active.update(state.db.as_ref()).await {
        tracing::warn!("Failed to update user after magic link verify: {}", e);
    }

    tracing::info!(
        email = %claims.email,
        client_id = %claims.client_id,
        "User authenticated via magic link"
    );

    // Continue to the consent screen
    let consent_url =
        super::consent::create_consent_redirect(super::consent::ConsentRedirectParams {
            user: &user,
            client_id: &claims.client_id,
            redirect_uri: &claims.redirect_uri,
            scope: &claims.scope,
            state: &claims.state,
            nonce: claims.nonce.as_deref(),
            code_challenge: claims.code_challenge.as_deref(),
            code_challenge_method: claims.code_challenge_method.as_deref(),
        });

    Redirect::to(&consent_url).into_response()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn send_magic_link_email(
    resources: &AppResources,
    email: &str,
    verify_url: &str,
    jwt_expires_at: OffsetDateTime,
) -> Result<(), sea_orm::DbErr> {
    let template = MagicLinkEmailTemplate {
        verify_url: verify_url.to_string(),
        environment_name: resources.config.environment_name.clone(),
    };

    let html_body = template.render_html().unwrap_or_default();
    let text_body = template.render_text();
    let subject = crate::email_templates::env_subject(
        "Sign in to Federation Tester",
        resources.config.environment_name.as_deref(),
    );

    email_outbox::enqueue(
        resources.db.as_ref(),
        email,
        &subject,
        Some(html_body),
        text_body,
        Some(jwt_expires_at),
    )
    .await
}

/// Render a simple inline error page.
fn render_error(message: &str) -> Response {
    let html = format!(
        r#"<!doctype html>
<html lang="en" class="govuk-template govuk-template--rebranded">
<head>
    <meta charset="utf-8">
    <title>Error - Federation Tester</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="/assets/govuk/govuk-frontend.min.css">
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
                    <p class="govuk-body">{message}</p>
                    <p class="govuk-body"><a class="govuk-link" href="/">Return to homepage</a></p>
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
        message = message
    );
    Html(html).into_response()
}
