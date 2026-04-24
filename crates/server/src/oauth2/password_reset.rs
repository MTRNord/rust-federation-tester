//! Password reset flow — unauthenticated endpoints.
//!
//! - `GET  /oauth2/password-reset`         — render the email-entry form
//! - `POST /oauth2/password-reset`         — issue a reset token, send email
//! - `GET  /oauth2/password-reset/confirm` — render the new-password form
//! - `POST /oauth2/password-reset/confirm` — validate token, update password

use crate::AppResources;
use crate::email_templates::PasswordResetEmailTemplate;
use crate::entity::oauth2_user;
use crate::oauth2::{
    OAUTH2_TAG, generate_verification_token, hash_password, validate_password_complexity,
};
use askama::Template;
use axum::{
    Extension, Form,
    extract::Query,
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};
use sea_orm::{ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use time::OffsetDateTime;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "password_reset_request.html")]
struct RequestPageTemplate {
    error: Option<String>,
    sent: bool,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum PasswordResetState {
    Form,
    Success,
    InvalidToken,
}

#[derive(Template)]
#[template(path = "password_reset_confirm.html")]
struct ConfirmPageTemplate {
    state: PasswordResetState,
    token: String,
    error: Option<String>,
}

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, ToSchema)]
pub struct ResetRequestForm {
    pub email: String,
}

#[derive(Debug, Deserialize)]
pub struct ConfirmQuery {
    pub token: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ConfirmForm {
    pub token: String,
    pub new_password: String,
    pub confirm_password: String,
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> OpenApiRouter {
    OpenApiRouter::new()
        .routes(routes!(get_reset_request, post_reset_request))
        .routes(routes!(get_reset_confirm, post_reset_confirm))
}

// ---------------------------------------------------------------------------
// GET /oauth2/password-reset
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/password-reset",
    tag = OAUTH2_TAG,
    operation_id = "Password Reset Request Page",
    summary = "Render the password reset request form",
    responses((status = 200, description = "HTML form"))
)]
async fn get_reset_request() -> Response {
    render_request_page(None, false)
}

// ---------------------------------------------------------------------------
// POST /oauth2/password-reset
// ---------------------------------------------------------------------------

#[utoipa::path(
    post,
    path = "/password-reset",
    tag = OAUTH2_TAG,
    operation_id = "Password Reset Request Submit",
    summary = "Send a password reset email",
    responses(
        (status = 200, description = "\"Check your email\" confirmation page"),
    )
)]
async fn post_reset_request(
    Extension(resources): Extension<AppResources>,
    Form(form): Form<ResetRequestForm>,
) -> Response {
    let email = form.email.trim().to_lowercase();
    if email.is_empty() || !email.contains('@') {
        return render_request_page(Some("Please enter a valid email address."), false);
    }

    // Add a small random delay (50–200 ms) so timing attacks cannot distinguish
    // "user found" from "user not found" by measuring response latency.
    let jitter_ms = {
        let mut buf = [0u8; 1];
        getrandom::fill(&mut buf).unwrap_or(());
        50u64 + (buf[0] as u64 * 150 / 255)
    };
    tokio::time::sleep(Duration::from_millis(jitter_ms)).await;

    // Always show "check your email" regardless of whether the address exists (anti-enumeration).
    issue_reset_token(&resources, &email).await;
    render_request_page(None, true)
}

// tracing! macros expand to `if` blocks that inflate the cognitive complexity
// score beyond what the three logical branches here actually warrant.
#[allow(clippy::cognitive_complexity)]
async fn issue_reset_token(resources: &AppResources, email: &str) {
    let user = match oauth2_user::Entity::find()
        .filter(oauth2_user::Column::Email.eq(email))
        .one(resources.db.as_ref())
        .await
    {
        Ok(Some(u)) => u,
        Ok(None) => return,
        Err(e) => {
            tracing::error!(email = %email, "DB error during password reset request: {}", e);
            return;
        }
    };

    let token = generate_verification_token();
    let expires = OffsetDateTime::now_utc() + time::Duration::hours(1);

    let mut active: oauth2_user::ActiveModel = user.into();
    active.password_reset_token = Set(Some(token.clone()));
    active.password_reset_expires_at = Set(Some(expires));

    if let Err(e) = active.update(resources.db.as_ref()).await {
        tracing::error!(email = %email, "Failed to store password reset token: {}", e);
        return;
    }

    let issuer = resources.config.oauth2.issuer_url.trim_end_matches('/');
    let reset_url = format!(
        "{}/oauth2/password-reset/confirm?token={}",
        issuer,
        urlencoding::encode(&token)
    );

    let template = PasswordResetEmailTemplate {
        reset_url,
        environment_name: resources.config.environment_name.clone(),
    };
    let html_body = template.render_html().unwrap_or_default();
    let text_body = template.render_text();
    let subject = crate::email_templates::env_subject(
        "Reset your Federation Tester password",
        resources.config.environment_name.as_deref(),
    );

    if let Err(e) = crate::email_outbox::enqueue(
        resources.db.as_ref(),
        email,
        &subject,
        Some(html_body),
        text_body,
        Some(expires),
    )
    .await
    {
        tracing::error!(email = %email, "Failed to enqueue password reset email: {}", e);
    }
}

// ---------------------------------------------------------------------------
// GET /oauth2/password-reset/confirm?token=…
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/password-reset/confirm",
    tag = OAUTH2_TAG,
    operation_id = "Password Reset Confirm Page",
    summary = "Render the new-password form",
    params(("token" = String, Query, description = "Reset token from email")),
    responses((status = 200, description = "HTML form or error page"))
)]
async fn get_reset_confirm(
    Extension(resources): Extension<AppResources>,
    Query(query): Query<ConfirmQuery>,
) -> Response {
    // Validate the token exists and is not expired — reject early so users
    // don't fill in a form that will fail on submit.
    let user = oauth2_user::Entity::find()
        .filter(oauth2_user::Column::PasswordResetToken.eq(&query.token))
        .one(resources.db.as_ref())
        .await;

    match user {
        Ok(Some(u)) if u.is_password_reset_valid() => {
            render_confirm_page(PasswordResetState::Form, &query.token, None)
        }
        _ => render_confirm_page(PasswordResetState::InvalidToken, "", None),
    }
}

// ---------------------------------------------------------------------------
// POST /oauth2/password-reset/confirm
// ---------------------------------------------------------------------------

#[utoipa::path(
    post,
    path = "/password-reset/confirm",
    tag = OAUTH2_TAG,
    operation_id = "Password Reset Confirm Submit",
    summary = "Set the new password using a reset token",
    responses(
        (status = 200, description = "Success or error HTML page"),
    )
)]
async fn post_reset_confirm(
    Extension(resources): Extension<AppResources>,
    Form(form): Form<ConfirmForm>,
) -> Response {
    if form.new_password != form.confirm_password {
        return render_confirm_page(
            PasswordResetState::Form,
            &form.token,
            Some("Passwords do not match"),
        );
    }
    if let Err(msg) = validate_password_complexity(&form.new_password) {
        return render_confirm_page(PasswordResetState::Form, &form.token, Some(msg));
    }

    match apply_password_reset(&resources, &form.token, &form.new_password).await {
        Ok(()) => render_confirm_page(PasswordResetState::Success, "", None),
        Err(ResetError::InvalidToken) => {
            render_confirm_page(PasswordResetState::InvalidToken, "", None)
        }
        Err(ResetError::InternalError(msg)) => {
            render_confirm_page(PasswordResetState::Form, &form.token, Some(msg))
        }
    }
}

enum ResetError {
    InvalidToken,
    InternalError(&'static str),
}

async fn apply_password_reset(
    resources: &AppResources,
    token: &str,
    new_password: &str,
) -> Result<(), ResetError> {
    let user = oauth2_user::Entity::find()
        .filter(oauth2_user::Column::PasswordResetToken.eq(token))
        .one(resources.db.as_ref())
        .await
        .map_err(|_| ResetError::InternalError("An error occurred. Please try again."))?;

    let user = match user {
        Some(u) if u.is_password_reset_valid() => u,
        _ => return Err(ResetError::InvalidToken),
    };

    let hash = hash_password(new_password).map_err(|e| {
        tracing::error!("Failed to hash password during reset: {}", e);
        ResetError::InternalError("An error occurred. Please try again.")
    })?;

    let user_id = user.id.clone();
    let mut active: oauth2_user::ActiveModel = user.into();
    active.password_hash = Set(Some(hash));
    active.password_reset_token = Set(None);
    active.password_reset_expires_at = Set(None);

    active.update(resources.db.as_ref()).await.map_err(|e| {
        tracing::error!(user_id = %user_id, "Failed to update password after reset: {}", e);
        ResetError::InternalError("An error occurred. Please try again.")
    })?;

    tracing::info!(user_id = %user_id, "Password reset completed");
    Ok(())
}

// ---------------------------------------------------------------------------
// Render helpers
// ---------------------------------------------------------------------------

fn render_request_page(error: Option<&str>, sent: bool) -> Response {
    let template = RequestPageTemplate {
        error: error.map(str::to_string),
        sent,
    };
    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response(),
    }
}

fn render_confirm_page(state: PasswordResetState, token: &str, error: Option<&str>) -> Response {
    let template = ConfirmPageTemplate {
        state,
        token: token.to_string(),
        error: error.map(str::to_string),
    };
    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response(),
    }
}
