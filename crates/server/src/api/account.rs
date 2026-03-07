//! Account management API endpoints (OAuth2-authenticated).
//!
//! - `GET    /`               Account info + additional emails
//! - `PATCH  /`               Toggle primary email receives_alerts
//! - `DELETE /`               Delete account (GDPR)
//! - `GET    /export`         GDPR data export (JSON download)
//! - `POST   /emails`         Add an additional email
//! - `GET    /emails/verify`  Verify an additional email via token link
//! - `PATCH  /emails/{id}`    Toggle receives_alerts on an additional email
//! - `DELETE /emails/{id}`    Remove an additional email

use crate::AppResources;
use crate::api::auth::{AuthError, OAuth2Auth};
use crate::entity::{
    alert, alert_status_history, oauth2_authorization, oauth2_identity, oauth2_token, oauth2_user,
    user_email,
};
use crate::oauth2::generate_verification_token;
use askama::Template;
use axum::{
    Extension, Json,
    extract::{Path, Query},
    http::{HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
};
use lettre::AsyncTransport;
use lettre::message::{MultiPart, SinglePart};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

pub const ACCOUNT_TAG: &str = "Account API";

// ---------------------------------------------------------------------------
// Response / request types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, ToSchema)]
pub struct EmailDto {
    pub id: String,
    pub email: String,
    pub verified: bool,
    pub receives_alerts: bool,
    pub created_at: OffsetDateTime,
}

impl From<user_email::Model> for EmailDto {
    fn from(m: user_email::Model) -> Self {
        Self {
            id: m.id,
            email: m.email,
            verified: m.verified,
            receives_alerts: m.receives_alerts,
            created_at: m.created_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AccountInfoResponse {
    pub user_id: String,
    pub email: String,
    pub name: Option<String>,
    pub email_verified: bool,
    /// Whether the primary login email receives alert notifications.
    pub receives_alerts: bool,
    pub created_at: OffsetDateTime,
    pub last_login_at: Option<OffsetDateTime>,
    pub additional_emails: Vec<EmailDto>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdatePrimaryRequest {
    pub receives_alerts: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AddEmailRequest {
    pub email: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateEmailRequest {
    pub receives_alerts: bool,
}

#[derive(Debug, Deserialize)]
pub struct VerifyTokenQuery {
    pub token: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct GdprExport {
    pub exported_at: OffsetDateTime,
    pub account: GdprAccountInfo,
    pub additional_emails: Vec<EmailDto>,
    pub alerts: Vec<GdprAlertInfo>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct GdprAccountInfo {
    pub user_id: String,
    pub email: String,
    pub name: Option<String>,
    pub email_verified: bool,
    pub receives_alerts: bool,
    pub created_at: OffsetDateTime,
    pub last_login_at: Option<OffsetDateTime>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct GdprAlertInfo {
    pub id: i32,
    pub server_name: String,
    pub email: String,
    pub verified: bool,
    pub created_at: OffsetDateTime,
    pub last_check_at: Option<OffsetDateTime>,
    pub is_currently_failing: bool,
}

impl From<alert::Model> for GdprAlertInfo {
    fn from(a: alert::Model) -> Self {
        Self {
            id: a.id,
            server_name: a.server_name,
            email: a.email,
            verified: a.verified,
            created_at: a.created_at,
            last_check_at: a.last_check_at,
            is_currently_failing: a.is_currently_failing,
        }
    }
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> OpenApiRouter {
    OpenApiRouter::new()
        // GET "" serves the HTML page (unauthenticated shell); JS calls /me etc.
        .routes(routes!(account_page))
        // GET /me returns JSON; PATCH/DELETE "" update/delete the account
        .routes(routes!(get_account))
        .routes(routes!(update_primary_settings, delete_account))
        .routes(routes!(export_data))
        .routes(routes!(add_email))
        // verify must be registered before /{id} so the static segment wins
        .routes(routes!(verify_email))
        .routes(routes!(update_email, remove_email))
}

// ---------------------------------------------------------------------------
// GET /oauth2/account  — HTML shell (no auth required; JS handles auth)
// ---------------------------------------------------------------------------

/// Askama template for the account management page.
#[derive(Template)]
#[template(path = "account.html")]
struct AccountPageTemplate {}

#[utoipa::path(
    get,
    path = "",
    tag = ACCOUNT_TAG,
    operation_id = "Account Page",
    summary = "Account management HTML page",
    responses(
        (status = 200, description = "Account management page HTML"),
    )
)]
async fn account_page() -> Response {
    let template = AccountPageTemplate {};
    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!("Failed to render account template: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// GET /oauth2/account/me
// ---------------------------------------------------------------------------

#[tracing::instrument(skip(resources, auth), fields(user_id = %auth.user_id))]
#[utoipa::path(
    get,
    path = "/me",
    tag = ACCOUNT_TAG,
    operation_id = "Get Account",
    summary = "Get account information",
    security(("OAuth2" = ["openid"])),
    responses(
        (status = 200, description = "Account information", body = AccountInfoResponse),
        (status = 401, description = "Unauthorized", body = AuthError),
    )
)]
async fn get_account(
    Extension(resources): Extension<AppResources>,
    OAuth2Auth(auth): OAuth2Auth,
) -> Result<Json<AccountInfoResponse>, AuthError> {
    let user = oauth2_user::Entity::find_by_id(&auth.user_id)
        .one(resources.db.as_ref())
        .await
        .map_err(|_| AuthError::server_error())?
        .ok_or_else(|| AuthError::not_found("User not found"))?;

    let additional_emails = user_email::Entity::find()
        .filter(user_email::Column::UserId.eq(&auth.user_id))
        .all(resources.db.as_ref())
        .await
        .map_err(|_| AuthError::server_error())?
        .into_iter()
        .map(EmailDto::from)
        .collect();

    Ok(Json(AccountInfoResponse {
        user_id: user.id,
        email: user.email,
        name: user.name,
        email_verified: user.email_verified,
        receives_alerts: user.receives_alerts,
        created_at: user.created_at,
        last_login_at: user.last_login_at,
        additional_emails,
    }))
}

// ---------------------------------------------------------------------------
// PATCH /api/v2/account
// ---------------------------------------------------------------------------

#[tracing::instrument(skip(resources, auth, payload), fields(user_id = %auth.user_id))]
#[utoipa::path(
    patch,
    path = "",
    tag = ACCOUNT_TAG,
    operation_id = "Update Primary Email Settings",
    summary = "Toggle whether the primary login email receives alert notifications",
    security(("OAuth2" = ["openid"])),
    request_body(content = UpdatePrimaryRequest),
    responses(
        (status = 200, description = "Updated account info", body = AccountInfoResponse),
        (status = 401, description = "Unauthorized", body = AuthError),
    )
)]
async fn update_primary_settings(
    Extension(resources): Extension<AppResources>,
    OAuth2Auth(auth): OAuth2Auth,
    Json(payload): Json<UpdatePrimaryRequest>,
) -> Result<Json<AccountInfoResponse>, AuthError> {
    let user = oauth2_user::Entity::find_by_id(&auth.user_id)
        .one(resources.db.as_ref())
        .await
        .map_err(|_| AuthError::server_error())?
        .ok_or_else(|| AuthError::not_found("User not found"))?;

    let mut active: oauth2_user::ActiveModel = user.into();
    active.receives_alerts = Set(payload.receives_alerts);
    let updated = active
        .update(resources.db.as_ref())
        .await
        .map_err(|_| AuthError::server_error())?;

    let additional_emails = user_email::Entity::find()
        .filter(user_email::Column::UserId.eq(&auth.user_id))
        .all(resources.db.as_ref())
        .await
        .map_err(|_| AuthError::server_error())?
        .into_iter()
        .map(EmailDto::from)
        .collect();

    Ok(Json(AccountInfoResponse {
        user_id: updated.id,
        email: updated.email,
        name: updated.name,
        email_verified: updated.email_verified,
        receives_alerts: updated.receives_alerts,
        created_at: updated.created_at,
        last_login_at: updated.last_login_at,
        additional_emails,
    }))
}

// ---------------------------------------------------------------------------
// DELETE /api/v2/account
// ---------------------------------------------------------------------------

#[tracing::instrument(skip(resources, auth), fields(user_id = %auth.user_id))]
#[utoipa::path(
    delete,
    path = "",
    tag = ACCOUNT_TAG,
    operation_id = "Delete Account",
    summary = "Permanently delete the account and all associated data (GDPR)",
    security(("OAuth2" = ["openid"])),
    responses(
        (status = 204, description = "Account deleted"),
        (status = 401, description = "Unauthorized", body = AuthError),
    )
)]
async fn delete_account(
    Extension(resources): Extension<AppResources>,
    OAuth2Auth(auth): OAuth2Auth,
) -> Result<StatusCode, AuthError> {
    let db = resources.db.as_ref();
    let user_id = &auth.user_id;
    let email = &auth.email;

    // 1. Collect alert IDs owned by this user so we can cascade to status history.
    let alert_ids: Vec<i32> = alert::Entity::find()
        .filter(
            alert::Column::UserId
                .eq(user_id)
                .or(alert::Column::Email.eq(email)),
        )
        .all(db)
        .await
        .map_err(|_| AuthError::server_error())?
        .into_iter()
        .map(|a| a.id)
        .collect();

    if !alert_ids.is_empty() {
        alert_status_history::Entity::delete_many()
            .filter(alert_status_history::Column::AlertId.is_in(alert_ids))
            .exec(db)
            .await
            .map_err(|_| AuthError::server_error())?;
    }

    // 2. Alerts
    alert::Entity::delete_many()
        .filter(
            alert::Column::UserId
                .eq(user_id)
                .or(alert::Column::Email.eq(email)),
        )
        .exec(db)
        .await
        .map_err(|_| AuthError::server_error())?;

    // 3. Additional emails
    user_email::Entity::delete_many()
        .filter(user_email::Column::UserId.eq(user_id))
        .exec(db)
        .await
        .map_err(|_| AuthError::server_error())?;

    // 4. OAuth2 tokens (revoke all sessions)
    oauth2_token::Entity::delete_many()
        .filter(oauth2_token::Column::UserId.eq(user_id))
        .exec(db)
        .await
        .map_err(|_| AuthError::server_error())?;

    // 5. OAuth2 authorization codes
    oauth2_authorization::Entity::delete_many()
        .filter(oauth2_authorization::Column::UserId.eq(user_id))
        .exec(db)
        .await
        .map_err(|_| AuthError::server_error())?;

    // 6. OAuth2 identities
    oauth2_identity::Entity::delete_many()
        .filter(oauth2_identity::Column::UserId.eq(user_id))
        .exec(db)
        .await
        .map_err(|_| AuthError::server_error())?;

    // 7. The user record itself
    oauth2_user::Entity::delete_by_id(user_id)
        .exec(db)
        .await
        .map_err(|_| AuthError::server_error())?;

    tracing::info!(user_id = %user_id, "Account deleted (GDPR request)");

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// GET /api/v2/account/export
// ---------------------------------------------------------------------------

#[tracing::instrument(skip(resources, auth), fields(user_id = %auth.user_id))]
#[utoipa::path(
    get,
    path = "/export",
    tag = ACCOUNT_TAG,
    operation_id = "Export Account Data",
    summary = "Download all personal data as JSON (GDPR Article 20)",
    security(("OAuth2" = ["openid"])),
    responses(
        (status = 200, description = "JSON file attachment containing all personal data"),
        (status = 401, description = "Unauthorized", body = AuthError),
    )
)]
async fn export_data(
    Extension(resources): Extension<AppResources>,
    OAuth2Auth(auth): OAuth2Auth,
) -> Result<Response, AuthError> {
    let db = resources.db.as_ref();

    let user = oauth2_user::Entity::find_by_id(&auth.user_id)
        .one(db)
        .await
        .map_err(|_| AuthError::server_error())?
        .ok_or_else(|| AuthError::not_found("User not found"))?;

    let additional_emails: Vec<EmailDto> = user_email::Entity::find()
        .filter(user_email::Column::UserId.eq(&auth.user_id))
        .all(db)
        .await
        .map_err(|_| AuthError::server_error())?
        .into_iter()
        .map(EmailDto::from)
        .collect();

    let alerts: Vec<GdprAlertInfo> = alert::Entity::find()
        .filter(
            alert::Column::UserId
                .eq(&auth.user_id)
                .or(alert::Column::Email.eq(&auth.email)),
        )
        .all(db)
        .await
        .map_err(|_| AuthError::server_error())?
        .into_iter()
        .map(GdprAlertInfo::from)
        .collect();

    let export = GdprExport {
        exported_at: OffsetDateTime::now_utc(),
        account: GdprAccountInfo {
            user_id: user.id,
            email: user.email,
            name: user.name,
            email_verified: user.email_verified,
            receives_alerts: user.receives_alerts,
            created_at: user.created_at,
            last_login_at: user.last_login_at,
        },
        additional_emails,
        alerts,
    };

    let json = serde_json::to_string_pretty(&export).map_err(|_| AuthError::server_error())?;

    let filename = format!("account-data-{}.json", OffsetDateTime::now_utc().date());
    let disposition = HeaderValue::from_str(&format!("attachment; filename=\"{}\"", filename))
        .map_err(|_| AuthError::server_error())?;

    Ok((
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            ),
            (header::CONTENT_DISPOSITION, disposition),
        ],
        json,
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// POST /api/v2/account/emails
// ---------------------------------------------------------------------------

#[tracing::instrument(skip(resources, auth, payload), fields(user_id = %auth.user_id))]
#[utoipa::path(
    post,
    path = "/emails",
    tag = ACCOUNT_TAG,
    operation_id = "Add Email",
    summary = "Add an additional email address (sends a verification link)",
    security(("OAuth2" = ["openid"])),
    request_body(content = AddEmailRequest),
    responses(
        (status = 201, description = "Email added, verification link sent", body = EmailDto),
        (status = 400, description = "Invalid or duplicate email", body = AuthError),
        (status = 401, description = "Unauthorized", body = AuthError),
    )
)]
async fn add_email(
    Extension(resources): Extension<AppResources>,
    OAuth2Auth(auth): OAuth2Auth,
    Json(payload): Json<AddEmailRequest>,
) -> Result<(StatusCode, Json<EmailDto>), AuthError> {
    let email = payload.email.trim().to_lowercase();
    if email.is_empty() || !email.contains('@') {
        return Err(AuthError::bad_request("Invalid email address"));
    }

    // Must not duplicate the primary login email
    if email == auth.email {
        return Err(AuthError::bad_request(
            "That is already your primary login email",
        ));
    }

    // Must not already exist in user_email
    let existing = user_email::Entity::find()
        .filter(user_email::Column::Email.eq(&email))
        .one(resources.db.as_ref())
        .await
        .map_err(|_| AuthError::server_error())?;

    if existing.is_some() {
        return Err(AuthError::bad_request(
            "That email address is already registered",
        ));
    }

    let token = generate_verification_token();
    let now = OffsetDateTime::now_utc();
    let expires = now + time::Duration::hours(24);

    let row = user_email::ActiveModel {
        id: Set(uuid::Uuid::new_v4().to_string()),
        user_id: Set(auth.user_id.clone()),
        email: Set(email.clone()),
        verified: Set(false),
        receives_alerts: Set(false),
        verification_token: Set(Some(token.clone())),
        verification_expires_at: Set(Some(expires)),
        created_at: Set(now),
    };

    let inserted = row
        .insert(resources.db.as_ref())
        .await
        .map_err(|_| AuthError::server_error())?;

    if let Err(e) = send_verification_email(&resources, &email, &token).await {
        tracing::error!("Failed to send additional-email verification: {}", e);
        // Clean up the row so the user can retry
        let _ = user_email::Entity::delete_by_id(&inserted.id)
            .exec(resources.db.as_ref())
            .await;
        return Err(AuthError::server_error());
    }

    Ok((StatusCode::CREATED, Json(EmailDto::from(inserted))))
}

// ---------------------------------------------------------------------------
// GET /api/v2/account/emails/verify?token=…
// ---------------------------------------------------------------------------

#[tracing::instrument(skip(resources, params))]
#[utoipa::path(
    get,
    path = "/emails/verify",
    tag = ACCOUNT_TAG,
    operation_id = "Verify Additional Email",
    summary = "Verify an additional email address via the token sent by email",
    params(("token" = String, Query, description = "Verification token from the email link")),
    responses(
        (status = 303, description = "Redirect to /account on success"),
        (status = 400, description = "Invalid or expired token"),
    )
)]
async fn verify_email(
    Extension(resources): Extension<AppResources>,
    Query(params): Query<VerifyTokenQuery>,
) -> Response {
    // After verification, redirect to the backend account page (same origin as this endpoint).
    let issuer = resources.config.oauth2.issuer_url.trim_end_matches('/');

    let row = match user_email::Entity::find()
        .filter(user_email::Column::VerificationToken.eq(&params.token))
        .one(resources.db.as_ref())
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => {
            return Redirect::to(&format!("{}/oauth2/account?error=invalid_token", issuer))
                .into_response();
        }
        Err(_) => {
            return Redirect::to(&format!("{}/oauth2/account?error=server_error", issuer))
                .into_response();
        }
    };

    if row.is_verification_expired() {
        let _ = user_email::Entity::delete_by_id(&row.id)
            .exec(resources.db.as_ref())
            .await;
        return Redirect::to(&format!("{}/oauth2/account?error=token_expired", issuer))
            .into_response();
    }

    let mut active: user_email::ActiveModel = row.into();
    active.verified = Set(true);
    active.verification_token = Set(None);
    active.verification_expires_at = Set(None);

    if let Err(e) = active.update(resources.db.as_ref()).await {
        tracing::error!("Failed to verify additional email: {}", e);
        return Redirect::to(&format!("{}/oauth2/account?error=server_error", issuer))
            .into_response();
    }

    Redirect::to(&format!("{}/oauth2/account?verified=1", issuer)).into_response()
}

// ---------------------------------------------------------------------------
// PATCH /api/v2/account/emails/{id}
// ---------------------------------------------------------------------------

#[tracing::instrument(skip(resources, auth, payload), fields(user_id = %auth.user_id, email_id = %id))]
#[utoipa::path(
    patch,
    path = "/emails/{id}",
    tag = ACCOUNT_TAG,
    operation_id = "Update Additional Email",
    summary = "Toggle receives_alerts for an additional email",
    security(("OAuth2" = ["openid"])),
    params(("id" = String, Path, description = "Email record ID")),
    request_body(content = UpdateEmailRequest),
    responses(
        (status = 200, description = "Updated email", body = EmailDto),
        (status = 401, description = "Unauthorized", body = AuthError),
        (status = 404, description = "Not found", body = AuthError),
    )
)]
async fn update_email(
    Extension(resources): Extension<AppResources>,
    OAuth2Auth(auth): OAuth2Auth,
    Path(id): Path<String>,
    Json(payload): Json<UpdateEmailRequest>,
) -> Result<Json<EmailDto>, AuthError> {
    let row = find_owned_email(&resources, &id, &auth.user_id).await?;

    if !row.verified && payload.receives_alerts {
        return Err(AuthError::bad_request(
            "Email must be verified before enabling alert notifications",
        ));
    }

    let mut active: user_email::ActiveModel = row.into();
    active.receives_alerts = Set(payload.receives_alerts);
    let updated = active
        .update(resources.db.as_ref())
        .await
        .map_err(|_| AuthError::server_error())?;

    Ok(Json(EmailDto::from(updated)))
}

// ---------------------------------------------------------------------------
// DELETE /api/v2/account/emails/{id}
// ---------------------------------------------------------------------------

#[tracing::instrument(skip(resources, auth), fields(user_id = %auth.user_id, email_id = %id))]
#[utoipa::path(
    delete,
    path = "/emails/{id}",
    tag = ACCOUNT_TAG,
    operation_id = "Remove Additional Email",
    summary = "Remove an additional email address",
    description = "Requires at least one other verified email (primary or additional) to remain.",
    security(("OAuth2" = ["openid"])),
    params(("id" = String, Path, description = "Email record ID")),
    responses(
        (status = 204, description = "Email removed"),
        (status = 400, description = "Cannot remove — no other verified email", body = AuthError),
        (status = 401, description = "Unauthorized", body = AuthError),
        (status = 404, description = "Not found", body = AuthError),
    )
)]
async fn remove_email(
    Extension(resources): Extension<AppResources>,
    OAuth2Auth(auth): OAuth2Auth,
    Path(id): Path<String>,
) -> Result<StatusCode, AuthError> {
    let row = find_owned_email(&resources, &id, &auth.user_id).await?;

    // Safety check: must have at least one other verified address after removal.
    // The primary email counts if it is verified.
    let other_verified_additional = user_email::Entity::find()
        .filter(user_email::Column::UserId.eq(&auth.user_id))
        .filter(user_email::Column::Id.ne(&id))
        .filter(user_email::Column::Verified.eq(true))
        .count(resources.db.as_ref())
        .await
        .map_err(|_| AuthError::server_error())?;

    let primary_verified = auth.email_verified;

    if other_verified_additional == 0 && !primary_verified {
        return Err(AuthError::bad_request(
            "Cannot remove the only verified email address. \
             Verify another email first.",
        ));
    }

    user_email::Entity::delete_by_id(&row.id)
        .exec(resources.db.as_ref())
        .await
        .map_err(|_| AuthError::server_error())?;

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn find_owned_email(
    resources: &AppResources,
    id: &str,
    user_id: &str,
) -> Result<user_email::Model, AuthError> {
    let row = user_email::Entity::find_by_id(id)
        .one(resources.db.as_ref())
        .await
        .map_err(|_| AuthError::server_error())?
        .ok_or_else(|| AuthError::not_found("Email not found"))?;

    if row.user_id != user_id {
        return Err(AuthError::forbidden("You do not own this email"));
    }

    Ok(row)
}

async fn send_verification_email(
    resources: &AppResources,
    to_email: &str,
    token: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let verify_url = format!(
        "{}/oauth2/account/emails/verify?token={}",
        resources.config.oauth2.issuer_url.trim_end_matches('/'),
        urlencoding::encode(token)
    );

    let body_html = format!(
        r#"<p>Click the link below to verify your email address:</p>
<p><a href="{url}">{url}</a></p>
<p>This link expires in 24 hours. If you did not request this, you can ignore this email.</p>"#,
        url = verify_url
    );
    let body_text = format!(
        "Verify your email address:\n{}\n\nThis link expires in 24 hours.",
        verify_url
    );

    let msg = lettre::Message::builder()
        .from(resources.config.smtp.from.parse()?)
        .to(to_email.parse()?)
        .subject("Verify your email address - Federation Tester")
        .header(lettre::message::header::MIME_VERSION_1_0)
        .multipart(
            MultiPart::alternative()
                .singlepart(
                    SinglePart::builder()
                        .header(lettre::message::header::ContentType::TEXT_PLAIN)
                        .body(body_text),
                )
                .singlepart(
                    SinglePart::builder()
                        .header(lettre::message::header::ContentType::TEXT_HTML)
                        .body(body_html),
                ),
        )?;

    resources.mailer.send(msg).await?;
    Ok(())
}
