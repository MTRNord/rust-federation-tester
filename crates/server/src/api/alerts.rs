//! Alert management API endpoints.
//!
//! Provides endpoints for managing federation alerts:
//! - `/register` - Register a new alert subscription
//! - `/list` - Request list of alerts for an email
//! - `/verify` - Verify email and complete actions
//! - `/{id}` - Delete an alert

use crate::{AppResources, entity::alert, recurring_alerts::AlertTaskManager};
use axum::{
    Extension, Json,
    extract::{Path, Query},
    response::IntoResponse,
};
use hyper::StatusCode;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use lettre::AsyncTransport;
use sea_orm::{ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};

/// Tag for OpenAPI documentation.
pub const ALERTS_TAG: &str = "Alerts API";

/// JWT claims for magic link authentication.
#[derive(Serialize, Deserialize)]
pub struct MagicClaims {
    pub exp: usize,
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    pub action: String, // "register", "list", "delete"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alert_id: Option<String>, // Only for delete
}

#[derive(serde::Deserialize, ToSchema)]
struct RegisterAlert {
    email: String,
    server_name: String,
}

#[derive(serde::Deserialize, ToSchema)]
struct ListAlerts {
    email: String,
}

#[derive(Deserialize, IntoParams)]
struct VerifyParams {
    token: String,
}

/// Shared state for alert endpoints.
#[derive(Clone)]
pub struct AlertAppState {
    pub task_manager: Arc<AlertTaskManager>,
}

/// Creates the alerts API router.
#[tracing::instrument(skip_all)]
pub fn router(alert_state: AlertAppState) -> OpenApiRouter {
    OpenApiRouter::new()
        .routes(routes!(register_alert, delete_alert))
        .routes(routes!(list_alerts))
        .routes(routes!(verify_alert))
        .with_state(alert_state)
}

#[tracing::instrument(skip(resources, payload), fields(server_name = payload.server_name, email_len = payload.email.len()))]
#[utoipa::path(
    post,
    path = "/register",
    operation_id = "Register Alert",
    tag = ALERTS_TAG,
    summary = "Register a new federation alert subscription",
    description = "Creates a new alert subscription to monitor a Matrix server's federation status.\n\n\
                   **Process:**\n\
                   1. A verification email is sent to the provided address\n\
                   2. The user must click the verification link to activate the alert\n\
                   3. Once verified, the system periodically checks the server's federation status\n\
                   4. If issues are detected, notification emails are sent\n\n\
                   **Note:** If an alert already exists for this email/server combination and is verified, \
                   no new verification email is sent.",
    request_body(
        content = RegisterAlert,
        description = "Alert subscription details"
    ),
    responses(
        (status = 200, description = "Verification email sent successfully", content_type = "application/json", example = json!({"status": "verification email sent"})),
        (status = 400, description = "Invalid request (e.g., invalid email format or server name)", content_type = "application/json"),
        (status = 500, description = "Internal server error (e.g., email delivery failed)", content_type = "application/json")
    )
)]
async fn register_alert(
    Extension(resources): Extension<AppResources>,
    Json(payload): Json<RegisterAlert>,
) -> impl IntoResponse {
    // JWT magic token
    let exp = (OffsetDateTime::now_utc() + time::Duration::hours(1)).unix_timestamp() as usize;
    let claims = MagicClaims {
        exp,
        email: payload.email.clone(),
        server_name: Some(payload.server_name.clone()),
        action: "register".to_string(),
        alert_id: None,
    };
    let secret = resources.config.magic_token_secret.as_bytes();
    let token = match encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret),
    ) {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("Failed to generate token: {e}") })),
            );
        }
    };

    let now = OffsetDateTime::now_utc();

    // Check for existing alert
    let existing = alert::Entity::find()
        .filter(alert::Column::Email.eq(payload.email.clone()))
        .filter(alert::Column::ServerName.eq(payload.server_name.clone()))
        .one(resources.db.as_ref())
        .await;
    match existing {
        Ok(Some(a)) => {
            if a.verified {
                // Already verified, noop
                return (
                    StatusCode::OK,
                    Json(json!({ "status": "already verified" })),
                );
            } else {
                // Not verified, update token and created_at, send new email
                let mut model: alert::ActiveModel = a.into();
                model.magic_token = Set(token.clone());
                model.created_at = Set(now);
                if let Err(e) = model.update(resources.db.as_ref()).await {
                    tracing::error!(
                        name = "api.register_alert.db_update_failed",
                        target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                        error = ?e,
                        message = "Failed to update existing alert"
                    );
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": format!("DB error: {e}")})),
                    );
                }
            }
        }
        Ok(None) => {
            // Insert alert (unverified)
            let new_alert = alert::ActiveModel {
                email: Set(payload.email.clone()),
                server_name: Set(payload.server_name.clone()),
                verified: Set(false),
                magic_token: Set(token.clone()),
                created_at: Set(now),
                ..Default::default()
            };
            let insert_res = alert::Entity::insert(new_alert)
                .exec(resources.db.as_ref())
                .await;
            if let Err(e) = insert_res {
                tracing::error!(
                    name = "api.register_alert.db_insert_failed",
                    target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                    error = ?e,
                    message = "Failed to insert new alert"
                );
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": format!("DB error: {e}")})),
                );
            }
        }
        Err(e) => {
            tracing::error!(
                name = "api.register_alert.db_query_failed",
                target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                error = ?e,
                message = "Failed to query existing alert"
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("DB error: {e}")})),
            );
        }
    }

    // Send verification email (always for new or unverified)
    let verify_url = format!("{}/verify?token={}", resources.config.frontend_url, token);

    let template = crate::email_templates::VerificationEmailTemplate {
        server_name: payload.server_name.clone(),
        verify_url: verify_url.clone(),
    };

    let subject = "Please verify your email for Federation Alerts";

    // Render both HTML and plain text versions
    let html_body = match template.render_html() {
        Ok(html) => html,
        Err(e) => {
            tracing::error!(
                name = "api.register_alert.template_render_failed",
                target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                error = %e,
                message = "Failed to render HTML email template"
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Failed to render email template" })),
            );
        }
    };
    let text_body = template.render_text();

    // Create multipart email with both HTML and plain text
    let email = lettre::Message::builder()
        .from(resources.config.smtp.from.parse().unwrap())
        .to(payload.email.parse().unwrap())
        .subject(subject)
        .header(lettre::message::header::MIME_VERSION_1_0)
        .message_id(None)
        .multipart(
            lettre::message::MultiPart::alternative()
                .singlepart(
                    lettre::message::SinglePart::builder()
                        .header(lettre::message::header::ContentType::TEXT_PLAIN)
                        .body(text_body),
                )
                .singlepart(
                    lettre::message::SinglePart::builder()
                        .header(lettre::message::header::ContentType::TEXT_HTML)
                        .body(html_body),
                ),
        )
        .unwrap();

    if let Err(e) = resources.mailer.send(email).await {
        tracing::error!(
            name = "api.register_alert.email_send_failed",
            target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            error = ?e,
            message = "Failed to send verification email"
        );
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("Failed to send email: {e}") })),
        );
    }

    (
        StatusCode::OK,
        Json(json!({ "status": "verification email sent" })),
    )
}

#[derive(Serialize, ToSchema)]
struct VerificatonResponseData {
    /// The result status of the verification
    status: String,
}

#[derive(Serialize, ToSchema)]
struct AlertsList {
    alerts: Vec<alert::Model>,
}

#[tracing::instrument(skip(resources, params), fields(token_len = params.token.len()))]
#[utoipa::path(
    get,
    path = "/verify",
    tag = ALERTS_TAG,
    operation_id = "Verify Alert Email",
    summary = "Verify email and complete pending action",
    description = "Verifies an email address and completes the pending action (register, list, or delete alert).\n\n\
                   **Actions:**\n\
                   - `register`: Activates the alert subscription and starts monitoring\n\
                   - `list`: Returns all alert subscriptions for the verified email\n\
                   - `delete`: Removes the specified alert subscription\n\n\
                   **Token:** The JWT token is sent via email and expires after 1 hour.",
    params(
        (
            "token" = String,
            Query,
            description = "JWT token received via email. Contains the action type and associated data.",
            example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
        ),
    ),
    responses(
        (status = 200, description = "Action completed successfully. Response body depends on action type.", content_type = "application/json"),
        (status = 400, description = "Invalid or expired token", content_type = "application/json"),
        (status = 404, description = "Alert not found (for delete action)", content_type = "application/json"),
        (status = 500, description = "Internal server error", content_type = "application/json")
    )
)]
async fn verify_alert(
    Extension(resources): Extension<AppResources>,
    Query(params): Query<VerifyParams>,
) -> impl IntoResponse {
    let secret = resources.config.magic_token_secret.as_bytes();
    let mut validation = Validation::default();
    validation.validate_exp = true;
    let token_data = decode::<MagicClaims>(
        &params.token,
        &DecodingKey::from_secret(secret),
        &validation,
    );
    match token_data {
        Ok(data) => {
            let claims = data.claims;
            match claims.action.as_str() {
                "register" => {
                    // Mark alert as verified (new flow)
                    let found = alert::Entity::find()
                        .filter(alert::Column::Email.eq(claims.email.clone()))
                        .filter(alert::Column::ServerName.eq(claims.server_name.clone()))
                        .one(resources.db.as_ref())
                        .await;
                    match found {
                        Ok(Some(a)) => {
                            let mut model: alert::ActiveModel = a.into();
                            model.verified = Set(true);
                            if let Err(e) = model.update(resources.db.as_ref()).await {
                                tracing::error!(
                                    name = "api.verify_alert.db_update_failed",
                                    target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                                    error = ?e,
                                    message = "Failed to verify alert"
                                );
                                return (
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    Json(json!({"error": format!("DB error: {e}")})),
                                );
                            }
                            (StatusCode::OK, Json(json!({"status": "alert verified"})))
                        }
                        Ok(None) => (
                            StatusCode::BAD_REQUEST,
                            Json(json!({"error": "No alert found for this email and server"})),
                        ),
                        Err(e) => {
                            tracing::error!(
                                name = "api.verify_alert.db_query_failed",
                                target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                                error = ?e,
                                message = "Failed to query alert for verification"
                            );
                            (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Json(json!({"error": format!("DB error: {e}")})),
                            )
                        }
                    }
                }
                "list" => {
                    // Return all alerts for this email/server
                    let alerts = alert::Entity::find()
                        .filter(alert::Column::Email.eq(claims.email.clone()))
                        .all(resources.db.as_ref())
                        .await;
                    match alerts {
                        Ok(list) => (StatusCode::OK, Json(json!({"alerts": list}))),
                        Err(e) => {
                            tracing::error!(
                                name = "api.verify_alert.db_query_failed",
                                target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                                error = ?e,
                                message = "Failed to query alerts for listing"
                            );
                            (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Json(json!({"error": format!("DB error: {e}")})),
                            )
                        }
                    }
                }
                "delete" => {
                    // Delete the alert with the given id for this email
                    if let Some(alert_id) = claims.alert_id.clone() {
                        let alert_id: i32 = match alert_id.parse() {
                            Ok(id) => id,
                            Err(e) => {
                                tracing::error!(
                                    name = "api.verify_alert.invalid_alert_id",
                                    target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                                    alert_id = %alert_id,
                                    error = ?e,
                                    message = "Invalid alert_id in token"
                                );
                                return (
                                    StatusCode::BAD_REQUEST,
                                    Json(json!({"error": "Invalid alert_id in token"})),
                                );
                            }
                        };
                        let del = alert::Entity::delete_many()
                            .filter(alert::Column::Id.eq(alert_id))
                            .filter(alert::Column::Email.eq(claims.email.clone()))
                            .exec(resources.db.as_ref())
                            .await;
                        match del {
                            Ok(_) => (StatusCode::OK, Json(json!({"status": "deleted"}))),
                            Err(e) => {
                                tracing::error!(
                                    name = "api.verify_alert.delete_failed",
                                    target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                                    error = ?e,
                                    message = "Failed to delete alert"
                                );
                                (
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    Json(json!({"error": format!("DB error: {e}")})),
                                )
                            }
                        }
                    } else {
                        (
                            StatusCode::BAD_REQUEST,
                            Json(json!({"error": "Missing alert_id in token"})),
                        )
                    }
                }
                _ => (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "Unknown action"})),
                ),
            }
        }
        Err(e) => {
            tracing::warn!(
                name = "api.verify_alert.invalid_or_expired_token",
                target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                error = %e,
                message = "Invalid or expired token used for verification"
            );
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Invalid or expired token"})),
            )
        }
    }
}

#[tracing::instrument(skip(resources, payload), fields(email_len = payload.email.len()))]
#[utoipa::path(
    post,
    path = "/list",
    tag = ALERTS_TAG,
    operation_id = "List Alerts",
    summary = "Request list of alert subscriptions",
    description = "Requests a list of all alert subscriptions for an email address.\n\n\
                   **Process:**\n\
                   1. A verification email is sent to the provided address\n\
                   2. The user clicks the verification link\n\
                   3. The list of alerts is returned in the verification response\n\n\
                   This two-step process ensures only the email owner can view their subscriptions.",
    request_body(
        content = ListAlerts,
        description = "Email address to list alerts for"
    ),
    responses(
        (status = 200, description = "Verification email sent successfully", content_type = "application/json", example = json!({"status": "verification email sent"})),
        (status = 400, description = "Invalid email format", content_type = "application/json"),
        (status = 500, description = "Internal server error (e.g., email delivery failed)", content_type = "application/json")
    )
)]
async fn list_alerts(
    Extension(resources): Extension<AppResources>,
    Json(payload): Json<ListAlerts>,
) -> impl IntoResponse {
    let exp = (OffsetDateTime::now_utc() + time::Duration::hours(1)).unix_timestamp() as usize;
    let claims = MagicClaims {
        exp,
        email: payload.email.clone(),
        action: "list".to_string(),
        alert_id: None,
        server_name: None,
    };
    let secret = resources.config.magic_token_secret.as_bytes();
    let token = match encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret),
    ) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(
                name = "api.list_alerts.token_generation_failed",
                target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                error = ?e,
                message = "Failed to generate token for listing alerts"
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("Failed to generate token: {e}") })),
            );
        }
    };
    let verify_url = format!("{}/verify?token={}", resources.config.frontend_url, token);
    let email_body = format!(
        r#"Hello,

You requested to view your alerts.

Please verify by clicking the link below (valid for 1 hour):
{verify_url}

Best regards,
The Federation Tester Team"#
    );
    let email = lettre::Message::builder()
        .from(resources.config.smtp.from.parse().unwrap())
        .to(payload.email.parse().unwrap())
        .subject("Verify to view your Federation Alerts")
        .header(lettre::message::header::ContentType::TEXT_PLAIN)
        .header(lettre::message::header::MIME_VERSION_1_0)
        .message_id(None)
        .body(email_body)
        .unwrap();
    if let Err(e) = resources.mailer.send(email).await {
        tracing::error!(
            name = "api.list_alerts.email_send_failed",
            target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            error = ?e,
            message = "Failed to send verification email"
        );
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("Failed to send email: {e}") })),
        );
    }
    (
        StatusCode::OK,
        Json(json!({ "status": "verification email sent" })),
    )
}

#[tracing::instrument(skip(resources))]
#[utoipa::path(
    delete,
    path = "/{id}",
    tag = ALERTS_TAG,
    operation_id = "Delete Alert",
    summary = "Request deletion of an alert subscription",
    description = "Initiates the deletion process for an alert subscription.\n\n\
                   **Process:**\n\
                   1. A verification email is sent to the alert's registered email address\n\
                   2. The user clicks the verification link to confirm deletion\n\
                   3. The alert is permanently removed and monitoring stops\n\n\
                   This two-step process prevents unauthorized deletion of alerts.",
    params(
        (
            "id" = i32,
            Path,
            description = "Numeric ID of the alert subscription to delete",
            example = 42
        ),
    ),
    responses(
        (status = 200, description = "Deletion verification email sent", content_type = "application/json", example = json!({"status": "verification email sent"})),
        (status = 404, description = "Alert with the specified ID not found", content_type = "application/json"),
        (status = 500, description = "Internal server error (e.g., email delivery failed)", content_type = "application/json")
    )
)]
async fn delete_alert(
    Extension(resources): Extension<AppResources>,
    Path(id): Path<i32>,
) -> impl IntoResponse {
    let found = alert::Entity::find()
        .filter(alert::Column::Id.eq(id))
        .one(resources.db.as_ref())
        .await;
    match found {
        Ok(Some(a)) => {
            let exp =
                (OffsetDateTime::now_utc() + time::Duration::hours(1)).unix_timestamp() as usize;
            let claims = MagicClaims {
                exp,
                email: a.email.clone(),
                server_name: Some(a.server_name.clone()),
                action: "delete".to_string(),
                alert_id: Some(id.to_string()),
            };
            let secret = resources.config.magic_token_secret.as_bytes();
            let token = match encode(
                &Header::default(),
                &claims,
                &EncodingKey::from_secret(secret),
            ) {
                Ok(t) => t,
                Err(e) => {
                    tracing::error!(
                        name = "api.delete_alert.token_generation_failed",
                        target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                        error = ?e,
                        message = "Failed to generate token for deleting alert"
                    );
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({ "error": format!("Failed to generate token: {e}") })),
                    );
                }
            };
            let verify_url = format!("{}/verify?token={}", resources.config.frontend_url, token);
            let email_body = format!(
                r#"Hello,

You requested to delete your alert for server: {}

Please verify by clicking the link below (valid for 1 hour):
{}

Best regards,
The Federation Tester Team"#,
                a.server_name, verify_url
            );
            let email = lettre::Message::builder()
                .from(resources.config.smtp.from.parse().unwrap())
                .to(a.email.parse().unwrap())
                .subject("Verify to delete your Federation Alert")
                .header(lettre::message::header::ContentType::TEXT_PLAIN)
                .header(lettre::message::header::MIME_VERSION_1_0)
                .message_id(None)
                .body(email_body)
                .unwrap();
            if let Err(e) = resources.mailer.send(email).await {
                tracing::error!(
                    name = "api.delete_alert.email_send_failed",
                    target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                    error = ?e,
                    message = "Failed to send verification email"
                );
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": format!("Failed to send email: {e}") })),
                );
            }
            (
                StatusCode::OK,
                Json(json!({ "status": "verification email sent" })),
            )
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Alert not found"})),
        ),
        Err(e) => {
            tracing::error!(
                name = "api.delete_alert.db_query_failed",
                target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                error = ?e,
                message = "Failed to query alert for deletion"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("DB error: {e}")})),
            )
        }
    }
}
