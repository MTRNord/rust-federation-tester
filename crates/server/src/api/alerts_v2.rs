//! v2 Alert management API endpoints (OAuth2-authenticated).
//!
//! Provides OAuth2-authenticated endpoints for managing federation alerts:
//! - `GET /` - List all alerts for the authenticated user
//! - `POST /` - Create a new alert subscription
//! - `DELETE /{id}` - Delete an alert
//! - `PUT /{id}/notify-emails` - Replace the notification email list for an alert

use crate::AppResources;
use crate::api::auth::{AuthError, OAuth2Auth, SCOPE_ALERTS_READ, SCOPE_ALERTS_WRITE};
use crate::entity::{alert, alert_notification_email, oauth2_user, user_email};
use crate::oauth2::IdentityService;
use axum::{Extension, Json, extract::Path};
use hyper::StatusCode;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter, TransactionTrait,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use time::OffsetDateTime;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

/// Tag for OpenAPI documentation.
pub const ALERTS_V2_TAG: &str = "Alerts API v2";

/// Response containing a list of alerts.
#[derive(Debug, Serialize, ToSchema)]
pub struct AlertsListResponse {
    /// List of alert subscriptions
    pub alerts: Vec<AlertDto>,
    /// Total number of alerts
    pub total: usize,
}

/// Alert data transfer object.
#[derive(Debug, Serialize, ToSchema)]
pub struct AlertDto {
    /// Unique alert identifier
    pub id: i32,
    /// Matrix server name being monitored
    pub server_name: String,
    /// Whether the alert is verified and active
    pub verified: bool,
    /// When the alert was created
    pub created_at: OffsetDateTime,
    /// Last time the server was checked
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_check_at: Option<OffsetDateTime>,
    /// Whether the server is currently failing federation checks
    pub is_currently_failing: bool,
    /// Email addresses that receive notifications for this alert
    pub notify_emails: Vec<String>,
}

/// Request to create a new alert.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateAlertRequest {
    /// Matrix server name to monitor (e.g., "matrix.org")
    pub server_name: String,
}

/// Response after creating an alert.
#[derive(Debug, Serialize, ToSchema)]
pub struct CreateAlertResponse {
    /// Unique alert identifier
    pub id: i32,
    /// Matrix server name being monitored
    pub server_name: String,
    /// Whether the alert is verified and active
    pub verified: bool,
    /// When the alert was created
    pub created_at: OffsetDateTime,
}

/// Request to replace the notification email list for an alert.
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateNotifyEmailsRequest {
    /// Email addresses to receive notifications (must all be verified by the user)
    pub emails: Vec<String>,
}

/// Creates the v2 alerts API router.
#[tracing::instrument(skip_all)]
pub fn router() -> OpenApiRouter {
    OpenApiRouter::new()
        .routes(routes!(list_alerts_v2, create_alert_v2))
        .routes(routes!(delete_alert_v2))
        .routes(routes!(update_notify_emails))
}

/// Build `AlertDto` values from alert models and a pre-loaded email map.
fn build_alert_dtos(
    alerts: Vec<alert::Model>,
    emails_by_alert: &HashMap<i32, Vec<String>>,
) -> Vec<AlertDto> {
    alerts
        .into_iter()
        .map(|a| {
            // Return effective recipients: explicit rows when present, otherwise
            // fall back to alert.email so the frontend never shows an empty list.
            let notify_emails = match emails_by_alert.get(&a.id) {
                Some(emails) if !emails.is_empty() => emails.clone(),
                _ => {
                    if a.email.is_empty() {
                        vec![]
                    } else {
                        vec![a.email.clone()]
                    }
                }
            };
            AlertDto {
                id: a.id,
                server_name: a.server_name,
                verified: a.verified,
                created_at: a.created_at,
                last_check_at: a.last_check_at,
                is_currently_failing: a.is_currently_failing,
                notify_emails,
            }
        })
        .collect()
}

/// Batch-load notification emails for a slice of alert IDs (2 queries total).
async fn load_emails_by_alert(
    db: &sea_orm::DatabaseConnection,
    alert_ids: &[i32],
) -> Result<HashMap<i32, Vec<String>>, AuthError> {
    if alert_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let rows = alert_notification_email::Entity::find()
        .filter(alert_notification_email::Column::AlertId.is_in(alert_ids.to_vec()))
        .all(db)
        .await
        .map_err(|e| {
            tracing::error!("DB error loading notification emails: {}", e);
            AuthError::server_error()
        })?;

    let mut map: HashMap<i32, Vec<String>> = HashMap::new();
    for row in rows {
        map.entry(row.alert_id).or_default().push(row.email);
    }
    Ok(map)
}

/// Collect the set of verified email addresses owned by a user.
async fn verified_email_set(
    db: &sea_orm::DatabaseConnection,
    user_id: &str,
) -> Result<HashSet<String>, AuthError> {
    let user = oauth2_user::Entity::find_by_id(user_id)
        .one(db)
        .await
        .map_err(|_| AuthError::server_error())?
        .ok_or_else(AuthError::server_error)?;

    let mut set: HashSet<String> = HashSet::new();
    if user.email_verified {
        set.insert(user.email);
    }

    let additional = user_email::Entity::find()
        .filter(user_email::Column::UserId.eq(user_id))
        .filter(user_email::Column::Verified.eq(true))
        .all(db)
        .await
        .map_err(|_| AuthError::server_error())?;
    for ue in additional {
        set.insert(ue.email);
    }

    Ok(set)
}

/// List all alerts for the authenticated user.
#[tracing::instrument(skip(resources, auth), fields(user_email = %auth.email))]
#[utoipa::path(
    get,
    path = "",
    tag = ALERTS_V2_TAG,
    operation_id = "List User Alerts",
    summary = "List all alerts for the authenticated user",
    description = "Returns all alert subscriptions owned by the authenticated user.\n\n\
                   **Authentication:** Requires OAuth2 Bearer token with `alerts:read` scope.\n\n\
                   **Note:** Also includes legacy alerts linked by email address that haven't been \
                   migrated to OAuth2 yet.",
    security(("OAuth2" = ["alerts:read"])),
    responses(
        (status = 200, description = "List of alerts", body = AlertsListResponse),
        (status = 401, description = "Missing or invalid token", body = AuthError),
        (status = 403, description = "Missing required scope", body = AuthError),
    )
)]
async fn list_alerts_v2(
    Extension(resources): Extension<AppResources>,
    OAuth2Auth(auth): OAuth2Auth,
) -> Result<Json<AlertsListResponse>, AuthError> {
    if !auth.has_scope(SCOPE_ALERTS_READ) {
        return Err(AuthError::insufficient_scope(SCOPE_ALERTS_READ));
    }

    let identity_service = IdentityService::new(resources.db.clone());
    let alerts = identity_service
        .get_user_alerts(&auth.user_id, &auth.email, auth.email_verified)
        .await
        .map_err(|e| {
            tracing::error!("Database error listing alerts: {}", e);
            AuthError::server_error()
        })?;

    let alert_ids: Vec<i32> = alerts.iter().map(|a| a.id).collect();
    let emails_by_alert = load_emails_by_alert(resources.db.as_ref(), &alert_ids).await?;

    let total = alerts.len();
    let alert_dtos = build_alert_dtos(alerts, &emails_by_alert);

    Ok(Json(AlertsListResponse {
        alerts: alert_dtos,
        total,
    }))
}

/// Create a new alert subscription.
#[tracing::instrument(skip(resources, auth, payload), fields(user_email = %auth.email, server_name = %payload.server_name))]
#[utoipa::path(
    post,
    path = "",
    tag = ALERTS_V2_TAG,
    operation_id = "Create Alert",
    summary = "Create a new alert subscription",
    description = "Creates a new alert subscription for the authenticated user.\n\n\
                   **Authentication:** Requires OAuth2 Bearer token with `alerts:write` scope.\n\n\
                   **Verification:**\n\
                   - If the user's email is verified, the alert is created as pre-verified and immediately active\n\
                   - If the user's email is not verified, the alert is created but will need email verification\n\n\
                   **Note:** Only one alert per server name per user is allowed.",
    security(("OAuth2" = ["alerts:write"])),
    request_body(content = CreateAlertRequest, description = "Alert details"),
    responses(
        (status = 201, description = "Alert created successfully", body = CreateAlertResponse),
        (status = 400, description = "Invalid request or alert already exists", body = AuthError),
        (status = 401, description = "Missing or invalid token", body = AuthError),
        (status = 403, description = "Missing required scope", body = AuthError),
    )
)]
async fn create_alert_v2(
    Extension(resources): Extension<AppResources>,
    OAuth2Auth(auth): OAuth2Auth,
    Json(payload): Json<CreateAlertRequest>,
) -> Result<(StatusCode, Json<CreateAlertResponse>), AuthError> {
    if !auth.has_scope(SCOPE_ALERTS_WRITE) {
        return Err(AuthError::insufficient_scope(SCOPE_ALERTS_WRITE));
    }

    let server_name = payload.server_name.trim().to_lowercase();
    if server_name.is_empty() {
        return Err(AuthError::bad_request("Server name cannot be empty"));
    }

    let now = OffsetDateTime::now_utc();

    let existing = alert::Entity::find()
        .filter(alert::Column::Email.eq(&auth.email))
        .filter(alert::Column::ServerName.eq(&server_name))
        .one(resources.db.as_ref())
        .await
        .map_err(|e| {
            tracing::error!("Database error checking existing alert: {}", e);
            AuthError::server_error()
        })?;

    if let Some(existing_alert) = existing {
        return Err(AuthError {
            error: "alert_exists".to_string(),
            error_description: Some(format!(
                "Alert for server '{}' already exists (id: {})",
                server_name, existing_alert.id
            )),
        });
    }

    let is_verified = auth.email_verified;

    let new_alert = alert::ActiveModel {
        email: Set(auth.email.clone()),
        server_name: Set(server_name.clone()),
        verified: Set(is_verified),
        magic_token: Set(None),
        created_at: Set(now),
        user_id: Set(Some(auth.user_id.clone())),
        ..Default::default()
    };

    let inserted = new_alert.insert(resources.db.as_ref()).await.map_err(|e| {
        tracing::error!("Failed to create alert: {}", e);
        AuthError::server_error()
    })?;

    // Seed notification email with the user's primary email.
    alert_notification_email::ActiveModel {
        alert_id: Set(inserted.id),
        email: Set(auth.email.clone()),
        created_at: Set(now),
        ..Default::default()
    }
    .insert(resources.db.as_ref())
    .await
    .map_err(|e| {
        tracing::error!("Failed to create initial notification email: {}", e);
        AuthError::server_error()
    })?;

    tracing::info!(
        alert_id = inserted.id,
        server_name = %server_name,
        verified = is_verified,
        "Created new alert via OAuth2"
    );

    Ok((
        StatusCode::CREATED,
        Json(CreateAlertResponse {
            id: inserted.id,
            server_name: inserted.server_name,
            verified: inserted.verified,
            created_at: inserted.created_at,
        }),
    ))
}

/// Delete an alert subscription.
#[tracing::instrument(skip(resources, auth), fields(user_email = %auth.email, alert_id = %id))]
#[utoipa::path(
    delete,
    path = "/{id}",
    tag = ALERTS_V2_TAG,
    operation_id = "Delete Alert",
    summary = "Delete an alert subscription",
    description = "Deletes an alert subscription owned by the authenticated user.\n\n\
                   **Authentication:** Requires OAuth2 Bearer token with `alerts:write` scope.\n\n\
                   **Ownership:** You can only delete alerts that you own. Ownership is verified by:\n\
                   - Matching OAuth2 user ID, or\n\
                   - Matching email address (for legacy alerts not yet linked to OAuth2)",
    security(("OAuth2" = ["alerts:write"])),
    params(("id" = i32, Path, description = "Alert ID to delete")),
    responses(
        (status = 204, description = "Alert deleted successfully"),
        (status = 401, description = "Missing or invalid token", body = AuthError),
        (status = 403, description = "Missing required scope or not owner", body = AuthError),
        (status = 404, description = "Alert not found", body = AuthError),
    )
)]
async fn delete_alert_v2(
    Extension(resources): Extension<AppResources>,
    OAuth2Auth(auth): OAuth2Auth,
    Path(id): Path<i32>,
) -> Result<StatusCode, AuthError> {
    if !auth.has_scope(SCOPE_ALERTS_WRITE) {
        return Err(AuthError::insufficient_scope(SCOPE_ALERTS_WRITE));
    }

    let alert_entity = alert::Entity::find_by_id(id)
        .one(resources.db.as_ref())
        .await
        .map_err(|e| {
            tracing::error!("Database error finding alert: {}", e);
            AuthError::server_error()
        })?
        .ok_or_else(|| AuthError::not_found("Alert not found"))?;

    let is_owner = alert_entity
        .user_id
        .as_ref()
        .map(|uid| uid == &auth.user_id)
        .unwrap_or(false)
        || alert_entity.email == auth.email;

    if !is_owner {
        tracing::warn!(
            alert_id = id,
            alert_email = %alert_entity.email,
            alert_user_id = ?alert_entity.user_id,
            auth_email = %auth.email,
            auth_user_id = %auth.user_id,
            "Unauthorized delete attempt"
        );
        return Err(AuthError::forbidden("You do not own this alert"));
    }

    alert::Entity::delete_by_id(id)
        .exec(resources.db.as_ref())
        .await
        .map_err(|e| {
            tracing::error!("Failed to delete alert: {}", e);
            AuthError::server_error()
        })?;

    tracing::info!(alert_id = id, "Deleted alert via OAuth2");

    Ok(StatusCode::NO_CONTENT)
}

/// Replace the notification email list for an alert.
#[tracing::instrument(skip(resources, auth, payload), fields(user_email = %auth.email, alert_id = %id))]
#[utoipa::path(
    put,
    path = "/{id}/notify-emails",
    tag = ALERTS_V2_TAG,
    operation_id = "Update Alert Notification Emails",
    summary = "Replace the notification email list for an alert",
    description = "Replaces all notification emails for the given alert. Every email in the list \
                   must be one of the user's verified addresses (primary or additional).\n\n\
                   **Authentication:** Requires OAuth2 Bearer token with `alerts:write` scope.",
    security(("OAuth2" = ["alerts:write"])),
    params(("id" = i32, Path, description = "Alert ID")),
    request_body(content = UpdateNotifyEmailsRequest, description = "New notification email list"),
    responses(
        (status = 200, description = "Notification emails updated", body = AlertDto),
        (status = 400, description = "Email not in user's verified set", body = AuthError),
        (status = 401, description = "Missing or invalid token", body = AuthError),
        (status = 403, description = "Missing required scope or not owner", body = AuthError),
        (status = 404, description = "Alert not found", body = AuthError),
    )
)]
async fn update_notify_emails(
    Extension(resources): Extension<AppResources>,
    OAuth2Auth(auth): OAuth2Auth,
    Path(id): Path<i32>,
    Json(payload): Json<UpdateNotifyEmailsRequest>,
) -> Result<Json<AlertDto>, AuthError> {
    if !auth.has_scope(SCOPE_ALERTS_WRITE) {
        return Err(AuthError::insufficient_scope(SCOPE_ALERTS_WRITE));
    }

    let alert_entity = alert::Entity::find_by_id(id)
        .one(resources.db.as_ref())
        .await
        .map_err(|e| {
            tracing::error!("DB error finding alert {}: {}", id, e);
            AuthError::server_error()
        })?
        .ok_or_else(|| AuthError::not_found("Alert not found"))?;

    // Allow ownership by user_id (OAuth2 alerts) OR by email for legacy alerts
    // (user_id IS NULL, same logic as the delete endpoint).
    let is_owner = alert_entity
        .user_id
        .as_ref()
        .map(|uid| uid == &auth.user_id)
        .unwrap_or(false)
        || (alert_entity.user_id.is_none() && alert_entity.email == auth.email);
    if !is_owner {
        return Err(AuthError::forbidden("You do not own this alert"));
    }

    // Validate: every requested email must be in the user's verified set.
    let verified = verified_email_set(resources.db.as_ref(), &auth.user_id).await?;
    for email in &payload.emails {
        if !verified.contains(email) {
            return Err(AuthError::bad_request(format!(
                "email_not_verified: {} is not a verified address on your account",
                email
            )));
        }
    }

    // Atomically replace the notification email list.
    let db = resources.db.as_ref();
    let txn = db.begin().await.map_err(|_| AuthError::server_error())?;

    alert_notification_email::Entity::delete_many()
        .filter(alert_notification_email::Column::AlertId.eq(id))
        .exec(&txn)
        .await
        .map_err(|e| {
            tracing::error!("Failed to delete old notification emails: {}", e);
            AuthError::server_error()
        })?;

    if !payload.emails.is_empty() {
        let now = OffsetDateTime::now_utc();
        let models: Vec<alert_notification_email::ActiveModel> = payload
            .emails
            .iter()
            .map(|email| alert_notification_email::ActiveModel {
                alert_id: Set(id),
                email: Set(email.clone()),
                created_at: Set(now),
                ..Default::default()
            })
            .collect();
        alert_notification_email::Entity::insert_many(models)
            .exec(&txn)
            .await
            .map_err(|e| {
                tracing::error!("Failed to insert new notification emails: {}", e);
                AuthError::server_error()
            })?;
    }

    txn.commit().await.map_err(|_| AuthError::server_error())?;

    tracing::info!(
        alert_id = id,
        email_count = payload.emails.len(),
        "Updated notification emails"
    );

    let dto = AlertDto {
        id: alert_entity.id,
        server_name: alert_entity.server_name,
        verified: alert_entity.verified,
        created_at: alert_entity.created_at,
        last_check_at: alert_entity.last_check_at,
        is_currently_failing: alert_entity.is_currently_failing,
        notify_emails: payload.emails,
    };

    Ok(Json(dto))
}
