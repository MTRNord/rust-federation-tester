//! v2 Alert management API endpoints (OAuth2-authenticated).
//!
//! Provides OAuth2-authenticated endpoints for managing federation alerts:
//! - `GET /` - List all alerts for the authenticated user
//! - `POST /` - Create a new alert subscription
//! - `DELETE /{id}` - Delete an alert
//!
//! These endpoints use Bearer token authentication via the OAuth2Auth extractor.

use crate::AppResources;
use crate::api::auth::{AuthError, OAuth2Auth, SCOPE_ALERTS_READ, SCOPE_ALERTS_WRITE};
use crate::entity::alert;
use crate::oauth2::IdentityService;
use axum::{Extension, Json, extract::Path};
use hyper::StatusCode;
use sea_orm::{ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter};
use serde::{Deserialize, Serialize};
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
}

impl From<alert::Model> for AlertDto {
    fn from(alert: alert::Model) -> Self {
        Self {
            id: alert.id,
            server_name: alert.server_name,
            verified: alert.verified,
            created_at: alert.created_at,
            last_check_at: alert.last_check_at,
            is_currently_failing: alert.is_currently_failing,
        }
    }
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

/// Creates the v2 alerts API router.
#[tracing::instrument(skip_all)]
pub fn router() -> OpenApiRouter {
    OpenApiRouter::new()
        .routes(routes!(list_alerts_v2, create_alert_v2))
        .routes(routes!(delete_alert_v2))
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
    // Validate scope
    if !auth.has_scope(SCOPE_ALERTS_READ) {
        return Err(AuthError::insufficient_scope(SCOPE_ALERTS_READ));
    }

    // Use IdentityService for backward-compatible lookup
    let identity_service = IdentityService::new(resources.db.clone());

    let alerts = identity_service
        .get_user_alerts(&auth.user_id, &auth.email)
        .await
        .map_err(|e| {
            tracing::error!("Database error listing alerts: {}", e);
            AuthError::server_error()
        })?;

    let total = alerts.len();
    let alert_dtos: Vec<AlertDto> = alerts.into_iter().map(AlertDto::from).collect();

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
    // Validate scope
    if !auth.has_scope(SCOPE_ALERTS_WRITE) {
        return Err(AuthError::insufficient_scope(SCOPE_ALERTS_WRITE));
    }

    // Validate server name is not empty
    let server_name = payload.server_name.trim().to_lowercase();
    if server_name.is_empty() {
        return Err(AuthError::bad_request("Server name cannot be empty"));
    }

    let now = OffsetDateTime::now_utc();

    // Check for existing alert
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

    // Check if user's email is verified
    let is_verified = auth.email_verified;

    // Create alert
    let new_alert = alert::ActiveModel {
        email: Set(auth.email.clone()),
        server_name: Set(server_name.clone()),
        verified: Set(is_verified),
        magic_token: Set(String::new()), // No magic token needed for OAuth2
        created_at: Set(now),
        user_id: Set(Some(auth.user_id.clone())),
        ..Default::default()
    };

    let inserted = new_alert.insert(resources.db.as_ref()).await.map_err(|e| {
        tracing::error!("Failed to create alert: {}", e);
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
    // Validate scope
    if !auth.has_scope(SCOPE_ALERTS_WRITE) {
        return Err(AuthError::insufficient_scope(SCOPE_ALERTS_WRITE));
    }

    // Find the alert
    let alert_entity = alert::Entity::find_by_id(id)
        .one(resources.db.as_ref())
        .await
        .map_err(|e| {
            tracing::error!("Database error finding alert: {}", e);
            AuthError::server_error()
        })?
        .ok_or_else(|| AuthError::not_found("Alert not found"))?;

    // Verify ownership: alert must belong to user by user_id OR email
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

    // Delete the alert
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
