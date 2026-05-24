//! v2 Alert management API endpoints (OAuth2-authenticated).
//!
//! Provides OAuth2-authenticated endpoints for managing federation alerts:
//! - `GET /` - List all alerts for the authenticated user
//! - `POST /` - Create a new alert subscription
//! - `GET /{id}` - Get a single alert
//! - `DELETE /{id}` - Delete an alert
//! - `GET /{id}/events` - Get recent events for an alert
//! - `PUT /{id}/notify-emails` - Replace the notification email list for an alert
//! - `PUT /{id}/settings` - Update alert settings including quiet hours

use crate::AppResources;
use crate::alerts::webhook::enqueue_ping;
use crate::api::auth::{AuthError, OAuth2Auth, SCOPE_ALERTS_READ, SCOPE_ALERTS_WRITE};
use crate::entity::{
    alert, alert_notification_email, alert_notification_webhook, alert_status_history, oauth2_user,
    user_email, webhook_outbox,
};
use crate::oauth2::IdentityService;
use axum::{Extension, Json, extract::Path};
use hyper::StatusCode;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter,
    QueryOrder, QuerySelect, TransactionTrait,
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
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Last time the server was checked
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub last_check_at: Option<OffsetDateTime>,
    /// Whether the server is currently failing federation checks
    pub is_currently_failing: bool,
    /// Email addresses that receive notifications for this alert
    pub notify_emails: Vec<String>,
    /// Webhook endpoints configured for this alert (secret is never included)
    pub notify_webhooks: Vec<WebhookDto>,
    /// Notify when the server's self-reported name or well-known delegation target changes
    pub notify_server_name_change: bool,
    /// Notify when the server's software version changes
    pub notify_version_change: bool,
    /// Notify when the set of TLS certificate fingerprints changes
    pub notify_tls_cert_change: bool,
    /// Notify when a TLS certificate is expiring within 14 days
    pub notify_tls_expiry: bool,
    /// Whether quiet hours are enabled
    pub quiet_hours_enabled: bool,
    /// Quiet window start in HH:MM format
    pub quiet_hours_from: String,
    /// Quiet window end in HH:MM format
    pub quiet_hours_to: String,
}

/// A single recent event for an alert.
#[derive(Debug, Serialize, ToSchema)]
pub struct AlertEventDto {
    /// When the event occurred
    #[serde(with = "time::serde::rfc3339")]
    pub when: OffsetDateTime,
    /// Short human-readable label for the event (suitable for a table cell)
    pub description: String,
    /// Full detail text, e.g. the raw failure reason (may be long)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Visual severity: "bad", "ok", or "info"
    pub kind: String,
}

/// Response containing recent events for an alert.
#[derive(Debug, Serialize, ToSchema)]
pub struct AlertEventsResponse {
    pub events: Vec<AlertEventDto>,
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

/// A configured webhook endpoint (secret field is always omitted).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct WebhookDto {
    pub id: i32,
    pub url: String,
    pub hmac_header: String,
    pub respect_quiet_hours: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// Request to add a new webhook endpoint.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateWebhookRequest {
    pub url: String,
    #[serde(default)]
    pub hmac_secret: Option<String>,
    #[serde(default)]
    pub hmac_header: Option<String>,
    #[serde(default)]
    pub respect_quiet_hours: Option<bool>,
}

/// Request to update an existing webhook endpoint (all fields optional).
#[derive(Debug, Deserialize, ToSchema)]
pub struct PatchWebhookRequest {
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub hmac_secret: Option<String>,
    #[serde(default)]
    pub hmac_header: Option<String>,
    #[serde(default)]
    pub respect_quiet_hours: Option<bool>,
}

/// A single delivery attempt from the webhook outbox.
#[derive(Debug, Serialize, ToSchema)]
pub struct DeliveryDto {
    pub id: String,
    pub event_type: String,
    pub status: String,
    pub attempts: i32,
    pub last_status_code: Option<i16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub delivered_at: Option<OffsetDateTime>,
}

/// Response for the delivery history endpoint.
#[derive(Debug, Serialize, ToSchema)]
pub struct DeliveryHistoryResponse {
    pub deliveries: Vec<DeliveryDto>,
}

/// Request to replace the notification email list for an alert.
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateNotifyEmailsRequest {
    /// Email addresses to receive notifications (must all be verified by the user)
    pub emails: Vec<String>,
}

/// Request to update change-notification settings for an alert.
/// All fields are optional — only provided fields are updated.
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateAlertSettingsRequest {
    pub notify_server_name_change: Option<bool>,
    pub notify_version_change: Option<bool>,
    pub notify_tls_cert_change: Option<bool>,
    pub notify_tls_expiry: Option<bool>,
    pub quiet_hours_enabled: Option<bool>,
    pub quiet_hours_from: Option<String>,
    pub quiet_hours_to: Option<String>,
}

/// Creates the v2 alerts API router.
#[tracing::instrument(skip_all)]
pub fn router() -> OpenApiRouter {
    OpenApiRouter::new()
        .routes(routes!(list_alerts_v2, create_alert_v2))
        .routes(routes!(get_alert_v2, delete_alert_v2))
        .routes(routes!(get_alert_events))
        .routes(routes!(update_notify_emails))
        .routes(routes!(update_alert_settings))
        .routes(routes!(list_webhooks, add_webhook))
        .routes(routes!(patch_webhook, delete_webhook))
        .routes(routes!(test_webhook))
        .routes(routes!(get_delivery_history))
        .routes(routes!(test_email))
}

/// Build `AlertDto` values from alert models and pre-loaded email/webhook maps.
fn build_alert_dtos(
    alerts: Vec<alert::Model>,
    emails_by_alert: &HashMap<i32, Vec<String>>,
    webhooks_by_alert: &HashMap<i32, Vec<WebhookDto>>,
) -> Vec<AlertDto> {
    alerts
        .into_iter()
        .map(|a| {
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
            let notify_webhooks = webhooks_by_alert.get(&a.id).cloned().unwrap_or_default();
            AlertDto {
                id: a.id,
                server_name: a.server_name,
                verified: a.verified,
                created_at: a.created_at,
                last_check_at: a.last_check_at,
                is_currently_failing: a.is_currently_failing,
                notify_emails,
                notify_webhooks,
                notify_server_name_change: a.notify_server_name_change,
                notify_version_change: a.notify_version_change,
                notify_tls_cert_change: a.notify_tls_cert_change,
                notify_tls_expiry: a.notify_tls_expiry,
                quiet_hours_enabled: a.quiet_hours_enabled,
                quiet_hours_from: a.quiet_hours_from,
                quiet_hours_to: a.quiet_hours_to,
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

/// Batch-load webhook endpoints for a slice of alert IDs.
async fn load_webhooks_by_alert(
    db: &sea_orm::DatabaseConnection,
    alert_ids: &[i32],
) -> Result<HashMap<i32, Vec<WebhookDto>>, AuthError> {
    if alert_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let rows = alert_notification_webhook::Entity::find()
        .filter(alert_notification_webhook::Column::AlertId.is_in(alert_ids.to_vec()))
        .all(db)
        .await
        .map_err(|e| {
            tracing::error!("DB error loading webhooks: {}", e);
            AuthError::server_error()
        })?;

    let mut map: HashMap<i32, Vec<WebhookDto>> = HashMap::new();
    for row in rows {
        map.entry(row.alert_id).or_default().push(WebhookDto {
            id: row.id,
            url: row.url,
            hmac_header: row.hmac_header,
            respect_quiet_hours: row.respect_quiet_hours,
            created_at: row.created_at,
        });
    }
    Ok(map)
}

/// Validate that a webhook URL is safe to deliver to.
///
/// Rules:
/// - Must use HTTPS scheme
/// - Literal IP addresses must not be private/loopback
/// - Hostnames are resolved via DNS; all returned addresses must be public
///   (prevents SSRF via domains that point to internal IPs or via DNS rebinding)
async fn validate_webhook_url(raw: &str) -> Result<(), AuthError> {
    let parsed = url::Url::parse(raw)
        .map_err(|_| AuthError::bad_request("webhook_url_invalid: must be a valid URL"))?;

    if parsed.scheme() != "https" {
        return Err(AuthError::bad_request(
            "webhook_url_https_required: URL must use HTTPS",
        ));
    }

    match parsed.host() {
        Some(url::Host::Ipv4(ip)) => {
            if is_private_ip(std::net::IpAddr::V4(ip)) {
                return Err(AuthError::bad_request(
                    "webhook_url_private_ip: URL must not point to a private/internal IP address",
                ));
            }
        }
        Some(url::Host::Ipv6(ip)) => {
            if is_private_ip(std::net::IpAddr::V6(ip)) {
                return Err(AuthError::bad_request(
                    "webhook_url_private_ip: URL must not point to a private/internal IP address",
                ));
            }
        }
        Some(url::Host::Domain(name)) => {
            let lookup = tokio::net::lookup_host(format!("{}:443", name))
                .await
                .map_err(|_| {
                    AuthError::bad_request(
                        "webhook_url_unresolvable: hostname could not be resolved",
                    )
                })?;
            for addr in lookup {
                if is_private_ip(addr.ip()) {
                    return Err(AuthError::bad_request(
                        "webhook_url_private_ip: URL must not point to a private/internal IP address",
                    ));
                }
            }
        }
        None => {
            return Err(AuthError::bad_request(
                "webhook_url_invalid: URL has no host",
            ));
        }
    }

    Ok(())
}

fn is_private_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
        }
        std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
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
    let webhooks_by_alert = load_webhooks_by_alert(resources.db.as_ref(), &alert_ids).await?;

    let total = alerts.len();
    let alert_dtos = build_alert_dtos(alerts, &emails_by_alert, &webhooks_by_alert);

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
        // Enable sensible defaults for new registrations; existing alerts
        // keep the DB default of false (no unexpected emails).
        notify_server_name_change: Set(true),
        notify_version_change: Set(true),
        notify_tls_cert_change: Set(false),
        notify_tls_expiry: Set(true),
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

    let webhooks_by_alert = load_webhooks_by_alert(resources.db.as_ref(), &[id]).await?;
    let dto = AlertDto {
        id: alert_entity.id,
        server_name: alert_entity.server_name,
        verified: alert_entity.verified,
        created_at: alert_entity.created_at,
        last_check_at: alert_entity.last_check_at,
        is_currently_failing: alert_entity.is_currently_failing,
        notify_emails: payload.emails,
        notify_webhooks: webhooks_by_alert.get(&id).cloned().unwrap_or_default(),
        notify_server_name_change: alert_entity.notify_server_name_change,
        notify_version_change: alert_entity.notify_version_change,
        notify_tls_cert_change: alert_entity.notify_tls_cert_change,
        notify_tls_expiry: alert_entity.notify_tls_expiry,
        quiet_hours_enabled: alert_entity.quiet_hours_enabled,
        quiet_hours_from: alert_entity.quiet_hours_from,
        quiet_hours_to: alert_entity.quiet_hours_to,
    };

    Ok(Json(dto))
}

/// Update change-notification settings for an alert.
#[tracing::instrument(skip(resources, auth, payload), fields(user_email = %auth.email, alert_id = %id))]
#[utoipa::path(
    put,
    path = "/{id}/settings",
    tag = ALERTS_V2_TAG,
    operation_id = "Update Alert Settings",
    summary = "Update change-notification settings for an alert",
    description = "Partially updates the change-notification flags for the given alert. \
                   Only the fields that are present in the request body are modified.\n\n\
                   **Authentication:** Requires OAuth2 Bearer token with `alerts:write` scope.",
    security(("OAuth2" = ["alerts:write"])),
    params(("id" = i32, Path, description = "Alert ID")),
    request_body(content = UpdateAlertSettingsRequest, description = "Settings to update"),
    responses(
        (status = 200, description = "Settings updated", body = AlertDto),
        (status = 401, description = "Missing or invalid token", body = AuthError),
        (status = 403, description = "Missing required scope or not owner", body = AuthError),
        (status = 404, description = "Alert not found", body = AuthError),
    )
)]
async fn update_alert_settings(
    Extension(resources): Extension<AppResources>,
    OAuth2Auth(auth): OAuth2Auth,
    Path(id): Path<i32>,
    Json(payload): Json<UpdateAlertSettingsRequest>,
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

    let is_owner = alert_entity
        .user_id
        .as_ref()
        .map(|uid| uid == &auth.user_id)
        .unwrap_or(false)
        || (alert_entity.user_id.is_none() && alert_entity.email == auth.email);
    if !is_owner {
        return Err(AuthError::forbidden("You do not own this alert"));
    }

    let mut active: alert::ActiveModel = alert_entity.clone().into();
    if let Some(v) = payload.notify_server_name_change {
        active.notify_server_name_change = Set(v);
    }
    if let Some(v) = payload.notify_version_change {
        active.notify_version_change = Set(v);
    }
    if let Some(v) = payload.notify_tls_cert_change {
        active.notify_tls_cert_change = Set(v);
    }
    if let Some(v) = payload.notify_tls_expiry {
        active.notify_tls_expiry = Set(v);
    }
    if let Some(v) = payload.quiet_hours_enabled {
        active.quiet_hours_enabled = Set(v);
    }
    if let Some(v) = payload.quiet_hours_from {
        active.quiet_hours_from = Set(v);
    }
    if let Some(v) = payload.quiet_hours_to {
        active.quiet_hours_to = Set(v);
    }

    let updated = active.update(resources.db.as_ref()).await.map_err(|e| {
        tracing::error!("Failed to update alert settings for {}: {}", id, e);
        AuthError::server_error()
    })?;

    tracing::info!(alert_id = id, "Updated alert notification settings");

    let emails_by_alert = load_emails_by_alert(resources.db.as_ref(), &[id]).await?;
    let notify_emails = match emails_by_alert.get(&id) {
        Some(emails) if !emails.is_empty() => emails.clone(),
        _ => {
            if updated.email.is_empty() {
                vec![]
            } else {
                vec![updated.email.clone()]
            }
        }
    };

    let webhooks_by_alert = load_webhooks_by_alert(resources.db.as_ref(), &[id]).await?;
    Ok(Json(AlertDto {
        id: updated.id,
        server_name: updated.server_name,
        verified: updated.verified,
        created_at: updated.created_at,
        last_check_at: updated.last_check_at,
        is_currently_failing: updated.is_currently_failing,
        notify_emails,
        notify_webhooks: webhooks_by_alert.get(&id).cloned().unwrap_or_default(),
        notify_server_name_change: updated.notify_server_name_change,
        notify_version_change: updated.notify_version_change,
        notify_tls_cert_change: updated.notify_tls_cert_change,
        notify_tls_expiry: updated.notify_tls_expiry,
        quiet_hours_enabled: updated.quiet_hours_enabled,
        quiet_hours_from: updated.quiet_hours_from,
        quiet_hours_to: updated.quiet_hours_to,
    }))
}

/// Get a single alert by ID.
#[tracing::instrument(skip(resources, auth), fields(user_email = %auth.email, alert_id = %id))]
#[utoipa::path(
    get,
    path = "/{id}",
    tag = ALERTS_V2_TAG,
    operation_id = "Get Alert",
    summary = "Get a single alert by ID",
    security(("OAuth2" = ["alerts:read"])),
    params(("id" = i32, Path, description = "Alert ID")),
    responses(
        (status = 200, description = "Alert", body = AlertDto),
        (status = 401, description = "Missing or invalid token", body = AuthError),
        (status = 403, description = "Missing required scope or not owner", body = AuthError),
        (status = 404, description = "Alert not found", body = AuthError),
    )
)]
async fn get_alert_v2(
    Extension(resources): Extension<AppResources>,
    OAuth2Auth(auth): OAuth2Auth,
    Path(id): Path<i32>,
) -> Result<Json<AlertDto>, AuthError> {
    if !auth.has_scope(SCOPE_ALERTS_READ) {
        return Err(AuthError::insufficient_scope(SCOPE_ALERTS_READ));
    }

    let alert_entity = alert::Entity::find_by_id(id)
        .one(resources.db.as_ref())
        .await
        .map_err(|e| {
            tracing::error!("DB error finding alert {}: {}", id, e);
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
        return Err(AuthError::forbidden("You do not own this alert"));
    }

    let emails_by_alert = load_emails_by_alert(resources.db.as_ref(), &[id]).await?;
    let webhooks_by_alert = load_webhooks_by_alert(resources.db.as_ref(), &[id]).await?;
    let notify_emails = match emails_by_alert.get(&id) {
        Some(emails) if !emails.is_empty() => emails.clone(),
        _ => {
            if alert_entity.email.is_empty() {
                vec![]
            } else {
                vec![alert_entity.email.clone()]
            }
        }
    };

    Ok(Json(AlertDto {
        id: alert_entity.id,
        server_name: alert_entity.server_name,
        verified: alert_entity.verified,
        created_at: alert_entity.created_at,
        last_check_at: alert_entity.last_check_at,
        is_currently_failing: alert_entity.is_currently_failing,
        notify_emails,
        notify_webhooks: webhooks_by_alert.get(&id).cloned().unwrap_or_default(),
        notify_server_name_change: alert_entity.notify_server_name_change,
        notify_version_change: alert_entity.notify_version_change,
        notify_tls_cert_change: alert_entity.notify_tls_cert_change,
        notify_tls_expiry: alert_entity.notify_tls_expiry,
        quiet_hours_enabled: alert_entity.quiet_hours_enabled,
        quiet_hours_from: alert_entity.quiet_hours_from,
        quiet_hours_to: alert_entity.quiet_hours_to,
    }))
}

/// Get recent events for an alert.
#[tracing::instrument(skip(resources, auth), fields(user_email = %auth.email, alert_id = %id))]
#[utoipa::path(
    get,
    path = "/{id}/events",
    tag = ALERTS_V2_TAG,
    operation_id = "Get Alert Events",
    summary = "Get recent events for an alert (last 50)",
    security(("OAuth2" = ["alerts:read"])),
    params(("id" = i32, Path, description = "Alert ID")),
    responses(
        (status = 200, description = "Recent events", body = AlertEventsResponse),
        (status = 401, description = "Missing or invalid token", body = AuthError),
        (status = 403, description = "Missing required scope or not owner", body = AuthError),
        (status = 404, description = "Alert not found", body = AuthError),
    )
)]
async fn get_alert_events(
    Extension(resources): Extension<AppResources>,
    OAuth2Auth(auth): OAuth2Auth,
    Path(id): Path<i32>,
) -> Result<Json<AlertEventsResponse>, AuthError> {
    if !auth.has_scope(SCOPE_ALERTS_READ) {
        return Err(AuthError::insufficient_scope(SCOPE_ALERTS_READ));
    }

    // Verify ownership first.
    let alert_entity = alert::Entity::find_by_id(id)
        .one(resources.db.as_ref())
        .await
        .map_err(|e| {
            tracing::error!("DB error finding alert {}: {}", id, e);
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
        return Err(AuthError::forbidden("You do not own this alert"));
    }

    let rows = alert_status_history::Entity::find()
        .filter(alert_status_history::Column::AlertId.eq(id))
        .order_by_desc(alert_status_history::Column::CreatedAt)
        .limit(50)
        .all(resources.db.as_ref())
        .await
        .map_err(|e| {
            tracing::error!("DB error loading events for alert {}: {}", id, e);
            AuthError::server_error()
        })?;

    let events = rows
        .into_iter()
        .map(|row| {
            let (description, detail, kind) = event_to_display(&row);
            AlertEventDto {
                when: row.created_at,
                description,
                detail,
                kind,
            }
        })
        .collect();

    Ok(Json(AlertEventsResponse { events }))
}

fn event_to_display(row: &alert_status_history::Model) -> (String, Option<String>, String) {
    match row.event_type.as_str() {
        "check_fail" => {
            let reason = row.failure_reason.as_deref().unwrap_or("unknown reason");
            (
                "Check failed".to_string(),
                Some(reason.to_string()),
                "bad".to_string(),
            )
        }
        "check_ok" => ("Check passed".to_string(), None, "ok".to_string()),
        "email_failure" => (
            "Failure notification sent".to_string(),
            None,
            "bad".to_string(),
        ),
        "email_recovery" => (
            "Recovery notification sent".to_string(),
            None,
            "ok".to_string(),
        ),
        "email_reminder" => (
            "Downtime reminder sent".to_string(),
            None,
            "info".to_string(),
        ),
        other => {
            let desc = row.details.as_deref().unwrap_or(other);
            (desc.to_string(), None, "info".to_string())
        }
    }
}

// ---------------------------------------------------------------------------
// Ownership helper (shared by webhook handlers)
// ---------------------------------------------------------------------------

async fn require_alert_owner(
    resources: &AppResources,
    alert_id: i32,
    auth: &crate::api::auth::AuthenticatedUser,
    scope: &str,
) -> Result<alert::Model, AuthError> {
    if !auth.has_scope(scope) {
        return Err(AuthError::insufficient_scope(scope));
    }
    let alert_entity = alert::Entity::find_by_id(alert_id)
        .one(resources.db.as_ref())
        .await
        .map_err(|e| {
            tracing::error!("DB error finding alert {}: {}", alert_id, e);
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
        return Err(AuthError::forbidden("You do not own this alert"));
    }
    Ok(alert_entity)
}

// ---------------------------------------------------------------------------
// Webhook management handlers
// ---------------------------------------------------------------------------

/// List webhook endpoints for an alert.
#[tracing::instrument(skip(resources, auth), fields(user_email = %auth.email, alert_id = %id))]
#[utoipa::path(
    get,
    path = "/{id}/notify-webhooks",
    tag = ALERTS_V2_TAG,
    operation_id = "List Webhooks",
    summary = "List webhook endpoints for an alert",
    security(("OAuth2" = ["alerts:read"])),
    params(("id" = i32, Path, description = "Alert ID")),
    responses(
        (status = 200, description = "List of webhooks", body = DeliveryHistoryResponse),
        (status = 401, description = "Missing or invalid token", body = AuthError),
        (status = 403, description = "Not owner or missing scope", body = AuthError),
        (status = 404, description = "Alert not found", body = AuthError),
    )
)]
async fn list_webhooks(
    Extension(resources): Extension<AppResources>,
    OAuth2Auth(auth): OAuth2Auth,
    Path(id): Path<i32>,
) -> Result<Json<Vec<WebhookDto>>, AuthError> {
    require_alert_owner(&resources, id, &auth, SCOPE_ALERTS_READ).await?;

    let rows = alert_notification_webhook::Entity::find()
        .filter(alert_notification_webhook::Column::AlertId.eq(id))
        .all(resources.db.as_ref())
        .await
        .map_err(|e| {
            tracing::error!("DB error listing webhooks for alert {}: {}", id, e);
            AuthError::server_error()
        })?;

    let dtos = rows
        .into_iter()
        .map(|r| WebhookDto {
            id: r.id,
            url: r.url,
            hmac_header: r.hmac_header,
            respect_quiet_hours: r.respect_quiet_hours,
            created_at: r.created_at,
        })
        .collect();

    Ok(Json(dtos))
}

/// Add a webhook endpoint to an alert.
#[tracing::instrument(skip(resources, auth, payload), fields(user_email = %auth.email, alert_id = %id))]
#[utoipa::path(
    post,
    path = "/{id}/notify-webhooks",
    tag = ALERTS_V2_TAG,
    operation_id = "Add Webhook",
    summary = "Add a webhook endpoint to an alert",
    security(("OAuth2" = ["alerts:write"])),
    params(("id" = i32, Path, description = "Alert ID")),
    request_body(content = CreateWebhookRequest, description = "Webhook details"),
    responses(
        (status = 201, description = "Webhook created", body = WebhookDto),
        (status = 400, description = "Invalid URL or max webhooks reached", body = AuthError),
        (status = 401, description = "Missing or invalid token", body = AuthError),
        (status = 403, description = "Not owner or missing scope", body = AuthError),
        (status = 404, description = "Alert not found", body = AuthError),
    )
)]
async fn add_webhook(
    Extension(resources): Extension<AppResources>,
    OAuth2Auth(auth): OAuth2Auth,
    Path(id): Path<i32>,
    Json(payload): Json<CreateWebhookRequest>,
) -> Result<(StatusCode, Json<WebhookDto>), AuthError> {
    require_alert_owner(&resources, id, &auth, SCOPE_ALERTS_WRITE).await?;

    validate_webhook_url(&payload.url).await?;

    if let Some(max) = resources.config.max_webhooks_per_alert {
        let count = alert_notification_webhook::Entity::find()
            .filter(alert_notification_webhook::Column::AlertId.eq(id))
            .count(resources.db.as_ref())
            .await
            .map_err(|_| AuthError::server_error())?;
        if count as usize >= max {
            return Err(AuthError::bad_request(format!(
                "max_webhooks_reached: this alert already has {max} webhook(s) (the configured maximum)"
            )));
        }
    }

    let now = OffsetDateTime::now_utc();
    let row = alert_notification_webhook::ActiveModel {
        alert_id: Set(id),
        url: Set(payload.url),
        hmac_secret: Set(payload.hmac_secret),
        hmac_header: Set(payload
            .hmac_header
            .unwrap_or_else(|| "X-Signature-256".to_string())),
        respect_quiet_hours: Set(payload.respect_quiet_hours.unwrap_or(false)),
        created_at: Set(now),
        ..Default::default()
    };

    let inserted = row.insert(resources.db.as_ref()).await.map_err(|e| {
        tracing::error!("Failed to insert webhook for alert {}: {}", id, e);
        AuthError::server_error()
    })?;

    tracing::info!(alert_id = id, webhook_id = inserted.id, "Added webhook");

    Ok((
        StatusCode::CREATED,
        Json(WebhookDto {
            id: inserted.id,
            url: inserted.url,
            hmac_header: inserted.hmac_header,
            respect_quiet_hours: inserted.respect_quiet_hours,
            created_at: inserted.created_at,
        }),
    ))
}

/// Update a webhook endpoint.
#[tracing::instrument(skip(resources, auth, payload), fields(user_email = %auth.email, alert_id = %id, webhook_id = %wid))]
#[utoipa::path(
    patch,
    path = "/{id}/notify-webhooks/{wid}",
    tag = ALERTS_V2_TAG,
    operation_id = "Update Webhook",
    summary = "Update a webhook endpoint",
    security(("OAuth2" = ["alerts:write"])),
    params(
        ("id" = i32, Path, description = "Alert ID"),
        ("wid" = i32, Path, description = "Webhook ID"),
    ),
    request_body(content = PatchWebhookRequest, description = "Fields to update"),
    responses(
        (status = 200, description = "Webhook updated", body = WebhookDto),
        (status = 400, description = "Invalid URL", body = AuthError),
        (status = 401, description = "Missing or invalid token", body = AuthError),
        (status = 403, description = "Not owner or missing scope", body = AuthError),
        (status = 404, description = "Alert or webhook not found", body = AuthError),
    )
)]
async fn patch_webhook(
    Extension(resources): Extension<AppResources>,
    OAuth2Auth(auth): OAuth2Auth,
    Path((id, wid)): Path<(i32, i32)>,
    Json(payload): Json<PatchWebhookRequest>,
) -> Result<Json<WebhookDto>, AuthError> {
    require_alert_owner(&resources, id, &auth, SCOPE_ALERTS_WRITE).await?;

    if let Some(ref url) = payload.url {
        validate_webhook_url(url).await?;
    }

    let webhook = alert_notification_webhook::Entity::find_by_id(wid)
        .one(resources.db.as_ref())
        .await
        .map_err(|_| AuthError::server_error())?
        .ok_or_else(|| AuthError::not_found("Webhook not found"))?;

    if webhook.alert_id != id {
        return Err(AuthError::not_found("Webhook not found"));
    }

    let mut active: alert_notification_webhook::ActiveModel = webhook.into();
    if let Some(url) = payload.url {
        active.url = Set(url);
    }
    if let Some(secret) = payload.hmac_secret {
        active.hmac_secret = Set(if secret.is_empty() {
            None
        } else {
            Some(secret)
        });
    }
    if let Some(header) = payload.hmac_header {
        active.hmac_header = Set(header);
    }
    if let Some(qh) = payload.respect_quiet_hours {
        active.respect_quiet_hours = Set(qh);
    }

    let updated = active.update(resources.db.as_ref()).await.map_err(|e| {
        tracing::error!("Failed to update webhook {}: {}", wid, e);
        AuthError::server_error()
    })?;

    Ok(Json(WebhookDto {
        id: updated.id,
        url: updated.url,
        hmac_header: updated.hmac_header,
        respect_quiet_hours: updated.respect_quiet_hours,
        created_at: updated.created_at,
    }))
}

/// Delete a webhook endpoint.
#[tracing::instrument(skip(resources, auth), fields(user_email = %auth.email, alert_id = %id, webhook_id = %wid))]
#[utoipa::path(
    delete,
    path = "/{id}/notify-webhooks/{wid}",
    tag = ALERTS_V2_TAG,
    operation_id = "Delete Webhook",
    summary = "Delete a webhook endpoint",
    security(("OAuth2" = ["alerts:write"])),
    params(
        ("id" = i32, Path, description = "Alert ID"),
        ("wid" = i32, Path, description = "Webhook ID"),
    ),
    responses(
        (status = 204, description = "Webhook deleted"),
        (status = 401, description = "Missing or invalid token", body = AuthError),
        (status = 403, description = "Not owner or missing scope", body = AuthError),
        (status = 404, description = "Alert or webhook not found", body = AuthError),
    )
)]
async fn delete_webhook(
    Extension(resources): Extension<AppResources>,
    OAuth2Auth(auth): OAuth2Auth,
    Path((id, wid)): Path<(i32, i32)>,
) -> Result<StatusCode, AuthError> {
    require_alert_owner(&resources, id, &auth, SCOPE_ALERTS_WRITE).await?;

    let webhook = alert_notification_webhook::Entity::find_by_id(wid)
        .one(resources.db.as_ref())
        .await
        .map_err(|_| AuthError::server_error())?
        .ok_or_else(|| AuthError::not_found("Webhook not found"))?;

    if webhook.alert_id != id {
        return Err(AuthError::not_found("Webhook not found"));
    }

    alert_notification_webhook::Entity::delete_by_id(wid)
        .exec(resources.db.as_ref())
        .await
        .map_err(|e| {
            tracing::error!("Failed to delete webhook {}: {}", wid, e);
            AuthError::server_error()
        })?;

    tracing::info!(alert_id = id, webhook_id = wid, "Deleted webhook");
    Ok(StatusCode::NO_CONTENT)
}

/// Enqueue a test delivery for a webhook.
#[tracing::instrument(skip(resources, auth), fields(user_email = %auth.email, alert_id = %id, webhook_id = %wid))]
#[utoipa::path(
    post,
    path = "/{id}/notify-webhooks/{wid}/test",
    tag = ALERTS_V2_TAG,
    operation_id = "Test Webhook",
    summary = "Enqueue a ping delivery for a webhook",
    security(("OAuth2" = ["alerts:write"])),
    params(
        ("id" = i32, Path, description = "Alert ID"),
        ("wid" = i32, Path, description = "Webhook ID"),
    ),
    responses(
        (status = 202, description = "Test delivery queued"),
        (status = 401, description = "Missing or invalid token", body = AuthError),
        (status = 403, description = "Not owner or missing scope", body = AuthError),
        (status = 404, description = "Alert or webhook not found", body = AuthError),
    )
)]
async fn test_webhook(
    Extension(resources): Extension<AppResources>,
    OAuth2Auth(auth): OAuth2Auth,
    Path((id, wid)): Path<(i32, i32)>,
) -> Result<StatusCode, AuthError> {
    let alert_entity = require_alert_owner(&resources, id, &auth, SCOPE_ALERTS_WRITE).await?;

    let webhook = alert_notification_webhook::Entity::find_by_id(wid)
        .one(resources.db.as_ref())
        .await
        .map_err(|_| AuthError::server_error())?
        .ok_or_else(|| AuthError::not_found("Webhook not found"))?;

    if webhook.alert_id != id {
        return Err(AuthError::not_found("Webhook not found"));
    }

    enqueue_ping(resources.db.as_ref(), id, wid, &alert_entity.server_name)
        .await
        .map_err(|e| {
            tracing::error!("Failed to enqueue test delivery for webhook {}: {}", wid, e);
            AuthError::server_error()
        })?;

    tracing::info!(
        alert_id = id,
        webhook_id = wid,
        "Queued test webhook delivery"
    );
    Ok(StatusCode::ACCEPTED)
}

/// Get delivery history for a webhook (last 20 entries, newest first).
#[tracing::instrument(skip(resources, auth), fields(user_email = %auth.email, alert_id = %id, webhook_id = %wid))]
#[utoipa::path(
    get,
    path = "/{id}/notify-webhooks/{wid}/deliveries",
    tag = ALERTS_V2_TAG,
    operation_id = "Get Webhook Deliveries",
    summary = "Get recent delivery history for a webhook",
    security(("OAuth2" = ["alerts:read"])),
    params(
        ("id" = i32, Path, description = "Alert ID"),
        ("wid" = i32, Path, description = "Webhook ID"),
    ),
    responses(
        (status = 200, description = "Delivery history", body = DeliveryHistoryResponse),
        (status = 401, description = "Missing or invalid token", body = AuthError),
        (status = 403, description = "Not owner or missing scope", body = AuthError),
        (status = 404, description = "Alert or webhook not found", body = AuthError),
    )
)]
async fn get_delivery_history(
    Extension(resources): Extension<AppResources>,
    OAuth2Auth(auth): OAuth2Auth,
    Path((id, wid)): Path<(i32, i32)>,
) -> Result<Json<DeliveryHistoryResponse>, AuthError> {
    require_alert_owner(&resources, id, &auth, SCOPE_ALERTS_READ).await?;

    let webhook = alert_notification_webhook::Entity::find_by_id(wid)
        .one(resources.db.as_ref())
        .await
        .map_err(|_| AuthError::server_error())?
        .ok_or_else(|| AuthError::not_found("Webhook not found"))?;

    if webhook.alert_id != id {
        return Err(AuthError::not_found("Webhook not found"));
    }

    let rows = webhook_outbox::Entity::find()
        .filter(webhook_outbox::Column::WebhookId.eq(wid))
        .order_by_desc(webhook_outbox::Column::CreatedAt)
        .limit(20)
        .all(resources.db.as_ref())
        .await
        .map_err(|e| {
            tracing::error!(
                "DB error loading delivery history for webhook {}: {}",
                wid,
                e
            );
            AuthError::server_error()
        })?;

    let deliveries = rows
        .into_iter()
        .map(|r| DeliveryDto {
            id: r.id,
            event_type: r.event_type,
            status: r.status,
            attempts: r.attempts,
            last_status_code: r.last_status_code,
            last_error: r.last_error,
            created_at: r.created_at,
            delivered_at: r.delivered_at,
        })
        .collect();

    Ok(Json(DeliveryHistoryResponse { deliveries }))
}

/// Enqueue a test email to all notify_emails on this alert.
#[tracing::instrument(skip(resources, auth), fields(user_email = %auth.email, alert_id = %id))]
#[utoipa::path(
    post,
    path = "/{id}/test-email",
    tag = ALERTS_V2_TAG,
    operation_id = "Test Email",
    summary = "Send a test email to all notification addresses for an alert",
    security(("OAuth2" = ["alerts:write"])),
    params(("id" = i32, Path, description = "Alert ID")),
    responses(
        (status = 202, description = "Test email(s) queued"),
        (status = 401, description = "Missing or invalid token", body = AuthError),
        (status = 403, description = "Not owner or missing scope", body = AuthError),
        (status = 404, description = "Alert not found", body = AuthError),
    )
)]
async fn test_email(
    Extension(resources): Extension<AppResources>,
    OAuth2Auth(auth): OAuth2Auth,
    Path(id): Path<i32>,
) -> Result<StatusCode, AuthError> {
    let alert_entity = require_alert_owner(&resources, id, &auth, SCOPE_ALERTS_WRITE).await?;

    let emails_by_alert = load_emails_by_alert(resources.db.as_ref(), &[id]).await?;
    let notify_emails: Vec<String> = match emails_by_alert.get(&id) {
        Some(emails) if !emails.is_empty() => emails.clone(),
        _ => {
            if alert_entity.email.is_empty() {
                vec![]
            } else {
                vec![alert_entity.email.clone()]
            }
        }
    };

    if notify_emails.is_empty() {
        return Err(AuthError::bad_request(
            "no_emails: this alert has no notification email addresses configured",
        ));
    }

    let config = &resources.config;
    let base = format!("{}/", config.frontend_url.trim_end_matches('/'));
    let check_url = format!("{}results?serverName={}", base, alert_entity.server_name);
    let alert_url = format!("{}alerts/edit/{}", base, id);
    let manage_url = format!("{}alerts", base);
    let sponsor_url = config
        .github_sponsors_url
        .clone()
        .or_else(|| config.liberapay_url.clone());

    let tmpl = crate::email_templates::TestEmailTemplate {
        server_name: alert_entity.server_name.clone(),
        check_url,
        alert_url,
        manage_url,
        environment_name: config.environment_name.clone(),
        sponsor_url,
    };
    let html_body = tmpl.render_html().ok();
    let text_body = tmpl.render_text();

    let subject = crate::email_templates::env_subject(
        &format!(
            "[Test] Federation Alert: {} – test notification",
            alert_entity.server_name
        ),
        config.environment_name.as_deref(),
    );

    for email in &notify_emails {
        if let Err(e) = crate::email_outbox::enqueue(
            resources.db.as_ref(),
            email,
            &subject,
            html_body.clone(),
            text_body.clone(),
            None,
        )
        .await
        {
            tracing::error!(
                alert_id = id,
                email = %email,
                error = %e,
                "Failed to enqueue test email"
            );
        }
    }

    tracing::info!(
        alert_id = id,
        email_count = notify_emails.len(),
        "Queued test emails"
    );
    Ok(StatusCode::ACCEPTED)
}
