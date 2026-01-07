use crate::logging::wide_events::WideEvent;
use crate::{
    AppResources,
    api::{alert_api::AlertAppState, federation_tester_api::AppState},
};
use hickory_resolver::name_server::ConnectionProvider;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use utoipa::{
    Modify, OpenApi,
    openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme},
};
use utoipa_axum::{router::OpenApiRouter, routes};
use utoipa_redoc::{Redoc, Servable};

const MISC_TAG: &str = "Miscellaneous";
const FEDERATION_TAG: &str = "Federation Tester API";
const ALERTS_TAG: &str = "Alerts API";

pub mod federation_tester_api {
    use crate::wide_instrument;
    use crate::{
        api::FEDERATION_TAG,
        client::resolution::{fetch_client_server_versions, resolve_client_side_api},
        connection_pool::ConnectionPool,
        response::{Root, generate_json_report},
        stats::{self, StatEvent},
    };
    use axum::{
        Json,
        extract::{Query, State},
        response::IntoResponse,
    };
    use hickory_resolver::{Resolver, name_server::ConnectionProvider};
    use hyper::StatusCode;
    use serde::Deserialize;
    use serde_json::json;
    use std::sync::Arc;
    use utoipa::IntoParams;
    use utoipa_axum::{router::OpenApiRouter, routes};

    #[derive(Deserialize, IntoParams, Debug)]
    pub struct ApiParams {
        pub server_name: String,
        /// When true/1 this request consents to counting anonymized statistics.
        #[serde(default)]
        pub stats_opt_in: Option<bool>,
    }

    #[derive(Clone)]
    pub struct AppState<P: ConnectionProvider> {
        pub resolver: Arc<Resolver<P>>,
        pub connection_pool: ConnectionPool,
    }

    pub(crate) fn router<P: ConnectionProvider>(
        state: AppState<P>,
        debug_mode: bool,
    ) -> OpenApiRouter {
        use axum::routing::get;
        let mut r = OpenApiRouter::new()
            .routes(routes!(get_report))
            .routes(routes!(get_fed_ok));

        if debug_mode {
            // Add non-documented debug route manually (not part of OpenAPI spec)
            r = r.route("/debug/cache-stats", get(cache_stats));
        }

        r.with_state(state)
    }

    #[utoipa::path(
        get,
        path = "/report",
        params(ApiParams),
        tag = FEDERATION_TAG,
        operation_id = "Get Federation Report as JSON",
        responses(
            (status = 200, description = "JSON report of the federation test", body = Root, content_type = "application/json"),
            (status = 400, description = "Invalid request parameters", content_type = "application/json"),
            (status = 500, description = "Internal server error", content_type = "application/json")
        ),
    )]
    async fn get_report<P: ConnectionProvider>(
        Query(params): Query<ApiParams>,
        State(state): State<AppState<P>>,
        axum::Extension(resources): axum::Extension<crate::AppResources>,
    ) -> impl IntoResponse {
        let evt = wide_instrument!(
            "api_get_report",
            concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            server_name = &params.server_name
        );
        let _wide_evt_enter = evt.enter();
        if params.server_name.is_empty() {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "server_name parameter is required" })),
            );
        }

        match generate_json_report(
            &params.server_name.to_lowercase(),
            state.resolver.as_ref(),
            &state.connection_pool,
        )
        .await
        {
            Ok(report) => {
                if params.stats_opt_in.unwrap_or(false) && resources.config.statistics.enabled {
                    // Fetch client-server versions for unstable features tracking
                    let (unstable_enabled, unstable_announced) = if report.federation_ok {
                        let cs_address = resolve_client_side_api(&params.server_name).await;
                        let cs_versions = fetch_client_server_versions(&cs_address).await;

                        if let Some(features) = cs_versions.unstable_features {
                            let enabled: Vec<String> = features
                                .iter()
                                .filter_map(|(k, v)| if *v { Some(k.clone()) } else { None })
                                .collect();
                            let announced: Vec<String> = features.keys().cloned().collect();
                            (Some(enabled), Some(announced))
                        } else {
                            (None, None)
                        }
                    } else {
                        (None, None)
                    };

                    stats::record_event(
                        &resources,
                        StatEvent {
                            server_name: &params.server_name,
                            federation_ok: report.federation_ok,
                            version_name: Some(&report.version.name),
                            version_string: Some(&report.version.version),
                            unstable_features_enabled: unstable_enabled.as_deref(),
                            unstable_features_announced: unstable_announced.as_deref(),
                        },
                    )
                    .await;
                }
                // Convert the report to a Value for JSON serialization
                let report = serde_json::to_value(report)
                    .unwrap_or_else(|_| json!({ "error": "Failed to serialize report" }));
                (StatusCode::OK, Json(report))
            }
            Err(e) => {
                tracing::error!(
                    name = "api.get_report.failed",
                    target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                    error = ?e,
                    message = "Error generating report"
                );
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "error": format!("Failed to generate report: {}", e)
                    })),
                )
            }
        }
    }

    #[utoipa::path(
        get,
        path = "/federation-ok",
        params(ApiParams),
        tag = FEDERATION_TAG,
        operation_id = "Check Federation Status",
        responses(
            (status = 200, description = "Returns 'GOOD' if federation is ok, 'BAD' otherwise", body = inline(String), example = "GOOD"),
            (status = 400, description = "Invalid request parameters"),
            (status = 500, description = "Internal server error")
        ),
    )]
    async fn get_fed_ok<P: ConnectionProvider>(
        Query(params): Query<ApiParams>,
        State(state): State<AppState<P>>,
        axum::Extension(resources): axum::Extension<crate::AppResources>,
    ) -> impl IntoResponse {
        let evt = wide_instrument!(
            "api_get_fed_ok",
            concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            server_name = &params.server_name
        );
        let _wide_evt_enter = evt.enter();
        if params.server_name.is_empty() {
            return (
                StatusCode::BAD_REQUEST,
                "server_name parameter is required".to_string(),
            );
        }

        match generate_json_report(
            &params.server_name.to_lowercase(),
            state.resolver.as_ref(),
            &state.connection_pool,
        )
        .await
        {
            Ok(report) => {
                if params.stats_opt_in.unwrap_or(false) && resources.config.statistics.enabled {
                    // Fetch client-server versions for unstable features tracking
                    let (unstable_enabled, unstable_announced) = if report.federation_ok {
                        let cs_address = resolve_client_side_api(&params.server_name).await;
                        let cs_versions = fetch_client_server_versions(&cs_address).await;

                        if let Some(features) = cs_versions.unstable_features {
                            let enabled: Vec<String> = features
                                .iter()
                                .filter_map(|(k, v)| if *v { Some(k.clone()) } else { None })
                                .collect();
                            let announced: Vec<String> = features.keys().cloned().collect();
                            (Some(enabled), Some(announced))
                        } else {
                            (None, None)
                        }
                    } else {
                        (None, None)
                    };

                    stats::record_event(
                        &resources,
                        StatEvent {
                            server_name: &params.server_name,
                            federation_ok: report.federation_ok,
                            version_name: Some(&report.version.name),
                            version_string: Some(&report.version.version),
                            unstable_features_enabled: unstable_enabled.as_deref(),
                            unstable_features_announced: unstable_announced.as_deref(),
                        },
                    )
                    .await;
                }
                (
                    StatusCode::OK,
                    if report.federation_ok {
                        "GOOD".to_string()
                    } else {
                        "BAD".to_string()
                    },
                )
            }
            Err(e) => {
                tracing::error!(
                    name = "api.get_fed_ok.failed",
                    target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                    error = ?e,
                    message = "Error generating report"
                );
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to generate report: {e}"),
                )
            }
        }
    }

    // Debug-only endpoint (conditionally added to router when debug_mode=true), therefore no OpenAPI doc.
    async fn cache_stats<P: ConnectionProvider>(
        State(state): State<AppState<P>>,
        axum::Extension(resources): axum::Extension<crate::AppResources>,
        axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    ) -> impl IntoResponse {
        let evt = wide_instrument!(
            "api_cache_stats",
            concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            client_addr = addr.ip()
        );
        let _wide_evt_enter = evt.enter();
        use serde::Serialize;
        if !is_allowed_ip(&addr, &resources.config.debug_allowed_nets) {
            return (
                hyper::StatusCode::FORBIDDEN,
                axum::Json(serde_json::json!({"error": "forbidden"})),
            );
        }

        #[derive(Serialize)]
        struct CombinedStats {
            connection_pools: usize,
        }
        let body = CombinedStats {
            connection_pools: state.connection_pool.len(),
        };
        let value = serde_json::to_value(body)
            .unwrap_or_else(|_| serde_json::json!({"error": "serialization failure"}));
        (hyper::StatusCode::OK, axum::Json(value))
    }

    fn is_allowed_ip(addr: &std::net::SocketAddr, nets: &[crate::config::IpNet]) -> bool {
        let ip = addr.ip();
        nets.iter().any(|net| net.contains(&ip))
    }
}
pub mod alert_api {
    use crate::wide_instrument;
    use crate::{AppResources, api::ALERTS_TAG, entity::alert, recurring_alerts::AlertTaskManager};
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

    #[derive(Clone)]
    pub struct AlertAppState {
        pub task_manager: Arc<AlertTaskManager>,
    }

    pub(crate) fn router(alert_state: AlertAppState) -> OpenApiRouter {
        OpenApiRouter::new()
            .routes(routes!(register_alert, delete_alert))
            .routes(routes!(list_alerts))
            .routes(routes!(verify_alert))
            .with_state(alert_state)
    }

    #[utoipa::path(
        post,
        path = "/register",
        operation_id = "Register Alert",
        tag = ALERTS_TAG,
        request_body = RegisterAlert,
        responses(
            (status = 200, description = "Verification email sent", content_type = "application/json" , example = json!({"status": "verification email sent"})),
            (status = 400, description = "Invalid request parameters", content_type = "application/json"),
            (status = 500, description = "Internal server error", content_type = "application/json")
        )
    )]
    async fn register_alert(
        Extension(resources): Extension<AppResources>,
        Json(payload): Json<RegisterAlert>,
    ) -> impl IntoResponse {
        let evt = wide_instrument!(
            "api_register_alert",
            concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            server_name = &payload.server_name
        );
        let _wide_evt_enter = evt.enter();

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

    #[utoipa::path(
        get,
        path = "/verify",
        tag = ALERTS_TAG,
        operation_id = "Verify Alert Email",
        params(VerifyParams),
        params(
            (
                "token" = String,
                Query,
                description = "JWT token for email verification",
                example = "123e4567-e89b-12d3-a456-426"
            ),
        ),
        responses(
            (status = 200, description = "Email verified successfully", content_type = "application/json", body = VerificatonResponseData),
            (status = 200, description = "List of alerts for the email", content_type = "application/json", body = AlertsList),
            (status = 400, description = "Invalid or expired token", content_type = "application/json"),
            (status = 500, description = "Internal server error", content_type = "application/json")
        )
    )]
    async fn verify_alert(
        Extension(resources): Extension<AppResources>,
        Query(params): Query<VerifyParams>,
    ) -> impl IntoResponse {
        let evt = wide_instrument!(
            "api_verify_alert",
            concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            token_len = params.token.len()
        );
        let _wide_evt_enter = evt.enter();

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
                                return (
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    Json(json!({"error": format!("DB error: {e}")})),
                                );
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
                                return (
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    Json(json!({"error": format!("DB error: {e}")})),
                                );
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
                                    return (
                                        StatusCode::INTERNAL_SERVER_ERROR,
                                        Json(json!({"error": format!("DB error: {e}")})),
                                    );
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

    #[utoipa::path(
        post,
        path = "/list",
        tag = ALERTS_TAG,
        operation_id = "List Alerts",
        responses(
            (status = 200, description = "Verification email has successfully been sent", content_type = "application/json", example = json!({"status": "verification email sent"})),
            (status = 500, description = "Internal server error", content_type = "application/json")
        )
    )]
    async fn list_alerts(
        Extension(resources): Extension<AppResources>,
        Json(payload): Json<ListAlerts>,
    ) -> impl IntoResponse {
        let evt = wide_instrument!(
            "api_list_alerts",
            concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            email = &payload.email
        );
        let _wide_evt_enter = evt.enter();

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

    #[utoipa::path(
        delete,
        path = "/{id}",
        tag = ALERTS_TAG,
        operation_id = "Delete Alert",
        params(
            (
                "id" = i32,
                Path,
                description = "ID of the alert to delete",
                example = "123e4567-e89b-12d3-a456-426"
            ),
        ),
        responses(
            (status = 200, description = "Alert deletion verification flow has been started", content_type = "application/json", example = json!({"status": "verification email sent"})),
            (status = 404, description = "Alert not found", content_type = "application/json"),
            (status = 500, description = "Internal server error", content_type = "application/json")
        )
    )]
    async fn delete_alert(
        Extension(resources): Extension<AppResources>,
        Path(id): Path<i32>,
    ) -> impl IntoResponse {
        let evt = wide_instrument!(
            "api_delete_alert",
            concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
            alert_id = &id
        );
        let _wide_evt_enter = evt.enter();
        let found = alert::Entity::find()
            .filter(alert::Column::Id.eq(id))
            .one(resources.db.as_ref())
            .await;
        match found {
            Ok(Some(a)) => {
                let exp = (OffsetDateTime::now_utc() + time::Duration::hours(1)).unix_timestamp()
                    as usize;
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
                let verify_url =
                    format!("{}/verify?token={}", resources.config.frontend_url, token);
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
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": format!("DB error: {e}")})),
                );
            }
        }
    }
}

#[utoipa::path(
    method(get, head),
    path = "/healthz",
    tag = MISC_TAG,
    operation_id = "Health Check",
    responses(
        (status = OK, description = "Ok", body = str, content_type = "text/plain", example = "ok")
    )
)]
async fn health() -> &'static str {
    "ok"
}

#[utoipa::path(
    get,
    path = "/metrics",
    tag = MISC_TAG,
    operation_id = "Prometheus Metrics",
    responses(
        (status = 200, description = "Prometheus metrics in text exposition format", body = String, content_type = "text/plain"),
        (status = 404, description = "Metrics disabled via configuration")
    )
)]
async fn metrics(
    axum::Extension(resources): axum::Extension<AppResources>,
) -> (hyper::StatusCode, String) {
    if !resources.config.statistics.enabled || !resources.config.statistics.prometheus_enabled {
        return (hyper::StatusCode::NOT_FOUND, String::new());
    }
    let body = crate::stats::build_prometheus_metrics_cached(&resources).await;
    (hyper::StatusCode::OK, body)
}

/// Middleware that collects/wires wide-event metadata and propagates traceparent header.
///
/// Behavior:
/// - If the incoming request includes a `traceparent` header, we record it onto the WideEvent
///   and echo it back in the response headers so capable frontends can correlate logs.
/// - We always create a per-request `WideEvent` span and enter it for the request lifetime so
///   recorded attributes and child events are attached to a request-scoped span.
/// - This middleware is defensive: if the client doesn't send trace headers (older versions),
///   we still create the request span and carry on.
async fn propagate_trace(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    // Create a request-scoped WideEvent and attach some common attributes.
    let evt = WideEvent::new(
        "request",
        concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
    );

    // Generate a server-side request_id and attach it to the event and response.
    let request_id = uuid::Uuid::new_v4().to_string();
    evt.add("request_id", &request_id);

    // Add HTTP method and path if available
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    evt.add("http.method", method);
    evt.add("http.path", path);

    // Record a few headers that may be useful (if present). Keep it small.
    if let Some(hv) = req.headers().get(axum::http::header::USER_AGENT)
        && let Ok(s) = hv.to_str()
    {
        evt.add("http.user_agent", s);
    }
    // Client IP is available through ConnectInfo; try to grab it from extensions if present.
    if let Some(addr) = req.extensions().get::<std::net::SocketAddr>() {
        evt.add("client.ip", addr.ip().to_string());
    }

    // Extract incoming traceparent header if present and attach to the event.
    let incoming_traceparent = req
        .headers()
        .get("traceparent")
        .and_then(|hv| hv.to_str().ok())
        .map(|s| s.to_string());
    if let Some(tp) = incoming_traceparent.as_deref() {
        evt.add("traceparent.incoming", tp);
    }

    // Enter the request span so downstream code logs/records attach to it.
    let _enter = evt.enter();

    // Call the next service in the stack.
    let mut response = next.run(req).await;

    // Always include x-request-id in the response so clients can correlate.
    if let Ok(hv) = axum::http::HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("x-request-id", hv);
    }

    // If an incoming traceparent was present, echo it back to the client so the client can
    // correlate. If not present, and tracing-opentelemetry is enabled, return the server span's traceparent.
    if let Some(tp) = incoming_traceparent {
        // It's okay if insertion fails (invalid header) — ignore in that case.
        if let Ok(hv) = axum::http::HeaderValue::from_str(&tp) {
            response.headers_mut().insert(
                axum::http::header::HeaderName::from_static("traceparent"),
                hv,
            );
        }
    } else {
        // If tracing-opentelemetry is enabled and a span was created, we can attempt to
        // return the current span's traceparent for clients that can accept it.
        // This is optional and guarded by the tracing-opentelemetry feature at compile time.
        #[cfg(feature = "tracing-opentelemetry")]
        {
            use opentelemetry::trace::TraceContextExt;
            use tracing_opentelemetry::OpenTelemetrySpanExt;

            // Extract the OpenTelemetry Context from the current tracing span (if available).
            let cx = tracing::Span::current().context();
            // Keep a SpanRef alive while we extract its SpanContext so we don't borrow a temporary.
            let span_ref = cx.span();
            let span_ctx = span_ref.span_context();
            if span_ctx.is_valid() {
                // Format traceparent according to W3C traceparent header: "00-{trace}-{span}-{flags}"
                let trace_id = span_ctx.trace_id().to_string();
                let span_id = span_ctx.span_id().to_string();
                let trace_flags = format!("{:02x}", span_ctx.trace_flags().to_u8());
                let tp_value = format!("00-{}-{}-{}", trace_id, span_id, trace_flags);
                if let Ok(hv) = axum::http::HeaderValue::from_str(&tp_value) {
                    response.headers_mut().insert(
                        axum::http::header::HeaderName::from_static("traceparent"),
                        hv,
                    );
                }
            }
        }
    }

    // Optionally, record response metadata as attributes on the same event/span.
    // e.g. status code
    {
        // Response::status() returns a StatusCode; convert to u16 then to u64 for the attribute.
        let status_u16 = response.status().as_u16();
        evt.add_u64("http.status_code", status_u16 as u64);
    }

    response
}

pub async fn start_webserver<P: ConnectionProvider>(
    app_state: AppState<P>,
    alert_state: AlertAppState,
    app_resources: AppResources,
    debug_mode: bool,
) -> color_eyre::Result<()> {
    // Build the router and attach middleware layers. The propagate_trace middleware is applied
    // so incoming trace headers are recorded and propagated back to clients when available.
    let (router, api) = OpenApiRouter::with_openapi(ApiDoc::openapi())
        .nest(
            "/api/federation",
            federation_tester_api::router::<P>(app_state, debug_mode),
        )
        .nest("/api/alerts", alert_api::router(alert_state))
        .routes(routes!(health))
        .routes(routes!(metrics))
        // Attach application resources, CORS, our trace propagation middleware and the standard TraceLayer.
        .layer(axum::Extension(app_resources))
        .layer(CorsLayer::permissive())
        .layer(axum::middleware::from_fn(propagate_trace))
        .layer(TraceLayer::new_for_http())
        .split_for_parts();

    let router = router.merge(Redoc::with_url("/api-docs", api));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    tracing::info!(
        name = "server.started",
        target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
        message = "Server running",
        addr = "0.0.0.0:8080"
    );
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await
    .map_err(|e| color_eyre::Report::msg(format!("Failed to start server: {e}")))?;

    Ok(())
}

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            let bearer = HttpBuilder::new()
                .scheme(HttpAuthScheme::Bearer)
                .bearer_format("JWT")
                .description(Some("Use the JWT token obtained from the `/api/alerts/register` endpoint to authenticate."))
                .build();
            components.add_security_scheme("Authorization", SecurityScheme::Http(bearer));
        }
    }
}

#[derive(OpenApi)]
#[openapi(
    modifiers(&SecurityAddon),
    info(
        title = "Federation Tester API",
        version = "1.0.0",
        description = "API for testing Matrix federation compatibility of servers."
    ),
    tags(
        (name = MISC_TAG, description = "Miscellaneous endpoints"),
        (name = FEDERATION_TAG, description = "Federation Tester API endpoints"),
        (name = ALERTS_TAG, description = "Alerts API endpoints")
    )
)]
struct ApiDoc;
