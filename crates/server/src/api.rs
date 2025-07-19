use crate::{
    AppResources,
    api::{alert_api::AlertAppState, federation_tester_api::AppState},
};
use hickory_resolver::name_server::ConnectionProvider;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::info;
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
    use crate::{
        api::FEDERATION_TAG,
        cache::{DnsCache, VersionCache, WellKnownCache},
        connection_pool::ConnectionPool,
        response::{Root, generate_json_report},
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
    use tracing::error;
    use utoipa::IntoParams;
    use utoipa_axum::{router::OpenApiRouter, routes};

    #[derive(Deserialize, IntoParams)]
    pub struct ApiParams {
        pub server_name: String,
        /// Skip cache and force fresh requests - useful for debugging
        #[serde(default)]
        pub no_cache: bool,
    }

    #[derive(Clone)]
    pub struct AppState<P: ConnectionProvider> {
        pub resolver: Arc<Resolver<P>>,
        pub connection_pool: ConnectionPool,
        pub dns_cache: DnsCache,
        pub well_known_cache: WellKnownCache,
        pub version_cache: VersionCache,
    }

    pub(crate) fn router<P: ConnectionProvider>(state: AppState<P>) -> OpenApiRouter {
        OpenApiRouter::new()
            .routes(routes!(get_report))
            .routes(routes!(get_fed_ok))
            .with_state(state)
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
    ) -> impl IntoResponse {
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
            &state.dns_cache,
            &state.well_known_cache,
            &state.version_cache,
            !params.no_cache,
        )
        .await
        {
            Ok(report) => {
                // Convert the report to a Value for JSON serialization
                let report = serde_json::to_value(report)
                    .unwrap_or_else(|_| json!({ "error": "Failed to serialize report" }));
                (StatusCode::OK, Json(report))
            }
            Err(e) => {
                error!("Error generating report: {e:?}");
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
    ) -> impl IntoResponse {
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
            &state.dns_cache,
            &state.well_known_cache,
            &state.version_cache,
            !params.no_cache,
        )
        .await
        {
            Ok(report) => (
                StatusCode::OK,
                if report.federation_ok {
                    "GOOD".to_string()
                } else {
                    "BAD".to_string()
                },
            ),
            Err(e) => {
                error!("Error generating report: {e:?}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to generate report: {e}"),
                )
            }
        }
    }
}
pub mod alert_api {
    use crate::{AppResources, api::ALERTS_TAG, entity::alert, recurring_alerts::AlertTaskManager};
    use axum::{
        Extension, Json,
        extract::{Path, Query},
        response::IntoResponse,
    };
    use hyper::StatusCode;
    use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
    use lettre::AsyncTransport;
    use sea_orm::{ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter};
    use serde::{Deserialize, Serialize};
    use serde_json::json;
    use std::sync::Arc;
    use time::OffsetDateTime;
    use tracing::error;
    use utoipa::{IntoParams, ToSchema};
    use utoipa_axum::{router::OpenApiRouter, routes};

    #[derive(Serialize, Deserialize)]
    pub struct MagicClaims {
        pub exp: usize,
        pub email: String,
        pub server_name: String,
        pub action: String,           // "register", "list", "delete"
        pub alert_id: Option<String>, // Only for delete
    }

    #[derive(serde::Deserialize, ToSchema)]
    struct RegisterAlert {
        email: String,
        server_name: String,
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
            .routes(routes!(register_alert, list_alerts, delete_alert))
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
        // JWT magic token
        let exp = (OffsetDateTime::now_utc() + time::Duration::hours(1)).unix_timestamp() as usize;
        let claims = MagicClaims {
            exp,
            email: payload.email.clone(),
            server_name: payload.server_name.clone(),
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
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": format!("DB error: {e}")})),
                    );
                }
            }
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": format!("DB error: {e}")})),
                );
            }
        }

        // Send verification email (always for new or unverified)
        let verify_url = format!("{}/verify?token={}", resources.config.frontend_url, token);
        let email_body = format!(
            r#"Hello,
        
You requested to receive alerts for your server: {}

Please verify your email address by clicking the link below (valid for 1 hour):
{}

If you did not request this, you can ignore this email.

Best regards,
The Federation Tester Team"#,
            payload.server_name, verify_url
        );
        let email = lettre::Message::builder()
            .from(resources.config.smtp.from.parse().unwrap())
            .to(payload.email.parse().unwrap())
            .subject("Please verify your email for Federation Alerts")
            .header(lettre::message::header::ContentType::TEXT_PLAIN)
            .message_id(None)
            .body(email_body)
            .unwrap();
        if let Err(e) = resources.mailer.send(email).await {
            error!("Failed to send verification email: {:#?}", e);
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
        let secret = resources.config.magic_token_secret.as_bytes();
        let token_data = decode::<MagicClaims>(
            &params.token,
            &DecodingKey::from_secret(secret),
            &Validation::new(Algorithm::HS256),
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
                            Err(e) => (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Json(json!({"error": format!("DB error: {e}")})),
                            ),
                        }
                    }
                    "list" => {
                        // Return all alerts for this email/server
                        let alerts = alert::Entity::find()
                            .filter(alert::Column::Email.eq(claims.email.clone()))
                            .filter(alert::Column::ServerName.eq(claims.server_name.clone()))
                            .all(resources.db.as_ref())
                            .await;
                        match alerts {
                            Ok(list) => (StatusCode::OK, Json(json!({"alerts": list}))),
                            Err(e) => (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Json(json!({"error": format!("DB error: {e}")})),
                            ),
                        }
                    }
                    "delete" => {
                        // Delete the alert with the given id for this email
                        if let Some(alert_id) = claims.alert_id.clone() {
                            let del = alert::Entity::delete_many()
                                .filter(alert::Column::Id.eq(alert_id.clone()))
                                .filter(alert::Column::Email.eq(claims.email.clone()))
                                .exec(resources.db.as_ref())
                                .await;
                            match del {
                                Ok(_) => (StatusCode::OK, Json(json!({"status": "deleted"}))),
                                Err(e) => (
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    Json(json!({"error": format!("DB error: {e}")})),
                                ),
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
            Err(_) => (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Invalid or expired token"})),
            ),
        }
    }

    #[utoipa::path(
        get,
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
        Json(payload): Json<RegisterAlert>,
    ) -> impl IntoResponse {
        let exp = (OffsetDateTime::now_utc() + time::Duration::hours(1)).unix_timestamp() as usize;
        let claims = MagicClaims {
            exp,
            email: payload.email.clone(),
            server_name: payload.server_name.clone(),
            action: "list".to_string(),
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
        let verify_url = format!("{}/verify?token={}", resources.config.frontend_url, token);
        let email_body = format!(
            r#"Hello,\n\nYou requested to view your alerts for server: {}\n\nPlease verify by clicking the link below (valid for 1 hour):\n{}\n\nBest regards,\nThe Federation Tester Team"#,
            payload.server_name, verify_url
        );
        let email = lettre::Message::builder()
            .from(resources.config.smtp.from.parse().unwrap())
            .to(payload.email.parse().unwrap())
            .subject("Verify to view your Federation Alerts")
            .header(lettre::message::header::ContentType::TEXT_PLAIN)
            .message_id(None)
            .body(email_body)
            .unwrap();
        if let Err(e) = resources.mailer.send(email).await {
            error!("Failed to send verification email: {:#?}", e);
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
                "id" = String,
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
        Path(id): Path<String>,
    ) -> impl IntoResponse {
        let found = alert::Entity::find()
            .filter(alert::Column::Id.eq(id.clone()))
            .one(resources.db.as_ref())
            .await;
        match found {
            Ok(Some(a)) => {
                let exp = (OffsetDateTime::now_utc() + time::Duration::hours(1)).unix_timestamp()
                    as usize;
                let claims = MagicClaims {
                    exp,
                    email: a.email.clone(),
                    server_name: a.server_name.clone(),
                    action: "delete".to_string(),
                    alert_id: Some(id.clone()),
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
                let verify_url =
                    format!("{}/verify?token={}", resources.config.frontend_url, token);
                let email_body = format!(
                    r#"Hello,\n\nYou requested to delete your alert for server: {}\n\nPlease verify by clicking the link below (valid for 1 hour):\n{}\n\nBest regards,\nThe Federation Tester Team"#,
                    a.server_name, verify_url
                );
                let email = lettre::Message::builder()
                    .from(resources.config.smtp.from.parse().unwrap())
                    .to(a.email.parse().unwrap())
                    .subject("Verify to delete your Federation Alert")
                    .header(lettre::message::header::ContentType::TEXT_PLAIN)
                    .body(email_body)
                    .unwrap();
                if let Err(e) = resources.mailer.send(email).await {
                    error!("Failed to send verification email: {:#?}", e);
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
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("DB error: {e}")})),
            ),
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

pub async fn start_webserver<P: ConnectionProvider>(
    app_state: AppState<P>,
    alert_state: AlertAppState,
    app_resources: AppResources,
) -> color_eyre::Result<()> {
    let (router, api) = OpenApiRouter::with_openapi(ApiDoc::openapi())
        .nest(
            "/api/federation",
            federation_tester_api::router::<P>(app_state),
        )
        .nest("/api/alerts", alert_api::router(alert_state))
        .layer(axum::Extension(app_resources))
        .routes(routes!(health))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .split_for_parts();

    let router = router.merge(Redoc::with_url("/api-docs", api));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    info!("Server running on http://0.0.0.0:8080");
    axum::serve(listener, router.into_make_service())
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
