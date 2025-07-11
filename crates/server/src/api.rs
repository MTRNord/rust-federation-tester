use crate::{
    AppResources,
    api::{alert_api::AlertAppState, federation_tester_api::AppState},
};
use hickory_resolver::name_server::ConnectionProvider;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::info;
use utoipa::OpenApi;
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
    use std::sync::Arc;

    use axum::{
        Extension, Json,
        extract::{Path, Query, State},
        response::{Html, IntoResponse},
    };
    use hyper::{HeaderMap, StatusCode};
    use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
    use lettre::AsyncTransport;
    use sea_orm::{ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter};
    use serde::{Deserialize, Serialize};
    use serde_json::json;
    use time::OffsetDateTime;
    use utoipa::{IntoParams, ToSchema};
    use utoipa_axum::{router::OpenApiRouter, routes};
    use uuid::Uuid;

    use crate::{AppResources, api::ALERTS_TAG, entity::alert, recurring_alerts::AlertTaskManager};

    #[derive(Serialize, Deserialize)]
    struct MagicClaims {
        exp: usize,
        email: String,
        server_name: String,
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

        let id = Uuid::new_v4();
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
                    id: Set(id),
                    email: Set(payload.email.clone()),
                    server_name: Set(payload.server_name.clone()),
                    verified: Set(false),
                    magic_token: Set(token.clone()),
                    created_at: Set(now),
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
            .body(email_body)
            .unwrap();
        if let Err(e) = resources.mailer.send(email).await {
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
        get,
        path = "/verify",
        tag = ALERTS_TAG,
        params(VerifyParams),
        responses(
            (status = 200, description = "Email verified successfully", content_type = "text/html"),
            (status = 400, description = "Invalid or expired token", content_type = "text/html"),
            (status = 500, description = "Internal server error", content_type = "text/html")
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
        let (status, body) = match token_data {
            Ok(data) => {
                // Find alert by email and server_name
                let claims = data.claims;
                let found = alert::Entity::find()
                    .filter(alert::Column::Email.eq(claims.email.clone()))
                    .filter(alert::Column::ServerName.eq(claims.server_name.clone()))
                    .one(resources.db.as_ref())
                    .await;
                match found {
                    Ok(Some(a)) => {
                        // Mark as verified
                        let mut model: alert::ActiveModel = a.into();
                        model.verified = Set(true);
                        if let Err(e) = model.update(resources.db.as_ref()).await {
                            (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                format!(
                                    r#"
<html>
    <head>
        <title>Verification failed</title>
        <style>
            body {{
                font-family: sans-serif;
                text-align: center;
                padding-top: 3em;
                background:#f8f9fa;
            }}
            .card {{
                background: #fff;
                max-width: 400px;
                margin: 2em auto;
                padding: 2em 2em 1em 2em;
                border-radius: 12px;
                box-shadow: 0 2px 12px #0001;
            }}
            h1{{
                color: #c00;
            }}
            p{{
                color:#333;
            }}
        </style>
    </head>
    <body>
        <div class='card'>
            <h1>❌ Verification failed</h1>
            <p>Database error: {e}</p>
        </div>
    </body>
</html>"#
                                ),
                            )
                        } else {
                            (
                                StatusCode::OK,
                                format!(
                                    r#"
<html>
    <head>
        <title>Email Verified</title>
        <style>
            body {{
                font-family: sans-serif;
                text-align: center;
                padding-top: 3em;
                background: #f8f9fa;
            }}
            .card {{
                background: #fff;
                max-width: 400px;
                margin: 2em auto;
                padding: 2em 2em 1em 2em;
                border-radius: 12px;
                box-shadow: 0 2px 12px #0001;
            }}
            h1 {{
                color: #090;
            }}
            p {{
                color: #333;
            }}
        </style>
    </head>
    <body>
        <div class='card'>
            <h1>✅ Email Verified!</h1>
            <p>Your email has been verified and you will receive alerts for <b>{}</b>.</p>
            <p>You may close this page.</p>
        </div>
    </body>
</html>"#,
                                    claims.server_name
                                ),
                            )
                        }
                    }
                    Ok(None) => (
                        StatusCode::BAD_REQUEST,
                        r#"
<html>
    <head>
        <title>Verification failed</title>
        <style>
            body {
                font-family: sans-serif;
                text-align: center;
                padding-top: 3em;
                background: #f8f9fa;
            }
            .card {
                background: #fff;
                max-width: 400px;
                margin: 2em auto;
                padding: 2em 2em 1em 2em;
                border-radius: 12px;
                box-shadow: 0 2px 12px #0001;
            }
            h1 {
                color: #c00;
            }
            p {
                color: #333;
            }
        </style>
    </head>
    <body>
        <div class='card'>
            <h1>❌ Verification failed</h1>
            <p>No matching alert found.</p>
        </div>
    </body>
</html>"#
                            .to_string(),
                    ),
                    Err(e) => (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!(
                            r#"
<html>
    <head>
        <title>Verification failed</title>
        <style>
            body {{
                font-family: sans-serif;
                text-align: center;
                padding-top: 3em;
                background: #f8f9fa;
            }}
            .card {{
                background: #fff;
                max-width: 400px;
                margin: 2em auto;
                padding: 2em 2em 1em 2em;
                border-radius: 12px;
                box-shadow: 0 2px 12px #0001;
            }}
            h1 {{
                color:#c00;
            }}
            p {{
                color:#333;
            }}
        </style>
    </head>
    <body>
        <div class='card'>
            <h1>❌ Verification failed</h1>
            <p>Database error: {e}</p>
        </div>
    </body>
</html>"#
                        ),
                    ),
                }
            }
            Err(_) => (
                StatusCode::BAD_REQUEST,
                r#"
<html>
    <head>
        <title>Verification failed</title>
        <style>
            body {
                font-family: sans-serif;
                text-align: center;
                padding-top: 3em;
                background: #f8f9fa;
            }
            .card {
                background: #fff;
                max-width: 400px;
                margin: 2em auto;
                padding: 2em 2em 1em 2em;
                border-radius: 12px;
                box-shadow: 0 2px 12px #0001;
            }
            h1 {
                color:#c00;
            }
            p {
                color:#333;
            }
        </style>
    </head>
    <body>
        <div class='card'>
            <h1>❌ Verification failed</h1>
            <p>Invalid or expired token.</p>
        </div>
    </body>
</html>"#
                    .to_string(),
            ),
        };
        (status, Html(body))
    }

    #[utoipa::path(
        get,
        path = "/list",
        tag = ALERTS_TAG,
        responses(
            (status = 200, description = "List of alerts for the email", content_type = "application/json"),
            (status = 401, description = "Unauthorized - invalid or missing token", content_type = "application/json"),
            (status = 500, description = "Internal server error", content_type = "application/json")
        )
    )]
    async fn list_alerts(
        Extension(resources): Extension<AppResources>,
        headers: HeaderMap,
    ) -> impl IntoResponse {
        // Get token from Authorization header
        let token = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "));
        if token.is_none() {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Missing or invalid Authorization header"})),
            );
        }
        let token = token.unwrap();
        // Find alert by token
        let found = alert::Entity::find()
            .filter(alert::Column::MagicToken.eq(token))
            .one(resources.db.as_ref())
            .await;
        let found = match found {
            Ok(Some(a)) => a,
            _ => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error": "Invalid token"})),
                );
            }
        };
        // List all alerts for this email
        let alerts = alert::Entity::find()
            .filter(alert::Column::Email.eq(found.email.clone()))
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

    #[utoipa::path(
        delete,
        path = "/{id}",
        tag = ALERTS_TAG,
        responses(
            (status = 200, description = "Alert deleted successfully", content_type = "application/json"),
            (status = 401, description = "Unauthorized - invalid or missing token", content_type = "application/json"),
            (status = 404, description = "Alert not found", content_type = "application/json"),
            (status = 500, description = "Internal server error", content_type = "application/json")
        )
    )]
    async fn delete_alert(
        Extension(resources): Extension<AppResources>,
        State(state): State<AlertAppState>,
        Path(id): Path<String>,
        headers: HeaderMap,
    ) -> impl IntoResponse {
        // Get token from Authorization header
        let token = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "));
        if token.is_none() {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Missing or invalid Authorization header"})),
            );
        }
        let token = token.unwrap();
        // Find alert by token
        let found = alert::Entity::find()
            .filter(alert::Column::MagicToken.eq(token))
            .one(resources.db.as_ref())
            .await;
        let found = match found {
            Ok(Some(a)) => a,
            _ => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error": "Invalid token"})),
                );
            }
        };
        // Only allow deleting alerts for this email
        let del = alert::Entity::delete_many()
            .filter(alert::Column::Id.eq(id.clone()))
            .filter(alert::Column::Email.eq(found.email.clone()))
            .exec(resources.db.as_ref())
            .await;
        if del.is_ok() {
            use uuid::Uuid;
            if let Ok(uuid) = Uuid::parse_str(&id) {
                state.task_manager.stop_task(uuid).await;
            }
        }
        match del {
            Ok(_) => (StatusCode::OK, Json(json!({"status": "deleted"}))),
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
    responses(
        (status = OK, description = "Ok", body = str, content_type = "text/plain")
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

#[derive(OpenApi)]
#[openapi(
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
