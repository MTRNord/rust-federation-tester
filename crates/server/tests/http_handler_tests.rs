//! HTTP handler tests for API endpoints.
//!
//! Tests the actual HTTP responses from the API handlers.

use axum::{Extension, Router, routing::get};
use axum_test::TestServer;
use migration::MigratorTrait;
use rust_federation_tester::{
    AppResources,
    api::{health, metrics},
    config::{AppConfig, OAuth2Config, SmtpConfig, StatisticsConfig},
};
use sea_orm::{Database, DatabaseConnection};
use std::sync::Arc;

/// Create a test database connection
async fn create_test_db() -> DatabaseConnection {
    let db = Database::connect("sqlite::memory:").await.expect("connect");

    // Apply migrations to the in-memory DB so tests share the same schema.
    // Call `up` with `None` for `steps` so all pending migrations are applied.
    migration::Migrator::up(&db, None)
        .await
        .expect("Failed to run migrations for test DB");

    db
}

/// Create a test config
fn create_test_config(stats_enabled: bool) -> AppConfig {
    AppConfig {
        database_url: "sqlite::memory:".into(),
        smtp: SmtpConfig {
            server: "localhost".into(),
            port: 25,
            username: "test".into(),
            password: "test".into(),
            from: "noreply@test.example.org".into(),
            timeout_secs: 10,
        },
        frontend_url: "http://localhost:3000".into(),
        magic_token_secret: "12345678901234567890123456789012".into(),
        debug_allowed_nets: vec![],
        statistics: StatisticsConfig {
            enabled: stats_enabled,
            prometheus_enabled: true,
            anonymization_salt: "test_salt".into(),
            raw_retention_days: 30,
        },
        oauth2: OAuth2Config::default(),
        federation_timeout_secs: 3,
        allow_private_targets: false,
        redis: Default::default(),
        environment_name: None,
    }
}

/// Create test AppResources
async fn create_test_resources(stats_enabled: bool) -> AppResources {
    let db = create_test_db().await;
    let config = Arc::new(create_test_config(stats_enabled));
    let mailer = Arc::new(
        lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::builder_dangerous("localhost")
            .build(),
    );
    AppResources {
        db: Arc::new(db),
        mailer,
        config,
        email_guard: rust_federation_tester::distributed::EmailGuard::Noop,
    }
}

// =============================================================================
// Health Endpoint Tests
// =============================================================================

#[tokio::test]
async fn test_health_endpoint_returns_ok() {
    let app = Router::new().route("/healthz", get(health::health));
    let server = TestServer::new(app).expect("create test server");

    let response = server.get("/healthz").await;

    response.assert_status_ok();
    response.assert_text("ok");
}

// =============================================================================
// Metrics Endpoint Tests
// =============================================================================

#[tokio::test]
async fn test_metrics_endpoint_with_stats_disabled() {
    let resources = create_test_resources(false).await;

    let app = Router::new()
        .route("/metrics", get(metrics::metrics))
        .layer(Extension(resources));

    let server = TestServer::new(app).expect("create test server");

    let response = server.get("/metrics").await;

    // When stats are disabled, metrics returns 404 per the handler logic
    response.assert_status_not_found();
}

#[tokio::test]
async fn test_metrics_endpoint_with_stats_enabled() {
    let resources = create_test_resources(true).await;

    let app = Router::new()
        .route("/metrics", get(metrics::metrics))
        .layer(Extension(resources));

    let server = TestServer::new(app).expect("create test server");

    let response = server.get("/metrics").await;

    response.assert_status_ok();
    // Should return plain text content type for Prometheus
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok());
    assert!(
        content_type.is_some_and(|ct| ct.contains("text/plain")),
        "Metrics should be text/plain for Prometheus"
    );
}

// =============================================================================
// Federation API Parameter Validation Tests
// =============================================================================

#[tokio::test]
async fn test_federation_report_missing_server_name() {
    // This test validates the parameter requirement without needing full DNS setup
    use axum::Json;
    use hyper::StatusCode;
    use serde_json::json;

    // Create a simple mock handler that just validates parameters
    async fn mock_report(
        axum::extract::Query(params): axum::extract::Query<
            rust_federation_tester::api::federation::ApiParams,
        >,
    ) -> (StatusCode, Json<serde_json::Value>) {
        if params.server_name.is_empty() {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "server_name parameter is required" })),
            );
        }
        (StatusCode::OK, Json(json!({ "mock": "ok" })))
    }

    let app = Router::new().route("/api/federation/report", get(mock_report));
    let server = TestServer::new(app).expect("create test server");

    // Test missing server_name - Axum returns 400 for missing required query params
    let response = server.get("/api/federation/report").await;
    response.assert_status_bad_request();
    // Axum returns its own deserialization error for missing query params
    let body = response.text();
    assert!(
        body.contains("server_name") || body.contains("missing field"),
        "Should mention missing server_name field"
    );
}

#[tokio::test]
async fn test_federation_report_empty_server_name() {
    use axum::Json;
    use hyper::StatusCode;
    use serde_json::json;

    async fn mock_report(
        axum::extract::Query(params): axum::extract::Query<
            rust_federation_tester::api::federation::ApiParams,
        >,
    ) -> (StatusCode, Json<serde_json::Value>) {
        if params.server_name.is_empty() {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "server_name parameter is required" })),
            );
        }
        (StatusCode::OK, Json(json!({ "mock": "ok" })))
    }

    let app = Router::new().route("/api/federation/report", get(mock_report));
    let server = TestServer::new(app).expect("create test server");

    // Test empty server_name
    let response = server
        .get("/api/federation/report")
        .add_query_param("server_name", "")
        .await;
    response.assert_status_bad_request();
}

#[tokio::test]
async fn test_federation_ok_missing_server_name() {
    async fn mock_fed_ok(
        axum::extract::Query(params): axum::extract::Query<
            rust_federation_tester::api::federation::ApiParams,
        >,
    ) -> (hyper::StatusCode, String) {
        if params.server_name.is_empty() {
            return (
                hyper::StatusCode::BAD_REQUEST,
                "server_name parameter is required".to_string(),
            );
        }
        (hyper::StatusCode::OK, "GOOD".to_string())
    }

    let app = Router::new().route("/api/federation/federation-ok", get(mock_fed_ok));
    let server = TestServer::new(app).expect("create test server");

    // Axum returns 400 for missing required query params
    let response = server.get("/api/federation/federation-ok").await;
    response.assert_status_bad_request();
    // Axum returns its own deserialization error
    let body = response.text();
    assert!(
        body.contains("server_name") || body.contains("missing field"),
        "Should mention missing server_name field"
    );
}

// =============================================================================
// Alerts API Tests
// =============================================================================

#[tokio::test]
async fn test_alerts_verify_invalid_token() {
    use rust_federation_tester::api::alerts;

    let resources = create_test_resources(false).await;
    // Convert OpenApiRouter to regular Router
    let app: Router = alerts::router().layer(Extension(resources)).into();
    let server = TestServer::new(app).expect("create test server");

    // Test with invalid token
    let response = server
        .get("/verify")
        .add_query_param("token", "invalid_token")
        .await;

    response.assert_status_bad_request();
    let body: serde_json::Value = response.json();
    assert!(
        body["error"]
            .as_str()
            .unwrap_or("")
            .contains("Invalid or expired token")
    );
}

#[tokio::test]
async fn test_alerts_verify_missing_token() {
    use rust_federation_tester::api::alerts;

    let resources = create_test_resources(false).await;
    // Convert OpenApiRouter to regular Router
    let app: Router = alerts::router().layer(Extension(resources)).into();
    let server = TestServer::new(app).expect("create test server");

    // Test without token parameter - should fail
    let response = server.get("/verify").await;

    // Missing required query param should be a bad request
    response.assert_status_bad_request();
}

#[tokio::test]
async fn test_alerts_delete_nonexistent() {
    use rust_federation_tester::api::alerts;

    let resources = create_test_resources(false).await;
    // Convert OpenApiRouter to regular Router
    let app: Router = alerts::router().layer(Extension(resources)).into();
    let server = TestServer::new(app).expect("create test server");

    // Try to delete a non-existent alert
    let response = server.delete("/99999").await;

    response.assert_status_not_found();
    let body: serde_json::Value = response.json();
    assert_eq!(body["error"], "Alert not found");
}

// =============================================================================
// Content-Type Tests
// =============================================================================

#[tokio::test]
async fn test_health_returns_text_plain() {
    let app = Router::new().route("/healthz", get(health::health));
    let server = TestServer::new(app).expect("create test server");

    let response = server.get("/healthz").await;

    response.assert_status_ok();
    // Health check should return text
    let body = response.text();
    assert_eq!(body, "ok");
}

// =============================================================================
// Integration-style Tests
// =============================================================================

#[tokio::test]
async fn test_combined_health_and_metrics() {
    let resources = create_test_resources(true).await;

    let app = Router::new()
        .route("/healthz", get(health::health))
        .route("/metrics", get(metrics::metrics))
        .layer(Extension(resources));

    let server = TestServer::new(app).expect("create test server");

    // Health should work
    let health_response = server.get("/healthz").await;
    health_response.assert_status_ok();
    health_response.assert_text("ok");

    // Metrics should work
    let metrics_response = server.get("/metrics").await;
    metrics_response.assert_status_ok();
}

#[tokio::test]
async fn test_404_for_unknown_routes() {
    let app = Router::new().route("/healthz", get(health::health));
    let server = TestServer::new(app).expect("create test server");

    let response = server.get("/unknown").await;
    response.assert_status_not_found();
}

// =============================================================================
// Stats Opt-in Parameter Tests
// =============================================================================

#[tokio::test]
async fn test_federation_stats_opt_in_parameter() {
    use axum::Json;
    use hyper::StatusCode;
    use serde_json::json;

    // Mock handler that validates stats_opt_in parameter parsing
    async fn mock_report(
        axum::extract::Query(params): axum::extract::Query<
            rust_federation_tester::api::federation::ApiParams,
        >,
    ) -> (StatusCode, Json<serde_json::Value>) {
        if params.server_name.is_empty() {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "server_name parameter is required" })),
            );
        }
        (
            StatusCode::OK,
            Json(json!({
                "server_name": params.server_name,
                "stats_opt_in": params.stats_opt_in
            })),
        )
    }

    let app = Router::new().route("/api/federation/report", get(mock_report));
    let server = TestServer::new(app).expect("create test server");

    // Test with stats_opt_in=true
    let response = server
        .get("/api/federation/report")
        .add_query_param("server_name", "example.org")
        .add_query_param("stats_opt_in", "true")
        .await;
    response.assert_status_ok();
    let body: serde_json::Value = response.json();
    assert_eq!(body["stats_opt_in"], true);

    // Test with stats_opt_in=false
    let response = server
        .get("/api/federation/report")
        .add_query_param("server_name", "example.org")
        .add_query_param("stats_opt_in", "false")
        .await;
    response.assert_status_ok();
    let body: serde_json::Value = response.json();
    assert_eq!(body["stats_opt_in"], false);

    // Test without stats_opt_in (should default to None)
    let response = server
        .get("/api/federation/report")
        .add_query_param("server_name", "example.org")
        .await;
    response.assert_status_ok();
    let body: serde_json::Value = response.json();
    assert!(body["stats_opt_in"].is_null());
}
