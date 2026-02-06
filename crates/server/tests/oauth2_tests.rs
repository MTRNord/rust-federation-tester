//! OAuth2 endpoint tests.
//!
//! Tests for the OAuth2 authorization server endpoints.

use axum::{
    Extension, Router,
    routing::{get, post},
};
use axum_test::TestServer;
use rust_federation_tester::{
    AppResources,
    config::{AppConfig, OAuth2Config, SmtpConfig, StatisticsConfig},
    oauth2::OAuth2State,
};
use sea_orm::{
    ColumnTrait, ConnectionTrait, Database, DatabaseConnection, DbBackend, QueryFilter, Statement,
};
use std::sync::Arc;

/// Create a test database with OAuth2 tables
async fn create_oauth2_test_db() -> DatabaseConnection {
    let db = Database::connect("sqlite::memory:").await.expect("connect");

    // Create oauth2_client table
    db.execute(Statement::from_string(
        DbBackend::Sqlite,
        r#"CREATE TABLE oauth2_client (
            id TEXT PRIMARY KEY,
            secret TEXT NULL,
            name TEXT NOT NULL,
            redirect_uris TEXT NOT NULL,
            grant_types TEXT NOT NULL DEFAULT 'authorization_code',
            scopes TEXT NOT NULL DEFAULT 'openid profile email',
            is_public INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );"#,
    ))
    .await
    .expect("create oauth2_client table");

    // Create oauth2_user table
    db.execute(Statement::from_string(
        DbBackend::Sqlite,
        r#"CREATE TABLE oauth2_user (
            id TEXT PRIMARY KEY,
            email TEXT NOT NULL UNIQUE,
            email_verified INTEGER NOT NULL DEFAULT 0,
            name TEXT NULL,
            created_at TEXT NOT NULL,
            last_login_at TEXT NULL,
            password_hash TEXT NULL,
            email_verification_token TEXT NULL,
            email_verification_expires_at TEXT NULL
        );"#,
    ))
    .await
    .expect("create oauth2_user table");

    // Create oauth2_authorization table
    db.execute(Statement::from_string(
        DbBackend::Sqlite,
        r#"CREATE TABLE oauth2_authorization (
            code TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            redirect_uri TEXT NOT NULL,
            scope TEXT NOT NULL,
            state TEXT NULL,
            nonce TEXT NULL,
            code_challenge TEXT NULL,
            code_challenge_method TEXT NULL,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL
        );"#,
    ))
    .await
    .expect("create oauth2_authorization table");

    // Create oauth2_token table
    db.execute(Statement::from_string(
        DbBackend::Sqlite,
        r#"CREATE TABLE oauth2_token (
            id TEXT PRIMARY KEY,
            access_token TEXT NOT NULL UNIQUE,
            refresh_token TEXT UNIQUE,
            token_type TEXT NOT NULL DEFAULT 'Bearer',
            client_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            scope TEXT NOT NULL,
            access_token_expires_at TEXT NOT NULL,
            refresh_token_expires_at TEXT NULL,
            created_at TEXT NOT NULL,
            revoked_at TEXT NULL
        );"#,
    ))
    .await
    .expect("create oauth2_token table");

    // Insert a test client (redirect_uris must be JSON array)
    db.execute(Statement::from_string(
        DbBackend::Sqlite,
        r#"INSERT INTO oauth2_client (id, secret, name, redirect_uris, grant_types, scopes, is_public, created_at, updated_at)
           VALUES ('test-client', NULL, 'Test Client', '["http://localhost:3000/callback"]', 'authorization_code refresh_token', 'openid profile email', 1, datetime('now'), datetime('now'));"#,
    ))
    .await
    .expect("insert test client");

    // Insert a confidential client (redirect_uris must be JSON array)
    db.execute(Statement::from_string(
        DbBackend::Sqlite,
        r#"INSERT INTO oauth2_client (id, secret, name, redirect_uris, grant_types, scopes, is_public, created_at, updated_at)
           VALUES ('confidential-client', 'secret123', 'Confidential Client', '["http://localhost:3000/callback"]', 'authorization_code', 'openid', 0, datetime('now'), datetime('now'));"#,
    ))
    .await
    .expect("insert confidential client");

    // Insert a test user
    db.execute(Statement::from_string(
        DbBackend::Sqlite,
        r#"INSERT INTO oauth2_user (id, email, email_verified, name, created_at)
           VALUES ('user-123', 'test@example.com', 1, 'Test User', datetime('now'));"#,
    ))
    .await
    .expect("insert test user");

    db
}

fn create_test_config() -> AppConfig {
    AppConfig {
        database_url: "sqlite::memory:".into(),
        smtp: SmtpConfig {
            server: "localhost".into(),
            port: 25,
            username: "test".into(),
            password: "test".into(),
            from: "noreply@test.example.org".into(),
        },
        frontend_url: "http://localhost:3000".into(),
        magic_token_secret: "12345678901234567890123456789012".into(),
        debug_allowed_nets: vec![],
        statistics: StatisticsConfig::default(),
        oauth2: OAuth2Config {
            enabled: true,
            issuer_url: "http://localhost:8080".into(),
            access_token_lifetime: 3600,
            refresh_token_lifetime: 86400,
            magic_links_enabled: true,
        },
    }
}

async fn create_test_resources() -> (AppResources, OAuth2State) {
    let db = create_oauth2_test_db().await;
    let db = Arc::new(db);
    let config = Arc::new(create_test_config());
    let mailer = Arc::new(
        lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::builder_dangerous("localhost")
            .build(),
    );

    let resources = AppResources {
        db: db.clone(),
        mailer,
        config: config.clone(),
    };

    let oauth2_state = OAuth2State::new(db, config.oauth2.issuer_url.clone());

    (resources, oauth2_state)
}

// =============================================================================
// Authorization Endpoint Tests
// =============================================================================

#[tokio::test]
async fn test_authorize_invalid_response_type() {
    use rust_federation_tester::oauth2::endpoints::authorize;

    let (resources, oauth2_state) = create_test_resources().await;

    let app: Router = Router::new()
        .route("/authorize", get(authorize))
        .with_state(oauth2_state)
        .layer(Extension(resources));
    let server = TestServer::new(app).expect("create test server");

    let response = server
        .get("/authorize")
        .add_query_param("response_type", "token") // Invalid - should be "code"
        .add_query_param("client_id", "test-client")
        .add_query_param("redirect_uri", "http://localhost:3000/callback")
        .await;

    // Should redirect with error
    response.assert_status_see_other();
}

#[tokio::test]
async fn test_authorize_invalid_client() {
    use rust_federation_tester::oauth2::endpoints::authorize;

    let (resources, oauth2_state) = create_test_resources().await;

    let app: Router = Router::new()
        .route("/authorize", get(authorize))
        .with_state(oauth2_state)
        .layer(Extension(resources));
    let server = TestServer::new(app).expect("create test server");

    let response = server
        .get("/authorize")
        .add_query_param("response_type", "code")
        .add_query_param("client_id", "nonexistent-client")
        .await;

    response.assert_status_bad_request();
    let body: serde_json::Value = response.json();
    assert_eq!(body["error"], "invalid_client");
}

#[tokio::test]
async fn test_authorize_invalid_redirect_uri() {
    use rust_federation_tester::oauth2::endpoints::authorize;

    let (resources, oauth2_state) = create_test_resources().await;

    let app: Router = Router::new()
        .route("/authorize", get(authorize))
        .with_state(oauth2_state)
        .layer(Extension(resources));
    let server = TestServer::new(app).expect("create test server");

    let response = server
        .get("/authorize")
        .add_query_param("response_type", "code")
        .add_query_param("client_id", "test-client")
        .add_query_param("redirect_uri", "http://evil.com/callback") // Not registered
        .await;

    response.assert_status_bad_request();
    let body: serde_json::Value = response.json();
    assert_eq!(body["error"], "invalid_request");
}

#[tokio::test]
async fn test_authorize_valid_request_redirects_to_login() {
    use rust_federation_tester::oauth2::endpoints::authorize;

    let (resources, oauth2_state) = create_test_resources().await;

    let app: Router = Router::new()
        .route("/authorize", get(authorize))
        .with_state(oauth2_state)
        .layer(Extension(resources));
    let server = TestServer::new(app).expect("create test server");

    let response = server
        .get("/authorize")
        .add_query_param("response_type", "code")
        .add_query_param("client_id", "test-client")
        .add_query_param("redirect_uri", "http://localhost:3000/callback")
        .add_query_param("scope", "openid profile")
        .add_query_param("state", "random-state")
        .await;

    // Should redirect to login page
    response.assert_status_see_other();
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .expect("location header");
    assert!(location.contains("/oauth2/login"));
    assert!(location.contains("client_id=test-client"));
}

#[tokio::test]
async fn test_authorize_with_pkce_and_nonce() {
    use rust_federation_tester::oauth2::endpoints::authorize;

    let (resources, oauth2_state) = create_test_resources().await;

    let app: Router = Router::new()
        .route("/authorize", get(authorize))
        .with_state(oauth2_state)
        .layer(Extension(resources));
    let server = TestServer::new(app).expect("create test server");

    let response = server
        .get("/authorize")
        .add_query_param("response_type", "code")
        .add_query_param("client_id", "test-client")
        .add_query_param("redirect_uri", "http://localhost:3000/callback")
        .add_query_param(
            "code_challenge",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        )
        .add_query_param("code_challenge_method", "S256")
        .add_query_param("nonce", "test-nonce-123")
        .add_query_param("login_hint", "user@example.com")
        .await;

    response.assert_status_see_other();
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .expect("location header");

    // Verify all parameters are passed through
    assert!(location.contains("code_challenge="));
    assert!(location.contains("nonce=test-nonce-123"));
    assert!(location.contains("login_hint=user%40example.com"));
}

// =============================================================================
// Token Endpoint Tests
// =============================================================================

#[tokio::test]
async fn test_token_missing_client_id() {
    use rust_federation_tester::oauth2::endpoints::token;

    let (_, oauth2_state) = create_test_resources().await;

    let app: Router = Router::new()
        .route("/token", post(token))
        .with_state(oauth2_state);
    let server = TestServer::new(app).expect("create test server");

    let response = server
        .post("/token")
        .form(&[("grant_type", "authorization_code"), ("code", "test-code")])
        .await;

    response.assert_status_bad_request();
    let body: serde_json::Value = response.json();
    assert_eq!(body["error"], "invalid_request");
}

#[tokio::test]
async fn test_token_invalid_client() {
    use rust_federation_tester::oauth2::endpoints::token;

    let (_, oauth2_state) = create_test_resources().await;

    let app: Router = Router::new()
        .route("/token", post(token))
        .with_state(oauth2_state);
    let server = TestServer::new(app).expect("create test server");

    let response = server
        .post("/token")
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", "test-code"),
            ("client_id", "nonexistent"),
        ])
        .await;

    response.assert_status_unauthorized();
    let body: serde_json::Value = response.json();
    assert_eq!(body["error"], "invalid_client");
}

#[tokio::test]
async fn test_token_unsupported_grant_type() {
    use rust_federation_tester::oauth2::endpoints::token;

    let (_, oauth2_state) = create_test_resources().await;

    let app: Router = Router::new()
        .route("/token", post(token))
        .with_state(oauth2_state);
    let server = TestServer::new(app).expect("create test server");

    let response = server
        .post("/token")
        .form(&[
            ("grant_type", "password"), // Unsupported
            ("client_id", "test-client"),
        ])
        .await;

    response.assert_status_bad_request();
    let body: serde_json::Value = response.json();
    assert_eq!(body["error"], "unsupported_grant_type");
}

#[tokio::test]
async fn test_token_authorization_code_not_found() {
    use rust_federation_tester::oauth2::endpoints::token;

    let (_, oauth2_state) = create_test_resources().await;

    let app: Router = Router::new()
        .route("/token", post(token))
        .with_state(oauth2_state);
    let server = TestServer::new(app).expect("create test server");

    let response = server
        .post("/token")
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", "nonexistent-code"),
            ("client_id", "test-client"),
        ])
        .await;

    response.assert_status_bad_request();
    let body: serde_json::Value = response.json();
    assert_eq!(body["error"], "invalid_grant");
}

#[tokio::test]
async fn test_token_refresh_not_found() {
    use rust_federation_tester::oauth2::endpoints::token;

    let (_, oauth2_state) = create_test_resources().await;

    let app: Router = Router::new()
        .route("/token", post(token))
        .with_state(oauth2_state);
    let server = TestServer::new(app).expect("create test server");

    let response = server
        .post("/token")
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", "nonexistent-token"),
            ("client_id", "test-client"),
        ])
        .await;

    response.assert_status_bad_request();
    let body: serde_json::Value = response.json();
    assert_eq!(body["error"], "invalid_grant");
}

// =============================================================================
// Revoke Endpoint Tests
// =============================================================================

#[tokio::test]
async fn test_revoke_nonexistent_token() {
    use rust_federation_tester::oauth2::endpoints::revoke;

    let (_, oauth2_state) = create_test_resources().await;

    let app: Router = Router::new()
        .route("/revoke", post(revoke))
        .with_state(oauth2_state);
    let server = TestServer::new(app).expect("create test server");

    // Per RFC 7009, should return 200 even for nonexistent tokens
    let response = server
        .post("/revoke")
        .form(&[("token", "nonexistent-token")])
        .await;

    response.assert_status_ok();
}

#[tokio::test]
async fn test_revoke_with_token_type_hint_access() {
    use rust_federation_tester::oauth2::endpoints::revoke;

    let (_, oauth2_state) = create_test_resources().await;

    let app: Router = Router::new()
        .route("/revoke", post(revoke))
        .with_state(oauth2_state);
    let server = TestServer::new(app).expect("create test server");

    let response = server
        .post("/revoke")
        .form(&[("token", "some-token"), ("token_type_hint", "access_token")])
        .await;

    response.assert_status_ok();
}

#[tokio::test]
async fn test_revoke_with_token_type_hint_refresh() {
    use rust_federation_tester::oauth2::endpoints::revoke;

    let (_, oauth2_state) = create_test_resources().await;

    let app: Router = Router::new()
        .route("/revoke", post(revoke))
        .with_state(oauth2_state);
    let server = TestServer::new(app).expect("create test server");

    let response = server
        .post("/revoke")
        .form(&[
            ("token", "some-token"),
            ("token_type_hint", "refresh_token"),
        ])
        .await;

    response.assert_status_ok();
}

#[tokio::test]
async fn test_revoke_with_unknown_token_type_hint() {
    use rust_federation_tester::oauth2::endpoints::revoke;

    let (_, oauth2_state) = create_test_resources().await;

    let app: Router = Router::new()
        .route("/revoke", post(revoke))
        .with_state(oauth2_state);
    let server = TestServer::new(app).expect("create test server");

    // RFC 7009: Server should ignore unknown hints
    let response = server
        .post("/revoke")
        .form(&[("token", "some-token"), ("token_type_hint", "unknown_type")])
        .await;

    response.assert_status_ok();
}

// =============================================================================
// UserInfo Endpoint Tests
// =============================================================================

#[tokio::test]
async fn test_userinfo_missing_token() {
    use rust_federation_tester::oauth2::endpoints::userinfo;

    let (_, oauth2_state) = create_test_resources().await;

    let app: Router = Router::new()
        .route("/userinfo", get(userinfo))
        .with_state(oauth2_state);
    let server = TestServer::new(app).expect("create test server");

    let response = server.get("/userinfo").await;

    response.assert_status_unauthorized();
    let body: serde_json::Value = response.json();
    assert_eq!(body["error"], "invalid_token");
}

#[tokio::test]
async fn test_userinfo_invalid_token() {
    use rust_federation_tester::oauth2::endpoints::userinfo;

    let (_, oauth2_state) = create_test_resources().await;

    let app: Router = Router::new()
        .route("/userinfo", get(userinfo))
        .with_state(oauth2_state);
    let server = TestServer::new(app).expect("create test server");

    let response = server
        .get("/userinfo")
        .add_header(
            axum::http::header::AUTHORIZATION,
            axum::http::HeaderValue::from_static("Bearer invalid-token"),
        )
        .await;

    response.assert_status_unauthorized();
    let body: serde_json::Value = response.json();
    assert_eq!(body["error"], "invalid_token");
}

// =============================================================================
// OpenID Configuration Tests
// =============================================================================

#[tokio::test]
async fn test_openid_configuration() {
    use rust_federation_tester::oauth2::endpoints::openid_configuration;

    let (_, oauth2_state) = create_test_resources().await;

    let app: Router = Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(openid_configuration),
        )
        .with_state(oauth2_state);
    let server = TestServer::new(app).expect("create test server");

    let response = server.get("/.well-known/openid-configuration").await;

    response.assert_status_ok();
    let body: serde_json::Value = response.json();

    assert_eq!(body["issuer"], "http://localhost:8080");
    assert!(
        body["authorization_endpoint"]
            .as_str()
            .unwrap()
            .contains("/authorize")
    );
    assert!(body["token_endpoint"].as_str().unwrap().contains("/token"));
    assert!(
        body["userinfo_endpoint"]
            .as_str()
            .unwrap()
            .contains("/userinfo")
    );
    assert!(
        body["revocation_endpoint"]
            .as_str()
            .unwrap()
            .contains("/revoke")
    );

    // Check supported values
    let response_types = body["response_types_supported"].as_array().unwrap();
    assert!(response_types.iter().any(|v| v == "code"));

    let grant_types = body["grant_types_supported"].as_array().unwrap();
    assert!(grant_types.iter().any(|v| v == "authorization_code"));
    assert!(grant_types.iter().any(|v| v == "refresh_token"));

    let scopes = body["scopes_supported"].as_array().unwrap();
    assert!(scopes.iter().any(|v| v == "openid"));

    let code_challenge_methods = body["code_challenge_methods_supported"].as_array().unwrap();
    assert!(code_challenge_methods.iter().any(|v| v == "S256"));
}

// =============================================================================
// OAuth2State Tests
// =============================================================================

#[tokio::test]
async fn test_oauth2_state_generate_token() {
    let token1 = OAuth2State::generate_token();
    let token2 = OAuth2State::generate_token();

    // Tokens should be unique
    assert_ne!(token1, token2);

    // Tokens should be base64 encoded (URL safe)
    assert!(
        token1
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    );

    // Tokens should be 43 characters (32 bytes base64 encoded without padding)
    assert_eq!(token1.len(), 43);
}

#[tokio::test]
async fn test_oauth2_state_get_or_create_user() {
    let db = create_oauth2_test_db().await;
    let db = Arc::new(db);
    let state = OAuth2State::new(db, "http://localhost".into());

    // Create new user
    let user1 = state.get_or_create_user("new@example.com").await.unwrap();
    assert_eq!(user1.email, "new@example.com");
    assert!(!user1.email_verified);

    // Get existing user
    let user2 = state.get_or_create_user("new@example.com").await.unwrap();
    assert_eq!(user1.id, user2.id);

    // Get pre-existing user
    let existing = state.get_or_create_user("test@example.com").await.unwrap();
    assert_eq!(existing.id, "user-123");
}

#[tokio::test]
async fn test_oauth2_state_verify_user_email() {
    let db = create_oauth2_test_db().await;
    let db = Arc::new(db);
    let state = OAuth2State::new(db.clone(), "http://localhost".into());

    // Create unverified user
    let user = state
        .get_or_create_user("unverified@example.com")
        .await
        .unwrap();
    assert!(!user.email_verified);

    // Verify email
    state.verify_user_email(&user.id).await.unwrap();

    // Check user is now verified
    use rust_federation_tester::entity::oauth2_user;
    use sea_orm::EntityTrait;
    let updated = oauth2_user::Entity::find_by_id(&user.id)
        .one(db.as_ref())
        .await
        .unwrap()
        .unwrap();
    assert!(updated.email_verified);
}

#[tokio::test]
async fn test_oauth2_state_update_last_login() {
    let db = create_oauth2_test_db().await;
    let db = Arc::new(db);
    let state = OAuth2State::new(db.clone(), "http://localhost".into());

    // Create user
    let user = state.get_or_create_user("login@example.com").await.unwrap();
    assert!(user.last_login_at.is_none());

    // Update last login
    state.update_last_login(&user.id).await.unwrap();

    // Check last login is set
    use rust_federation_tester::entity::oauth2_user;
    use sea_orm::EntityTrait;
    let updated = oauth2_user::Entity::find_by_id(&user.id)
        .one(db.as_ref())
        .await
        .unwrap()
        .unwrap();
    assert!(updated.last_login_at.is_some());
}

// =============================================================================
// Successful Token Exchange Tests
// =============================================================================

/// Helper to create an authorization code in the test database
async fn create_test_authorization(db: &DatabaseConnection) {
    use time::OffsetDateTime;
    let now = OffsetDateTime::now_utc();
    let expires = now + time::Duration::minutes(10);

    db.execute(Statement::from_string(
        DbBackend::Sqlite,
        format!(
            r#"INSERT INTO oauth2_authorization (code, client_id, user_id, redirect_uri, scope, state, nonce, code_challenge, code_challenge_method, expires_at, created_at)
               VALUES ('valid-auth-code', 'test-client', 'user-123', 'http://localhost:3000/callback', 'openid profile email', 'test-state', NULL, NULL, NULL, '{}', '{}')"#,
            expires.format(&time::format_description::well_known::Rfc3339).unwrap(),
            now.format(&time::format_description::well_known::Rfc3339).unwrap()
        ),
    ))
    .await
    .expect("insert authorization code");
}

/// Helper to create a valid token in the test database
async fn create_test_token(db: &DatabaseConnection) {
    use time::OffsetDateTime;
    let now = OffsetDateTime::now_utc();
    let access_expires = now + time::Duration::hours(1);
    let refresh_expires = now + time::Duration::days(7);

    db.execute(Statement::from_string(
        DbBackend::Sqlite,
        format!(
            r#"INSERT INTO oauth2_token (id, access_token, refresh_token, token_type, client_id, user_id, scope, access_token_expires_at, refresh_token_expires_at, created_at, revoked_at)
               VALUES ('token-id-1', 'valid-access-token', 'valid-refresh-token', 'Bearer', 'test-client', 'user-123', 'openid profile email', '{}', '{}', '{}', NULL)"#,
            access_expires.format(&time::format_description::well_known::Rfc3339).unwrap(),
            refresh_expires.format(&time::format_description::well_known::Rfc3339).unwrap(),
            now.format(&time::format_description::well_known::Rfc3339).unwrap()
        ),
    ))
    .await
    .expect("insert test token");
}

#[tokio::test]
async fn test_token_authorization_code_success() {
    use rust_federation_tester::oauth2::endpoints::token;

    let db = create_oauth2_test_db().await;
    create_test_authorization(&db).await;
    let db = Arc::new(db);
    let oauth2_state = OAuth2State::new(db, "http://localhost:8080".into());

    let app: Router = Router::new()
        .route("/token", post(token))
        .with_state(oauth2_state);
    let server = TestServer::new(app).expect("create test server");

    let response = server
        .post("/token")
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", "valid-auth-code"),
            ("client_id", "test-client"),
            ("redirect_uri", "http://localhost:3000/callback"),
        ])
        .await;

    response.assert_status_ok();
    let body: serde_json::Value = response.json();
    assert!(body["access_token"].as_str().is_some());
    assert_eq!(body["token_type"], "Bearer");
    assert!(body["expires_in"].as_i64().unwrap() > 0);
    assert!(body["refresh_token"].as_str().is_some());
    assert!(body["scope"].as_str().is_some());
}

#[tokio::test]
async fn test_token_refresh_success() {
    use rust_federation_tester::oauth2::endpoints::token;

    let db = create_oauth2_test_db().await;
    create_test_token(&db).await;
    let db = Arc::new(db);
    let oauth2_state = OAuth2State::new(db, "http://localhost:8080".into());

    let app: Router = Router::new()
        .route("/token", post(token))
        .with_state(oauth2_state);
    let server = TestServer::new(app).expect("create test server");

    let response = server
        .post("/token")
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", "valid-refresh-token"),
            ("client_id", "test-client"),
        ])
        .await;

    response.assert_status_ok();
    let body: serde_json::Value = response.json();
    assert!(body["access_token"].as_str().is_some());
    assert_eq!(body["token_type"], "Bearer");
    // New access token should be different from old one
    assert_ne!(body["access_token"], "valid-access-token");
}

#[tokio::test]
async fn test_userinfo_with_valid_token() {
    use rust_federation_tester::oauth2::endpoints::userinfo;

    let db = create_oauth2_test_db().await;
    create_test_token(&db).await;
    let db = Arc::new(db);
    let oauth2_state = OAuth2State::new(db, "http://localhost:8080".into());

    let app: Router = Router::new()
        .route("/userinfo", get(userinfo))
        .with_state(oauth2_state);
    let server = TestServer::new(app).expect("create test server");

    let response = server
        .get("/userinfo")
        .add_header(
            axum::http::header::AUTHORIZATION,
            axum::http::HeaderValue::from_static("Bearer valid-access-token"),
        )
        .await;

    response.assert_status_ok();
    let body: serde_json::Value = response.json();
    assert_eq!(body["sub"], "user-123");
    assert_eq!(body["email"], "test@example.com");
    assert_eq!(body["email_verified"], true);
    assert_eq!(body["name"], "Test User");
}

#[tokio::test]
async fn test_revoke_existing_token() {
    use rust_federation_tester::oauth2::endpoints::revoke;

    let db = create_oauth2_test_db().await;
    create_test_token(&db).await;
    let db = Arc::new(db);
    let oauth2_state = OAuth2State::new(db.clone(), "http://localhost:8080".into());

    let app: Router = Router::new()
        .route("/revoke", post(revoke))
        .with_state(oauth2_state);
    let server = TestServer::new(app).expect("create test server");

    // Revoke the access token
    let response = server
        .post("/revoke")
        .form(&[
            ("token", "valid-access-token"),
            ("token_type_hint", "access_token"),
        ])
        .await;

    response.assert_status_ok();

    // Verify token is revoked (revoked_at should be set)
    use rust_federation_tester::entity::oauth2_token;
    use sea_orm::EntityTrait;
    let token = oauth2_token::Entity::find()
        .filter(oauth2_token::Column::AccessToken.eq("valid-access-token"))
        .one(db.as_ref())
        .await
        .unwrap()
        .unwrap();
    assert!(token.revoked_at.is_some());
}

#[tokio::test]
async fn test_token_confidential_client_with_basic_auth() {
    use base64::Engine;
    use rust_federation_tester::oauth2::endpoints::token;

    let db = create_oauth2_test_db().await;
    create_test_authorization(&db).await;
    // Update the auth code to use confidential client
    db.execute(Statement::from_string(
        DbBackend::Sqlite,
        r#"UPDATE oauth2_authorization SET client_id = 'confidential-client' WHERE code = 'valid-auth-code'"#,
    ))
    .await
    .expect("update auth code");

    let db = Arc::new(db);
    let oauth2_state = OAuth2State::new(db, "http://localhost:8080".into());

    let app: Router = Router::new()
        .route("/token", post(token))
        .with_state(oauth2_state);
    let server = TestServer::new(app).expect("create test server");

    // Use Basic auth header
    let credentials =
        base64::engine::general_purpose::STANDARD.encode("confidential-client:secret123");

    let response = server
        .post("/token")
        .add_header(
            axum::http::header::AUTHORIZATION,
            axum::http::HeaderValue::from_str(&format!("Basic {}", credentials)).unwrap(),
        )
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", "valid-auth-code"),
            ("redirect_uri", "http://localhost:3000/callback"),
        ])
        .await;

    response.assert_status_ok();
    let body: serde_json::Value = response.json();
    assert!(body["access_token"].as_str().is_some());
}

#[tokio::test]
async fn test_token_confidential_client_wrong_secret() {
    use rust_federation_tester::oauth2::endpoints::token;

    let (_, oauth2_state) = create_test_resources().await;

    let app: Router = Router::new()
        .route("/token", post(token))
        .with_state(oauth2_state);
    let server = TestServer::new(app).expect("create test server");

    let response = server
        .post("/token")
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", "some-code"),
            ("client_id", "confidential-client"),
            ("client_secret", "wrong-secret"),
        ])
        .await;

    response.assert_status_unauthorized();
    let body: serde_json::Value = response.json();
    assert_eq!(body["error"], "invalid_client");
}

// =============================================================================
// Authorization Code Validation Tests
// =============================================================================

#[tokio::test]
async fn test_token_authorization_code_expired() {
    use rust_federation_tester::oauth2::endpoints::token;
    use time::OffsetDateTime;

    let db = create_oauth2_test_db().await;

    // Create an expired authorization code
    let now = OffsetDateTime::now_utc();
    let expired = now - time::Duration::hours(1); // Already expired

    db.execute(Statement::from_string(
        DbBackend::Sqlite,
        format!(
            r#"INSERT INTO oauth2_authorization (code, client_id, user_id, redirect_uri, scope, state, nonce, code_challenge, code_challenge_method, expires_at, created_at)
               VALUES ('expired-auth-code', 'test-client', 'user-123', 'http://localhost:3000/callback', 'openid', NULL, NULL, NULL, NULL, '{}', '{}')"#,
            expired.format(&time::format_description::well_known::Rfc3339).unwrap(),
            now.format(&time::format_description::well_known::Rfc3339).unwrap()
        ),
    ))
    .await
    .expect("insert expired authorization code");

    let db = Arc::new(db);
    let oauth2_state = OAuth2State::new(db, "http://localhost:8080".into());

    let app: Router = Router::new()
        .route("/token", post(token))
        .with_state(oauth2_state);
    let server = TestServer::new(app).expect("create test server");

    let response = server
        .post("/token")
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", "expired-auth-code"),
            ("client_id", "test-client"),
        ])
        .await;

    response.assert_status_bad_request();
    let body: serde_json::Value = response.json();
    assert_eq!(body["error"], "invalid_grant");
    assert!(
        body["error_description"]
            .as_str()
            .unwrap()
            .contains("expired")
    );
}

#[tokio::test]
async fn test_token_authorization_code_client_mismatch() {
    use rust_federation_tester::oauth2::endpoints::token;

    let db = create_oauth2_test_db().await;
    create_test_authorization(&db).await; // Created for test-client
    let db = Arc::new(db);
    let oauth2_state = OAuth2State::new(db, "http://localhost:8080".into());

    let app: Router = Router::new()
        .route("/token", post(token))
        .with_state(oauth2_state);
    let server = TestServer::new(app).expect("create test server");

    // Try to use auth code with different client
    let response = server
        .post("/token")
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", "valid-auth-code"),
            ("client_id", "confidential-client"),
            ("client_secret", "secret123"),
        ])
        .await;

    response.assert_status_bad_request();
    let body: serde_json::Value = response.json();
    assert_eq!(body["error"], "invalid_grant");
}

#[tokio::test]
async fn test_token_authorization_code_redirect_uri_mismatch() {
    use rust_federation_tester::oauth2::endpoints::token;

    let db = create_oauth2_test_db().await;
    create_test_authorization(&db).await;
    let db = Arc::new(db);
    let oauth2_state = OAuth2State::new(db, "http://localhost:8080".into());

    let app: Router = Router::new()
        .route("/token", post(token))
        .with_state(oauth2_state);
    let server = TestServer::new(app).expect("create test server");

    let response = server
        .post("/token")
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", "valid-auth-code"),
            ("client_id", "test-client"),
            ("redirect_uri", "http://different.com/callback"), // Mismatch
        ])
        .await;

    response.assert_status_bad_request();
    let body: serde_json::Value = response.json();
    assert_eq!(body["error"], "invalid_grant");
}

// =============================================================================
// UserInfo Edge Cases
// =============================================================================

#[tokio::test]
async fn test_userinfo_insufficient_scope() {
    use rust_federation_tester::oauth2::endpoints::userinfo;
    use time::OffsetDateTime;

    let db = create_oauth2_test_db().await;

    // Create a token without openid scope
    let now = OffsetDateTime::now_utc();
    let access_expires = now + time::Duration::hours(1);

    db.execute(Statement::from_string(
        DbBackend::Sqlite,
        format!(
            r#"INSERT INTO oauth2_token (id, access_token, refresh_token, token_type, client_id, user_id, scope, access_token_expires_at, refresh_token_expires_at, created_at, revoked_at)
               VALUES ('token-no-openid', 'no-openid-token', NULL, 'Bearer', 'test-client', 'user-123', 'profile email', '{}', NULL, '{}', NULL)"#,
            access_expires.format(&time::format_description::well_known::Rfc3339).unwrap(),
            now.format(&time::format_description::well_known::Rfc3339).unwrap()
        ),
    ))
    .await
    .expect("insert token without openid scope");

    let db = Arc::new(db);
    let oauth2_state = OAuth2State::new(db, "http://localhost:8080".into());

    let app: Router = Router::new()
        .route("/userinfo", get(userinfo))
        .with_state(oauth2_state);
    let server = TestServer::new(app).expect("create test server");

    let response = server
        .get("/userinfo")
        .add_header(
            axum::http::header::AUTHORIZATION,
            axum::http::HeaderValue::from_static("Bearer no-openid-token"),
        )
        .await;

    response.assert_status_forbidden();
    let body: serde_json::Value = response.json();
    assert_eq!(body["error"], "insufficient_scope");
}
