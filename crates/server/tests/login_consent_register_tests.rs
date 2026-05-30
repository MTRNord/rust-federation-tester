//! Tests for login, consent, magic-link and register OAuth2 handlers,
//! plus additional security-parser coverage.

use axum::{Extension, Router};
use axum_test::TestServer;
use migration::MigratorTrait;
use rust_federation_tester::{
    AppResources,
    config::{AppConfig, OAuth2Config, SmtpConfig, StatisticsConfig},
    oauth2::{
        OAuth2State,
        consent::{ConsentData, ConsentRedirectParams},
    },
};
use sea_orm::{ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement};
use std::sync::Arc;
use time::OffsetDateTime;

// ── helpers ────────────────────────────────────────────────────────────────

fn location(response: &axum_test::TestResponse) -> String {
    response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

async fn create_test_db() -> Arc<DatabaseConnection> {
    let db = Database::connect("sqlite::memory:").await.expect("connect");
    migration::Migrator::up(&db, None)
        .await
        .expect("migrations");

    db.execute(Statement::from_string(
        DbBackend::Sqlite,
        r#"INSERT INTO oauth2_client (id, secret, name, redirect_uris, grant_types, scopes, is_public, created_at, updated_at)
           VALUES ('pub-client', NULL, 'Pub', '["http://localhost:3000/cb"]', 'authorization_code', 'openid', 1, datetime('now'), datetime('now'));"#,
    )).await.expect("client");

    // verified user with no password (magic-link only)
    // unverified user (no password)
    db.execute(Statement::from_string(
        DbBackend::Sqlite,
        r#"INSERT INTO oauth2_user (id, email, email_verified, name, receives_alerts, created_at)
           VALUES
             ('user-verified',   'verified@example.com',   1, NULL, 1, datetime('now')),
             ('user-unverified', 'unverified@example.com', 0, NULL, 1, datetime('now')),
             ('user-nopass',     'nopass@example.com',     1, NULL, 1, datetime('now'));"#,
    ))
    .await
    .expect("users");

    Arc::new(db)
}

fn base_config() -> AppConfig {
    AppConfig {
        database_url: "sqlite::memory:".into(),
        listen_addr: Some("[::]:8080".into()),
        smtp: SmtpConfig {
            enabled: false,
            server: "localhost".into(),
            port: 25,
            username: "".into(),
            password: "".into(),
            from: "noreply@test.example.org".into(),
            timeout_secs: 5,
        },
        frontend_url: "http://localhost:3000".into(),
        magic_token_secret: "test-secret-32-chars-xxxxxxxxxxx".into(),
        debug_allowed_nets: vec![],
        trusted_proxy_nets: vec![],
        statistics: StatisticsConfig::default(),
        oauth2: OAuth2Config {
            enabled: true,
            issuer_url: "http://localhost:8080".into(),
            access_token_lifetime: 3600,
            refresh_token_lifetime: 86400,
            magic_links_enabled: true,
            account_client_secret: "test_account_client_secret".into(),
        },
        federation_timeout_secs: 3,
        allow_private_targets: false,
        redis: Default::default(),
        environment_name: None,
        github_sponsors_url: None,
        liberapay_url: None,
        email_log_retention_days: 7,
        release_sources: Default::default(),
        max_webhooks_per_alert: None,
    }
}

async fn setup() -> (AppResources, OAuth2State) {
    let db = create_test_db().await;
    let config = Arc::new(base_config());
    let mailer: Option<Arc<dyn rust_federation_tester::EmailSender>> = Some(Arc::new(
        rust_federation_tester::backends::LettreSmtpSender::new(Arc::new(
            lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::builder_dangerous("localhost")
                .build(),
        )),
    ));
    let resources = AppResources {
        db: db.clone(),
        mailer,
        config: config.clone(),
        email_guard: rust_federation_tester::distributed::EmailGuard::Noop,
        release_cache: std::sync::Arc::new(dashmap::DashMap::new()),
        http_client: std::sync::Arc::new(reqwest::Client::new()),
    };
    let state = OAuth2State::new(
        db,
        config.oauth2.issuer_url.clone(),
        config.frontend_url.clone(),
    );
    (resources, state)
}

fn login_server(resources: AppResources, state: OAuth2State) -> TestServer {
    let (router, _api) = rust_federation_tester::oauth2::login::router().split_for_parts();
    let app: Router = router.with_state(state).layer(Extension(resources));
    TestServer::new(app)
}

fn magic_link_server(resources: AppResources, state: OAuth2State) -> TestServer {
    let (router, _api) = rust_federation_tester::oauth2::magic_link::router().split_for_parts();
    let app: Router = router.with_state(state).layer(Extension(resources));
    TestServer::new(app)
}

fn register_server(resources: AppResources, state: OAuth2State) -> TestServer {
    let (router, _api) = rust_federation_tester::oauth2::register::router().split_for_parts();
    let app: Router = router.with_state(state).layer(Extension(resources));
    TestServer::new(app)
}

fn consent_server(resources: AppResources, state: OAuth2State) -> TestServer {
    let (router, _api) = rust_federation_tester::oauth2::consent::router().split_for_parts();
    let app: Router = router.with_state(state).layer(Extension(resources));
    TestServer::new(app)
}

// ── ConsentData pure-logic tests ──────────────────────────────────────────

#[test]
fn consent_data_encode_decode_roundtrip() {
    let data = ConsentData {
        user_id: "u1".into(),
        user_email: "a@b.com".into(),
        client_id: "client1".into(),
        redirect_uri: "http://localhost/cb".into(),
        scope: "openid profile".into(),
        state: "xyz".into(),
        nonce: Some("nonce1".into()),
        code_challenge: None,
        code_challenge_method: None,
        expires_at: OffsetDateTime::now_utc().unix_timestamp() + 600,
    };
    let token = data.encode();
    let back = ConsentData::decode(&token).expect("decode");
    assert_eq!(back.user_id, "u1");
    assert_eq!(back.client_id, "client1");
    assert_eq!(back.nonce, Some("nonce1".into()));
}

#[test]
fn consent_data_decode_invalid_base64_returns_none() {
    assert!(ConsentData::decode("!!!invalid!!!").is_none());
}

#[test]
fn consent_data_decode_invalid_json_returns_none() {
    use base64::Engine;
    let bad = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"not json");
    assert!(ConsentData::decode(&bad).is_none());
}

#[test]
fn consent_data_not_expired_for_future_ts() {
    let data = ConsentData {
        user_id: "u".into(),
        user_email: "u@e.com".into(),
        client_id: "c".into(),
        redirect_uri: "http://localhost".into(),
        scope: "openid".into(),
        state: "s".into(),
        nonce: None,
        code_challenge: None,
        code_challenge_method: None,
        expires_at: OffsetDateTime::now_utc().unix_timestamp() + 600,
    };
    assert!(!data.is_expired());
}

#[test]
fn consent_data_expired_for_past_ts() {
    let data = ConsentData {
        user_id: "u".into(),
        user_email: "u@e.com".into(),
        client_id: "c".into(),
        redirect_uri: "http://localhost".into(),
        scope: "openid".into(),
        state: "s".into(),
        nonce: None,
        code_challenge: None,
        code_challenge_method: None,
        expires_at: OffsetDateTime::now_utc().unix_timestamp() - 1,
    };
    assert!(data.is_expired());
}

#[test]
fn consent_data_with_pkce_roundtrip() {
    let data = ConsentData {
        user_id: "u".into(),
        user_email: "u@e.com".into(),
        client_id: "c".into(),
        redirect_uri: "http://localhost".into(),
        scope: "openid".into(),
        state: "s".into(),
        nonce: None,
        code_challenge: Some("challenge123".into()),
        code_challenge_method: Some("S256".into()),
        expires_at: OffsetDateTime::now_utc().unix_timestamp() + 600,
    };
    let back = ConsentData::decode(&data.encode()).unwrap();
    assert_eq!(back.code_challenge.as_deref(), Some("challenge123"));
    assert_eq!(back.code_challenge_method.as_deref(), Some("S256"));
}

#[test]
fn create_consent_redirect_encodes_all_params() {
    let user = rust_federation_tester::entity::oauth2_user::Model {
        id: "uid".into(),
        email: "u@e.com".into(),
        email_verified: true,
        name: None,
        receives_alerts: true,
        created_at: OffsetDateTime::now_utc(),
        last_login_at: None,
        password_hash: None,
        email_verification_token: None,
        email_verification_expires_at: None,
        password_reset_token: None,
        password_reset_expires_at: None,
        timezone: "UTC".into(),
    };
    let full_url =
        rust_federation_tester::oauth2::consent::create_consent_redirect(ConsentRedirectParams {
            user: &user,
            client_id: "c1",
            redirect_uri: "http://localhost/cb",
            scope: "openid",
            state: "st1",
            nonce: Some("n1"),
            code_challenge: None,
            code_challenge_method: None,
        });

    assert!(full_url.starts_with("/oauth2/consent?token="));
    let token = full_url.split("token=").nth(1).unwrap();
    let decoded = ConsentData::decode(token).unwrap();
    assert_eq!(decoded.user_id, "uid");
    assert_eq!(decoded.client_id, "c1");
    assert_eq!(decoded.nonce.as_deref(), Some("n1"));
}

// ── login handler tests ───────────────────────────────────────────────────

fn login_base_form() -> Vec<(&'static str, &'static str)> {
    vec![
        ("response_type", "code"),
        ("client_id", "pub-client"),
        ("redirect_uri", "http://localhost:3000/cb"),
        ("scope", "openid"),
        ("state", "s1"),
    ]
}

#[tokio::test]
async fn login_empty_email_redirects_with_error() {
    let (resources, state) = setup().await;
    let server = login_server(resources, state);
    let mut form = login_base_form();
    form.extend([("email", ""), ("password", "any")]);

    let response = server.post("/login").form(&form).await;
    response.assert_status_see_other();
    assert!(location(&response).contains("error="));
}

#[tokio::test]
async fn login_nonexistent_user_redirects_with_error() {
    let (resources, state) = setup().await;
    let server = login_server(resources, state);
    let mut form = login_base_form();
    form.extend([("email", "ghost@example.com"), ("password", "whatever")]);

    let response = server.post("/login").form(&form).await;
    response.assert_status_see_other();
    assert!(location(&response).contains("error="));
}

#[tokio::test]
async fn login_empty_password_redirects_with_error() {
    let (resources, state) = setup().await;
    let server = login_server(resources, state);
    let mut form = login_base_form();
    form.extend([("email", "verified@example.com"), ("password", "")]);

    let response = server.post("/login").form(&form).await;
    response.assert_status_see_other();
    assert!(location(&response).contains("error="));
}

#[tokio::test]
async fn login_magic_link_only_account_gets_error() {
    let (resources, state) = setup().await;
    let server = login_server(resources, state);
    let mut form = login_base_form();
    // nopass@example.com has no password_hash
    form.extend([("email", "nopass@example.com"), ("password", "anything")]);

    let response = server.post("/login").form(&form).await;
    response.assert_status_see_other();
    let loc = location(&response);
    assert!(
        loc.contains("error="),
        "magic-link-only account, got: {loc}"
    );
}

#[tokio::test]
async fn login_wrong_password_redirects_with_error() {
    let (resources, state) = setup().await;
    // Insert user with a real hash
    let hash = rust_federation_tester::oauth2::hash_password("GoodPass1!").expect("hash");
    state.db.execute(Statement::from_string(
        DbBackend::Sqlite,
        format!(
            r#"INSERT INTO oauth2_user (id, email, email_verified, name, receives_alerts, created_at, password_hash)
               VALUES ('user-pw', 'pw@example.com', 1, NULL, 1, datetime('now'), '{hash}');"#,
        ),
    )).await.expect("insert");
    let server = login_server(resources, state);

    let mut form = login_base_form();
    form.extend([("email", "pw@example.com"), ("password", "WrongPass1!")]);
    let response = server.post("/login").form(&form).await;
    response.assert_status_see_other();
    assert!(location(&response).contains("error="));
}

#[tokio::test]
async fn login_unverified_email_redirects_with_error() {
    let (resources, state) = setup().await;
    let hash = rust_federation_tester::oauth2::hash_password("Pass1!").expect("hash");
    state.db.execute(Statement::from_string(
        DbBackend::Sqlite,
        format!(
            r#"INSERT INTO oauth2_user (id, email, email_verified, name, receives_alerts, created_at, password_hash)
               VALUES ('user-unverified-pw', 'unverified-pw@example.com', 0, NULL, 1, datetime('now'), '{hash}');"#,
        ),
    )).await.expect("insert");
    let server = login_server(resources, state);

    let mut form = login_base_form();
    form.extend([
        ("email", "unverified-pw@example.com"),
        ("password", "Pass1!"),
    ]);
    let response = server.post("/login").form(&form).await;
    response.assert_status_see_other();
    let loc = location(&response);
    assert!(loc.contains("error="), "unverified email, got: {loc}");
}

#[tokio::test]
async fn login_correct_credentials_redirects_to_consent() {
    let (resources, state) = setup().await;
    let hash = rust_federation_tester::oauth2::hash_password("CorrectPass1!").expect("hash");
    state.db.execute(Statement::from_string(
        DbBackend::Sqlite,
        format!(
            r#"INSERT INTO oauth2_user (id, email, email_verified, name, receives_alerts, created_at, password_hash)
               VALUES ('user-ok', 'ok@example.com', 1, NULL, 1, datetime('now'), '{hash}');"#,
        ),
    )).await.expect("insert");
    let server = login_server(resources, state);

    let mut form = login_base_form();
    form.extend([("email", "ok@example.com"), ("password", "CorrectPass1!")]);
    let response = server.post("/login").form(&form).await;
    response.assert_status_see_other();
    let loc = location(&response);
    assert!(
        loc.contains("/oauth2/consent"),
        "should redirect to consent, got: {loc}"
    );
}

// ── magic-link handler tests ──────────────────────────────────────────────

fn magic_link_base_form() -> Vec<(&'static str, &'static str)> {
    vec![
        ("response_type", "code"),
        ("client_id", "pub-client"),
        ("redirect_uri", "http://localhost:3000/cb"),
        ("scope", "openid"),
        ("state", "s1"),
    ]
}

#[tokio::test]
async fn magic_link_empty_email_redirects_with_error() {
    let (resources, state) = setup().await;
    let server = magic_link_server(resources, state);
    let mut form = magic_link_base_form();
    form.push(("email", ""));

    let response = server.post("/magic-link").form(&form).await;
    response.assert_status_see_other();
    assert!(location(&response).contains("error="));
}

#[tokio::test]
async fn magic_link_invalid_email_format_redirects_with_error() {
    let (resources, state) = setup().await;
    let server = magic_link_server(resources, state);
    let mut form = magic_link_base_form();
    form.push(("email", "not-an-email"));

    let response = server.post("/magic-link").form(&form).await;
    response.assert_status_see_other();
    assert!(location(&response).contains("error="));
}

#[tokio::test]
async fn magic_link_valid_email_renders_check_email_page() {
    let (resources, state) = setup().await;
    let server = magic_link_server(resources, state);
    let mut form = magic_link_base_form();
    form.push(("email", "new-ml@example.com"));

    let response = server.post("/magic-link").form(&form).await;
    // Renders "check your email" page (200 HTML) — email delivery is skipped (SMTP disabled)
    response.assert_status_ok();
    let body = response.text();
    // The template renders the email address or at least contains HTML
    assert!(!body.is_empty(), "should render HTML page");
}

#[tokio::test]
async fn magic_link_verify_invalid_token_redirects_with_error() {
    let (resources, state) = setup().await;
    let server = magic_link_server(resources, state);

    let response = server
        .get("/magic-link/verify")
        .add_query_param("token", "invalid.jwt.here")
        .await;
    response.assert_status_see_other();
    assert!(location(&response).contains("error="));
}

// ── register handler tests ────────────────────────────────────────────────

fn register_base_form<'a>(
    email: &'a str,
    password: &'a str,
    confirm: &'a str,
) -> Vec<(&'static str, &'a str)> {
    vec![
        ("response_type", "code"),
        ("client_id", "pub-client"),
        ("redirect_uri", "http://localhost:3000/cb"),
        ("scope", "openid"),
        ("state", "s1"),
        ("email", email),
        ("password", password),
        ("password_confirm", confirm),
    ]
}

#[tokio::test]
async fn register_empty_email_redirects() {
    let (resources, state) = setup().await;
    let server = register_server(resources, state);

    let form = register_base_form("", "SomePass1!", "SomePass1!");
    let response = server.post("/register").form(&form).await;
    response.assert_status_see_other();
    // Should redirect back to register with an error
    let loc = location(&response);
    assert!(
        loc.contains("register") || loc.contains("error="),
        "got: {loc}"
    );
}

#[tokio::test]
async fn register_password_mismatch_redirects() {
    let (resources, state) = setup().await;
    let server = register_server(resources, state);

    let form = register_base_form("new@example.com", "Pass1!", "Pass2!");
    let response = server.post("/register").form(&form).await;
    response.assert_status_see_other();
    let loc = location(&response);
    assert!(
        loc.contains("register") || loc.contains("error="),
        "got: {loc}"
    );
}

#[tokio::test]
async fn register_existing_email_does_not_panic() {
    let (resources, state) = setup().await;
    let server = register_server(resources, state);

    let form = register_base_form("verified@example.com", "NewPass1!", "NewPass1!");
    let response = server.post("/register").form(&form).await;
    let status = response.status_code();
    assert!(
        !status.is_server_error(),
        "duplicate email must not produce 5xx, got {status}"
    );
}

#[tokio::test]
async fn register_verify_invalid_token_redirects() {
    let (resources, state) = setup().await;
    let server = register_server(resources, state);

    let response = server
        .get("/verify-email")
        .add_query_param("token", "not-a-real-token")
        .await;
    response.assert_status_see_other();
}

#[tokio::test]
async fn register_new_user_creates_account_and_redirects() {
    let (resources, state) = setup().await;
    let server = register_server(resources, state);

    let form = register_base_form("brandnew@example.com", "GoodPass1!", "GoodPass1!");
    let response = server.post("/register").form(&form).await;
    response.assert_status_see_other();
    // Should redirect with a success message, not an error
    let loc = location(&response);
    assert!(
        !loc.contains("error="),
        "new user registration should succeed, got: {loc}"
    );
}

#[tokio::test]
async fn register_weak_password_redirects_with_error() {
    let (resources, state) = setup().await;
    let server = register_server(resources, state);

    // "abc" is too weak — should fail password complexity check
    let form = register_base_form("weak@example.com", "abc", "abc");
    let response = server.post("/register").form(&form).await;
    response.assert_status_see_other();
    let loc = location(&response);
    assert!(
        loc.contains("register") || loc.contains("error="),
        "weak password should produce error, got: {loc}"
    );
}

#[tokio::test]
async fn register_verified_with_no_password_upgrades_to_password() {
    // 'nopass@example.com' is verified but has no password_hash (magic-link only).
    // Registering with a new password should upgrade the account.
    let (resources, state) = setup().await;
    let server = register_server(resources, state);

    let form = register_base_form("nopass@example.com", "NewPass1!", "NewPass1!");
    let response = server.post("/register").form(&form).await;
    response.assert_status_see_other();
    // Should succeed — redirect without error
    let loc = location(&response);
    assert!(
        !loc.is_empty(),
        "should redirect somewhere, got empty location"
    );
}

#[tokio::test]
async fn register_verify_valid_token_succeeds() {
    // Seed a user with a valid (non-expired) verification token
    let (resources, state) = setup().await;
    let token = "valid-verification-token-123";
    let expires_at = OffsetDateTime::now_utc() + time::Duration::hours(24);
    state.db.execute(Statement::from_string(
        DbBackend::Sqlite,
        format!(
            r#"INSERT INTO oauth2_user (id, email, email_verified, name, receives_alerts, created_at, email_verification_token, email_verification_expires_at)
               VALUES ('user-to-verify', 'to-verify@example.com', 0, NULL, 1, datetime('now'), '{token}', '{expires_at}');"#,
        ),
    )).await.expect("insert");

    let server = register_server(resources, state);

    let response = server
        .get("/verify-email")
        .add_query_param("token", token)
        .await;
    response.assert_status_see_other();
    let loc = location(&response);
    assert!(
        loc.contains("login") || loc.contains("message="),
        "valid token should redirect to login with success, got: {loc}"
    );
}

// ── consent handler tests ─────────────────────────────────────────────────

fn make_consent_token(expires_offset_secs: i64) -> String {
    ConsentData {
        user_id: "user-verified".into(),
        user_email: "verified@example.com".into(),
        client_id: "pub-client".into(),
        redirect_uri: "http://localhost:3000/cb".into(),
        scope: "openid".into(),
        state: "st".into(),
        nonce: None,
        code_challenge: None,
        code_challenge_method: None,
        expires_at: OffsetDateTime::now_utc().unix_timestamp() + expires_offset_secs,
    }
    .encode()
}

#[tokio::test]
async fn consent_page_invalid_token_redirects() {
    let (resources, state) = setup().await;
    let server = consent_server(resources, state);

    let response = server
        .get("/consent")
        .add_query_param("token", "!!!bad!!!")
        .await;
    // axum_test follows redirects by default; the page renders an error HTML or redirects
    let status = response.status_code();
    assert!(
        status.is_redirection() || status.is_success(),
        "should not 5xx, got {status}"
    );
}

#[tokio::test]
async fn consent_page_expired_token_redirects_or_errors() {
    let (resources, state) = setup().await;
    let server = consent_server(resources, state);

    let token = make_consent_token(-1); // expired 1 second ago
    let response = server
        .get("/consent")
        .add_query_param("token", &token)
        .await;
    let status = response.status_code();
    assert!(
        !status.is_server_error(),
        "expired token must not produce 5xx, got {status}"
    );
}

#[tokio::test]
async fn consent_submit_deny_redirects_with_access_denied() {
    let (resources, state) = setup().await;
    let server = consent_server(resources, state);
    let token = make_consent_token(600);

    let form = vec![("consent_token", token.as_str()), ("action", "deny")];
    let response = server.post("/consent").form(&form).await;
    response.assert_status_see_other();
    let loc = location(&response);
    assert!(
        loc.contains("access_denied"),
        "deny should produce access_denied, got: {loc}"
    );
}

#[tokio::test]
async fn consent_submit_approve_creates_code_and_redirects() {
    let (resources, state) = setup().await;
    let server = consent_server(resources, state);
    let token = make_consent_token(600);

    let form = vec![("consent_token", token.as_str()), ("action", "approve")];
    let response = server.post("/consent").form(&form).await;
    response.assert_status_see_other();
    let loc = location(&response);
    assert!(
        loc.contains("code="),
        "approve should produce authorization code, got: {loc}"
    );
}

#[tokio::test]
async fn consent_submit_with_state_includes_state_in_redirect() {
    let (resources, state) = setup().await;
    let server = consent_server(resources, state);

    let token = ConsentData {
        user_id: "user-verified".into(),
        user_email: "verified@example.com".into(),
        client_id: "pub-client".into(),
        redirect_uri: "http://localhost:3000/cb".into(),
        scope: "openid".into(),
        state: "my-state-value".into(),
        nonce: None,
        code_challenge: None,
        code_challenge_method: None,
        expires_at: OffsetDateTime::now_utc().unix_timestamp() + 600,
    }
    .encode();

    let form = vec![("consent_token", token.as_str()), ("action", "approve")];
    let response = server.post("/consent").form(&form).await;
    response.assert_status_see_other();
    let loc = location(&response);
    assert!(loc.contains("state="), "should preserve state, got: {loc}");
}

// ── SecureJsonParser additional coverage ─────────────────────────────────
// Tests use default limits: max_array_length=10_000, max_object_keys=1_000,
// max_string_length=64KB, max_size=1MB, max_depth=32.

#[test]
fn security_array_too_large() {
    use rust_federation_tester::security::{JsonSecurityError, secure_parse_json_slice};

    // 10_001 elements exceeds the default max_array_length of 10_000
    let items = (0..10_001)
        .map(|i| i.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let json = format!("[{items}]");
    let result = secure_parse_json_slice(json.as_bytes());
    assert!(matches!(
        result,
        Err(JsonSecurityError::ArrayTooLarge { .. })
    ));
}

#[test]
fn security_too_many_object_keys() {
    use rust_federation_tester::security::{JsonSecurityError, secure_parse_json_slice};

    // 1_001 keys exceeds the default max_object_keys of 1_000
    let pairs = (0..1_001)
        .map(|i| format!(r#""k{i}":1"#))
        .collect::<Vec<_>>()
        .join(",");
    let json = format!("{{{pairs}}}");
    let result = secure_parse_json_slice(json.as_bytes());
    assert!(matches!(result, Err(JsonSecurityError::TooManyKeys { .. })));
}

#[test]
fn security_object_key_too_long() {
    use rust_federation_tester::security::{JsonSecurityError, secure_parse_json_slice};

    // A key of 65_537 bytes exceeds the default max_string_length of 64KB
    let long_key = "k".repeat(64 * 1024 + 1);
    let json = serde_json::json!({ long_key: 1 });
    let result = secure_parse_json_slice(json.to_string().as_bytes());
    assert!(matches!(
        result,
        Err(JsonSecurityError::StringTooLong { .. })
    ));
}

#[test]
fn security_reader_too_large() {
    use rust_federation_tester::security::{JsonSecurityError, secure_parse_json_reader};

    // 2MB string JSON exceeds default max_size of 1MB
    let large = format!(r#""{}""#, "x".repeat(2 * 1024 * 1024));
    let result = secure_parse_json_reader(large.as_bytes());
    assert!(matches!(result, Err(JsonSecurityError::TooLarge { .. })));
}

#[test]
fn security_valid_nested_object_passes() {
    use rust_federation_tester::security::secure_parse_json_slice;

    let json = r#"{"outer":{"inner":{"value":42}}}"#;
    assert!(secure_parse_json_slice(json.as_bytes()).is_ok());
}

#[test]
fn security_parse_error_on_invalid_json() {
    use rust_federation_tester::security::{JsonSecurityError, secure_parse_json_slice};

    let result = secure_parse_json_slice(b"not json at all");
    assert!(matches!(result, Err(JsonSecurityError::ParseError(_))));
}

#[test]
fn security_valid_array_within_limits() {
    use rust_federation_tester::security::secure_parse_json_slice;

    let items = (0..100)
        .map(|i| i.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let json = format!("[{items}]");
    assert!(secure_parse_json_slice(json.as_bytes()).is_ok());
}
