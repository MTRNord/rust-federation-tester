//! Tests for the v2 Alerts API (OAuth2-authenticated).
//!
//! These tests verify the dual-auth functionality where OAuth2 tokens
//! can be used to manage alerts.

use migration::MigratorTrait;
use rust_federation_tester::entity::{
    alert, alert_notification_email, oauth2_client, oauth2_token, oauth2_user, user_email,
};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, Database, DatabaseConnection, EntityTrait,
    QueryFilter,
};
use std::sync::Arc;
use time::OffsetDateTime;

/// Create an in-memory SQLite database with required tables by running the real migrations.
async fn setup_test_db() -> Arc<DatabaseConnection> {
    let db = Database::connect("sqlite::memory:")
        .await
        .expect("Failed to connect to in-memory database");

    // Run the real migrations so tests use the same single source of truth for the schema.
    // The `migration` crate is added as a dev-dependency in Cargo.toml.
    // Use the Migrator provided by the migration crate to apply all migrations to the test DB.
    // Pass `None` for `steps` so all pending migrations are applied.
    migration::Migrator::up(&db, None)
        .await
        .expect("Failed to run migrations for test database");

    Arc::new(db)
}

/// Create a test user in the database.
async fn create_test_user(
    db: &DatabaseConnection,
    id: &str,
    email: &str,
    email_verified: bool,
) -> oauth2_user::Model {
    let now = OffsetDateTime::now_utc();
    let user = oauth2_user::ActiveModel {
        id: Set(id.to_string()),
        email: Set(email.to_string()),
        email_verified: Set(email_verified),
        name: Set(None),
        receives_alerts: Set(true),
        created_at: Set(now),
        last_login_at: Set(None),
        password_hash: Set(None),
        email_verification_token: Set(None),
        email_verification_expires_at: Set(None),
        password_reset_token: sea_orm::ActiveValue::NotSet,
        password_reset_expires_at: sea_orm::ActiveValue::NotSet,
    };
    user.insert(db).await.expect("Failed to create test user")
}

/// Create a test OAuth2 client in the database.
async fn create_test_client(db: &DatabaseConnection, client_id: &str) -> oauth2_client::Model {
    let now = OffsetDateTime::now_utc();
    let client = oauth2_client::ActiveModel {
        id: Set(client_id.to_string()),
        secret: Set(None),
        name: Set("Test Client".to_string()),
        redirect_uris: Set("[\"http://localhost:3000/callback\"]".to_string()),
        grant_types: Set("authorization_code refresh_token".to_string()),
        scopes: Set("openid profile email alerts:read alerts:write".to_string()),
        is_public: Set(true),
        created_at: Set(now),
        updated_at: Set(now),
    };
    client
        .insert(db)
        .await
        .expect("Failed to create test client")
}

/// Create a test OAuth2 token in the database.
async fn create_test_token(
    db: &DatabaseConnection,
    access_token: &str,
    user_id: &str,
    client_id: &str,
    scopes: &str,
    expired: bool,
    revoked: bool,
) -> oauth2_token::Model {
    let now = OffsetDateTime::now_utc();
    let expires_at = if expired {
        now - time::Duration::hours(1)
    } else {
        now + time::Duration::hours(1)
    };

    let token = oauth2_token::ActiveModel {
        id: Set(uuid::Uuid::new_v4().to_string()),
        access_token: Set(access_token.to_string()),
        refresh_token: Set(None),
        token_type: Set("Bearer".to_string()),
        client_id: Set(client_id.to_string()),
        user_id: Set(user_id.to_string()),
        scope: Set(scopes.to_string()),
        access_token_expires_at: Set(expires_at),
        refresh_token_expires_at: Set(None),
        created_at: Set(now),
        revoked_at: Set(if revoked { Some(now) } else { None }),
    };
    token.insert(db).await.expect("Failed to create test token")
}

/// Create a test alert in the database.
async fn create_test_alert(
    db: &DatabaseConnection,
    email: &str,
    server_name: &str,
    user_id: Option<&str>,
    verified: bool,
) -> alert::Model {
    let now = OffsetDateTime::now_utc();
    let alert = alert::ActiveModel {
        email: Set(email.to_string()),
        server_name: Set(server_name.to_string()),
        verified: Set(verified),
        magic_token: Set(None),
        created_at: Set(now),
        user_id: Set(user_id.map(String::from)),
        ..Default::default()
    };
    alert.insert(db).await.expect("Failed to create test alert")
}

// =============================================================================
// Token Validation Tests
// =============================================================================

#[tokio::test]
async fn test_oauth2_token_is_valid() {
    let db = setup_test_db().await;
    let user = create_test_user(db.as_ref(), "user-1", "test@example.com", true).await;
    let client = create_test_client(db.as_ref(), "test-client").await;

    // Valid token
    let valid_token = create_test_token(
        db.as_ref(),
        "valid-token",
        &user.id,
        &client.id,
        "openid alerts:read",
        false, // not expired
        false, // not revoked
    )
    .await;
    assert!(valid_token.is_valid());

    // Expired token
    let expired_token = create_test_token(
        db.as_ref(),
        "expired-token",
        &user.id,
        &client.id,
        "openid alerts:read",
        true, // expired
        false,
    )
    .await;
    assert!(!expired_token.is_valid());
    assert!(expired_token.is_access_token_expired());

    // Revoked token
    let revoked_token = create_test_token(
        db.as_ref(),
        "revoked-token",
        &user.id,
        &client.id,
        "openid alerts:read",
        false,
        true, // revoked
    )
    .await;
    assert!(!revoked_token.is_valid());
    assert!(revoked_token.is_revoked());
}

#[tokio::test]
async fn test_oauth2_token_has_scope() {
    let db = setup_test_db().await;
    let user = create_test_user(db.as_ref(), "user-1", "test@example.com", true).await;
    let client = create_test_client(db.as_ref(), "test-client").await;

    let token = create_test_token(
        db.as_ref(),
        "scoped-token",
        &user.id,
        &client.id,
        "openid profile alerts:read",
        false,
        false,
    )
    .await;

    assert!(token.has_scope("openid"));
    assert!(token.has_scope("profile"));
    assert!(token.has_scope("alerts:read"));
    assert!(!token.has_scope("alerts:write"));
    assert!(!token.has_scope("email"));
}

// =============================================================================
// Identity Service Tests
// =============================================================================

#[tokio::test]
async fn test_identity_service_get_user_alerts_by_user_id() {
    use rust_federation_tester::oauth2::IdentityService;

    let db = setup_test_db().await;
    let user = create_test_user(db.as_ref(), "user-1", "test@example.com", true).await;

    // Create alert linked to user_id
    create_test_alert(
        db.as_ref(),
        "test@example.com",
        "matrix.org",
        Some(&user.id),
        true,
    )
    .await;

    let service = IdentityService::new(db.clone());
    // email_verified=true allows seeing user_id linked alerts (always allowed)
    let alerts = service
        .get_user_alerts(&user.id, "test@example.com", true)
        .await
        .expect("Failed to get alerts");

    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].server_name, "matrix.org");
}

#[tokio::test]
async fn test_identity_service_get_user_alerts_by_email_legacy() {
    use rust_federation_tester::oauth2::IdentityService;

    let db = setup_test_db().await;
    let user = create_test_user(db.as_ref(), "user-1", "test@example.com", true).await;

    // Create legacy alert (no user_id, just email)
    create_test_alert(
        db.as_ref(),
        "test@example.com",
        "legacy.server.com",
        None,
        true,
    )
    .await;

    let service = IdentityService::new(db.clone());
    // email_verified=true allows seeing legacy alerts by email match
    let alerts = service
        .get_user_alerts(&user.id, "test@example.com", true)
        .await
        .expect("Failed to get alerts");

    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].server_name, "legacy.server.com");
}

#[tokio::test]
async fn test_identity_service_get_user_alerts_combined() {
    use rust_federation_tester::oauth2::IdentityService;

    let db = setup_test_db().await;
    let user = create_test_user(db.as_ref(), "user-1", "test@example.com", true).await;

    // Create alert linked to user_id
    create_test_alert(
        db.as_ref(),
        "test@example.com",
        "linked.server.com",
        Some(&user.id),
        true,
    )
    .await;

    // Create legacy alert (no user_id)
    create_test_alert(
        db.as_ref(),
        "test@example.com",
        "legacy.server.com",
        None,
        true,
    )
    .await;

    let service = IdentityService::new(db.clone());
    // email_verified=true allows seeing both user_id-linked and legacy alerts
    let alerts = service
        .get_user_alerts(&user.id, "test@example.com", true)
        .await
        .expect("Failed to get alerts");

    assert_eq!(alerts.len(), 2);
}

#[tokio::test]
async fn test_identity_service_hides_legacy_alerts_when_unverified() {
    use rust_federation_tester::oauth2::IdentityService;

    let db = setup_test_db().await;
    let user = create_test_user(db.as_ref(), "user-1", "test@example.com", false).await;

    // Create alert linked to user_id
    create_test_alert(
        db.as_ref(),
        "test@example.com",
        "linked.server.com",
        Some(&user.id),
        true,
    )
    .await;

    // Create legacy alert (no user_id)
    create_test_alert(
        db.as_ref(),
        "test@example.com",
        "legacy.server.com",
        None,
        true,
    )
    .await;

    let service = IdentityService::new(db.clone());
    // SECURITY: email_verified=false should ONLY return user_id-linked alerts
    let alerts = service
        .get_user_alerts(&user.id, "test@example.com", false)
        .await
        .expect("Failed to get alerts");

    // Only the user_id-linked alert should be visible, legacy hidden for security
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].server_name, "linked.server.com");
}

// =============================================================================
// Alert Ownership Tests
// =============================================================================

#[tokio::test]
async fn test_alert_ownership_by_user_id() {
    let db = setup_test_db().await;
    let user1 = create_test_user(db.as_ref(), "user-1", "user1@example.com", true).await;
    let user2 = create_test_user(db.as_ref(), "user-2", "user2@example.com", true).await;

    // Alert owned by user1
    let alert = create_test_alert(
        db.as_ref(),
        "user1@example.com",
        "matrix.org",
        Some(&user1.id),
        true,
    )
    .await;

    // User1 owns it
    let is_owner_user1 = alert
        .user_id
        .as_ref()
        .map(|uid| uid == &user1.id)
        .unwrap_or(false)
        || alert.email == user1.email;
    assert!(is_owner_user1);

    // User2 does not own it
    let is_owner_user2 = alert
        .user_id
        .as_ref()
        .map(|uid| uid == &user2.id)
        .unwrap_or(false)
        || alert.email == user2.email;
    assert!(!is_owner_user2);
}

#[tokio::test]
async fn test_alert_ownership_by_email_legacy() {
    let db = setup_test_db().await;
    let user = create_test_user(db.as_ref(), "user-1", "test@example.com", true).await;

    // Legacy alert (no user_id)
    let alert = create_test_alert(
        db.as_ref(),
        "test@example.com",
        "legacy.server.com",
        None,
        true,
    )
    .await;

    // User owns it via email match
    let is_owner = alert
        .user_id
        .as_ref()
        .map(|uid| uid == &user.id)
        .unwrap_or(false)
        || alert.email == user.email;
    assert!(is_owner);
}

// =============================================================================
// Alert Creation Tests
// =============================================================================

#[tokio::test]
async fn test_create_alert_links_to_user_id() {
    let db = setup_test_db().await;
    let user = create_test_user(db.as_ref(), "user-1", "test@example.com", true).await;

    let now = OffsetDateTime::now_utc();
    let alert = alert::ActiveModel {
        email: Set("test@example.com".to_string()),
        server_name: Set("new.server.com".to_string()),
        verified: Set(true), // Pre-verified for verified email
        magic_token: Set(None),
        created_at: Set(now),
        user_id: Set(Some(user.id.clone())),
        ..Default::default()
    };

    let inserted = alert
        .insert(db.as_ref())
        .await
        .expect("Failed to insert alert");

    assert_eq!(inserted.user_id, Some(user.id));
    assert!(inserted.verified);
}

#[tokio::test]
async fn test_alert_duplicate_detection() {
    use sea_orm::{ColumnTrait, QueryFilter};

    let db = setup_test_db().await;
    let _user = create_test_user(db.as_ref(), "user-1", "test@example.com", true).await;

    // Create first alert
    create_test_alert(
        db.as_ref(),
        "test@example.com",
        "matrix.org",
        Some("user-1"),
        true,
    )
    .await;

    // Check for duplicate
    let existing = alert::Entity::find()
        .filter(alert::Column::Email.eq("test@example.com"))
        .filter(alert::Column::ServerName.eq("matrix.org"))
        .one(db.as_ref())
        .await
        .expect("Failed to query");

    assert!(existing.is_some());
}

// =============================================================================
// Auth Error Tests
// =============================================================================

#[test]
fn test_auth_error_insufficient_scope() {
    use rust_federation_tester::api::auth::AuthError;

    let error = AuthError::insufficient_scope("alerts:read");
    assert_eq!(error.error, "insufficient_scope");
    assert!(
        error
            .error_description
            .as_ref()
            .unwrap()
            .contains("alerts:read")
    );
}

#[test]
fn test_auth_error_invalid_token() {
    use rust_federation_tester::api::auth::AuthError;

    let error = AuthError::invalid_token("Token expired");
    assert_eq!(error.error, "invalid_token");
    assert!(
        error
            .error_description
            .as_ref()
            .unwrap()
            .contains("Token expired")
    );
}

#[test]
fn test_auth_error_forbidden() {
    use rust_federation_tester::api::auth::AuthError;

    let error = AuthError::forbidden("You do not own this alert");
    assert_eq!(error.error, "forbidden");
}

#[test]
fn test_auth_error_not_found() {
    use rust_federation_tester::api::auth::AuthError;

    let error = AuthError::not_found("Alert not found");
    assert_eq!(error.error, "not_found");
}

// =============================================================================
// Helpers for notification email tests
// =============================================================================

async fn create_notification_email(
    db: &DatabaseConnection,
    alert_id: i32,
    email: &str,
) -> alert_notification_email::Model {
    let now = OffsetDateTime::now_utc();
    alert_notification_email::ActiveModel {
        alert_id: Set(alert_id),
        email: Set(email.to_string()),
        created_at: Set(now),
        ..Default::default()
    }
    .insert(db)
    .await
    .expect("Failed to create notification email")
}

async fn create_additional_email(
    db: &DatabaseConnection,
    user_id: &str,
    email: &str,
    verified: bool,
) -> user_email::Model {
    let now = OffsetDateTime::now_utc();
    user_email::ActiveModel {
        id: Set(uuid::Uuid::new_v4().to_string()),
        user_id: Set(user_id.to_string()),
        email: Set(email.to_string()),
        verified: Set(verified),
        receives_alerts: Set(true),
        verification_token: Set(None),
        verification_expires_at: Set(None),
        created_at: Set(now),
    }
    .insert(db)
    .await
    .expect("Failed to create additional email")
}

// =============================================================================
// Alert Notification Email Tests
// =============================================================================

#[tokio::test]
async fn test_notification_email_created_with_alert() {
    let db = setup_test_db().await;
    let user = create_test_user(db.as_ref(), "user-1", "user@example.com", true).await;
    let alert = create_test_alert(
        db.as_ref(),
        "user@example.com",
        "matrix.org",
        Some(&user.id),
        true,
    )
    .await;

    // Manually insert a notification email (simulating what create_alert_v2 does)
    let ne = create_notification_email(db.as_ref(), alert.id, "user@example.com").await;
    assert_eq!(ne.alert_id, alert.id);
    assert_eq!(ne.email, "user@example.com");
}

#[tokio::test]
async fn test_notification_emails_multiple_per_alert() {
    let db = setup_test_db().await;
    let user = create_test_user(db.as_ref(), "user-1", "user@example.com", true).await;
    let alert = create_test_alert(
        db.as_ref(),
        "user@example.com",
        "matrix.org",
        Some(&user.id),
        true,
    )
    .await;

    create_notification_email(db.as_ref(), alert.id, "user@example.com").await;
    create_notification_email(db.as_ref(), alert.id, "other@example.com").await;

    let rows = alert_notification_email::Entity::find()
        .filter(alert_notification_email::Column::AlertId.eq(alert.id))
        .all(db.as_ref())
        .await
        .expect("Failed to query notification emails");

    assert_eq!(rows.len(), 2);
    let emails: Vec<&str> = rows.iter().map(|r| r.email.as_str()).collect();
    assert!(emails.contains(&"user@example.com"));
    assert!(emails.contains(&"other@example.com"));
}

#[tokio::test]
async fn test_notification_email_cascade_delete() {
    let db = setup_test_db().await;
    let user = create_test_user(db.as_ref(), "user-1", "user@example.com", true).await;
    let alert = create_test_alert(
        db.as_ref(),
        "user@example.com",
        "matrix.org",
        Some(&user.id),
        true,
    )
    .await;
    create_notification_email(db.as_ref(), alert.id, "user@example.com").await;
    create_notification_email(db.as_ref(), alert.id, "other@example.com").await;

    // Delete the alert — FK cascade should remove notification email rows.
    alert::Entity::delete_by_id(alert.id)
        .exec(db.as_ref())
        .await
        .expect("Failed to delete alert");

    let rows = alert_notification_email::Entity::find()
        .filter(alert_notification_email::Column::AlertId.eq(alert.id))
        .all(db.as_ref())
        .await
        .expect("Failed to query notification emails after delete");

    assert!(
        rows.is_empty(),
        "Notification email rows should be cascade-deleted with the alert"
    );
}

#[tokio::test]
async fn test_get_notification_emails_oauth2_alert() {
    use rust_federation_tester::alerts::checks::get_notification_emails;

    let db = setup_test_db().await;
    let user = create_test_user(db.as_ref(), "user-1", "user@example.com", true).await;
    let alert = create_test_alert(
        db.as_ref(),
        "user@example.com",
        "matrix.org",
        Some(&user.id),
        true,
    )
    .await;
    create_notification_email(db.as_ref(), alert.id, "user@example.com").await;
    create_notification_email(db.as_ref(), alert.id, "extra@example.com").await;

    let emails = get_notification_emails(db.as_ref(), &alert).await;
    assert_eq!(emails.len(), 2);
    assert!(emails.contains(&"user@example.com".to_string()));
    assert!(emails.contains(&"extra@example.com".to_string()));
}

#[tokio::test]
async fn test_get_notification_emails_legacy_alert() {
    use rust_federation_tester::alerts::checks::get_notification_emails;

    let db = setup_test_db().await;
    // Legacy alert: user_id is None
    let alert = create_test_alert(
        db.as_ref(),
        "legacy@example.com",
        "old.server.com",
        None,
        true,
    )
    .await;

    let emails = get_notification_emails(db.as_ref(), &alert).await;
    assert_eq!(emails, vec!["legacy@example.com".to_string()]);
}

#[tokio::test]
async fn test_get_notification_emails_empty_table_fallback() {
    use rust_federation_tester::alerts::checks::get_notification_emails;

    let db = setup_test_db().await;
    let user = create_test_user(db.as_ref(), "user-1", "user@example.com", true).await;
    // OAuth2 alert but NO rows in alert_notification_email
    let alert = create_test_alert(
        db.as_ref(),
        "user@example.com",
        "matrix.org",
        Some(&user.id),
        true,
    )
    .await;

    let emails = get_notification_emails(db.as_ref(), &alert).await;
    // Falls back to alert.email when the table is empty
    assert_eq!(emails, vec!["user@example.com".to_string()]);
}

#[tokio::test]
async fn test_verified_email_set_primary_only() {
    let db = setup_test_db().await;
    let user = create_test_user(db.as_ref(), "user-1", "user@example.com", true).await;

    // The user has no additional emails — only the primary verified email.
    let verified = user_email::Entity::find()
        .filter(user_email::Column::UserId.eq(&user.id))
        .filter(user_email::Column::Verified.eq(true))
        .all(db.as_ref())
        .await
        .expect("Failed to query user_email");

    assert!(verified.is_empty());
    // Primary email is verified via oauth2_user.email_verified = true
    assert!(user.email_verified);
    assert_eq!(user.email, "user@example.com");
}

#[tokio::test]
async fn test_verified_email_set_with_additional() {
    let db = setup_test_db().await;
    let user = create_test_user(db.as_ref(), "user-1", "user@example.com", true).await;
    create_additional_email(db.as_ref(), &user.id, "extra@example.com", true).await;
    create_additional_email(db.as_ref(), &user.id, "unverified@example.com", false).await;

    let verified_additional = user_email::Entity::find()
        .filter(user_email::Column::UserId.eq(&user.id))
        .filter(user_email::Column::Verified.eq(true))
        .all(db.as_ref())
        .await
        .expect("Failed to query verified additional emails");

    // Only extra@example.com is verified; unverified@example.com should not appear.
    assert_eq!(verified_additional.len(), 1);
    assert_eq!(verified_additional[0].email, "extra@example.com");
}

#[tokio::test]
async fn test_notification_email_replace_list() {
    let db = setup_test_db().await;
    let user = create_test_user(db.as_ref(), "user-1", "user@example.com", true).await;
    let alert = create_test_alert(
        db.as_ref(),
        "user@example.com",
        "matrix.org",
        Some(&user.id),
        true,
    )
    .await;
    create_notification_email(db.as_ref(), alert.id, "user@example.com").await;
    create_notification_email(db.as_ref(), alert.id, "old@example.com").await;

    // Simulate the replace: delete all, insert new set.
    alert_notification_email::Entity::delete_many()
        .filter(alert_notification_email::Column::AlertId.eq(alert.id))
        .exec(db.as_ref())
        .await
        .expect("Failed to delete old notification emails");

    let now = OffsetDateTime::now_utc();
    let new_emails = vec!["user@example.com", "new@example.com"];
    for email in &new_emails {
        alert_notification_email::ActiveModel {
            alert_id: Set(alert.id),
            email: Set(email.to_string()),
            created_at: Set(now),
            ..Default::default()
        }
        .insert(db.as_ref())
        .await
        .expect("Failed to insert notification email");
    }

    let rows = alert_notification_email::Entity::find()
        .filter(alert_notification_email::Column::AlertId.eq(alert.id))
        .all(db.as_ref())
        .await
        .expect("Failed to query notification emails");

    assert_eq!(rows.len(), 2);
    let emails: Vec<&str> = rows.iter().map(|r| r.email.as_str()).collect();
    assert!(emails.contains(&"user@example.com"));
    assert!(emails.contains(&"new@example.com"));
    assert!(!emails.contains(&"old@example.com"));
}

#[tokio::test]
async fn test_notification_email_empty_list_allowed() {
    let db = setup_test_db().await;
    let user = create_test_user(db.as_ref(), "user-1", "user@example.com", true).await;
    let alert = create_test_alert(
        db.as_ref(),
        "user@example.com",
        "matrix.org",
        Some(&user.id),
        true,
    )
    .await;
    create_notification_email(db.as_ref(), alert.id, "user@example.com").await;

    // Delete all notification emails (empty list).
    alert_notification_email::Entity::delete_many()
        .filter(alert_notification_email::Column::AlertId.eq(alert.id))
        .exec(db.as_ref())
        .await
        .expect("Failed to delete notification emails");

    let rows = alert_notification_email::Entity::find()
        .filter(alert_notification_email::Column::AlertId.eq(alert.id))
        .all(db.as_ref())
        .await
        .expect("Failed to query notification emails");

    assert!(rows.is_empty());
}
