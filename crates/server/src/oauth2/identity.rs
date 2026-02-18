//! Identity linking service for OAuth2 user migration.
//!
//! This module handles:
//! - Linking existing alerts to OAuth2 users when they authenticate
//! - Creating/linking external identity provider accounts
//! - Managing the transition from magic links to OAuth2
//!
//! ## Security: Email Verification Requirement
//!
//! To prevent account takeover, legacy alerts are ONLY linked to an OAuth2 user
//! when the user's email address has been verified. This prevents an attacker
//! from creating an OAuth2 account with someone else's email and gaining access
//! to their existing alerts.
//!
//! - `authenticate_user()` only links alerts if `email_verified = true`
//! - `get_user_alerts()` only returns legacy alerts (user_id = NULL) if `email_verified = true`

use crate::entity::{alert, oauth2_identity, oauth2_user};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter,
};
use std::sync::Arc;
use time::OffsetDateTime;

/// Parameters for linking an external identity provider to a user.
#[derive(Debug, Clone)]
pub struct ExternalIdentityParams<'a> {
    pub user_id: &'a str,
    pub provider: &'a str,
    pub subject: &'a str,
    pub email: Option<&'a str>,
    pub name: Option<&'a str>,
    pub access_token: Option<&'a str>,
    pub refresh_token: Option<&'a str>,
    pub token_expires_at: Option<OffsetDateTime>,
}

/// Service for managing identity linking between legacy magic links and OAuth2.
pub struct IdentityService {
    db: Arc<DatabaseConnection>,
}

impl IdentityService {
    pub fn new(db: Arc<DatabaseConnection>) -> Self {
        Self { db }
    }

    /// Get or create an OAuth2 user by email.
    /// This is the primary identity linking point.
    #[tracing::instrument(skip(self))]
    pub async fn get_or_create_user(
        &self,
        email: &str,
    ) -> Result<oauth2_user::Model, sea_orm::DbErr> {
        // Try to find existing user
        if let Some(user) = oauth2_user::Entity::find()
            .filter(oauth2_user::Column::Email.eq(email))
            .one(self.db.as_ref())
            .await?
        {
            return Ok(user);
        }

        // Create new user
        let now = OffsetDateTime::now_utc();
        let user = oauth2_user::ActiveModel {
            id: Set(uuid::Uuid::new_v4().to_string()),
            email: Set(email.to_string()),
            email_verified: Set(false),
            name: Set(None),
            created_at: Set(now),
            last_login_at: Set(None),
            password_hash: Set(None),
            email_verification_token: Set(None),
            email_verification_expires_at: Set(None),
        };

        user.insert(self.db.as_ref()).await
    }

    /// Link all existing alerts for an email address to an OAuth2 user.
    /// This is called when a user first authenticates via OAuth2.
    #[tracing::instrument(skip(self))]
    pub async fn link_existing_alerts(
        &self,
        user_id: &str,
        email: &str,
    ) -> Result<u64, sea_orm::DbErr> {
        use sea_orm::sea_query::Expr;

        // Update all alerts with this email to link to the OAuth2 user
        let result = alert::Entity::update_many()
            .col_expr(alert::Column::UserId, Expr::value(user_id))
            .filter(alert::Column::Email.eq(email))
            .filter(alert::Column::UserId.is_null())
            .exec(self.db.as_ref())
            .await?;

        if result.rows_affected > 0 {
            tracing::info!(
                email = email,
                user_id = user_id,
                count = result.rows_affected,
                "Linked existing alerts to OAuth2 user"
            );
        }

        Ok(result.rows_affected)
    }

    /// Complete user authentication: get/create user, link alerts, update last login.
    ///
    /// ## Security: Email Verification Required for Linking
    ///
    /// Legacy alerts are ONLY linked to the OAuth2 user if `email_verified = true`.
    /// This prevents account takeover where an attacker creates an OAuth2 account
    /// with someone else's email to access their existing alerts.
    ///
    /// If email is not verified:
    /// - User account is created/updated normally
    /// - Legacy alerts are NOT linked (remain with user_id = NULL)
    /// - User can only see alerts they create via OAuth2 (with their user_id)
    /// - Once email is verified on a subsequent login, alerts will be linked
    #[tracing::instrument(skip(self))]
    pub async fn authenticate_user(
        &self,
        email: &str,
        email_verified: bool,
    ) -> Result<oauth2_user::Model, sea_orm::DbErr> {
        // Get or create the user
        let user = self.get_or_create_user(email).await?;

        // SECURITY: Only link legacy alerts if email is verified
        // This prevents account takeover where an attacker creates an OAuth2 account
        // with someone else's email to hijack their existing alerts
        if email_verified {
            let linked_count = self.link_existing_alerts(&user.id, email).await?;
            if linked_count > 0 {
                tracing::info!(
                    email = email,
                    user_id = %user.id,
                    count = linked_count,
                    "Linked legacy alerts to verified OAuth2 user"
                );
            }
        } else {
            tracing::debug!(
                email = email,
                user_id = %user.id,
                "Skipping alert linking - email not verified (security protection)"
            );
        }

        // Update user record
        let mut active: oauth2_user::ActiveModel = user.clone().into();
        active.last_login_at = Set(Some(OffsetDateTime::now_utc()));
        if email_verified && !user.email_verified {
            active.email_verified = Set(true);
        }
        let updated = active.update(self.db.as_ref()).await?;

        Ok(updated)
    }

    /// Link an external identity provider to an existing user.
    #[tracing::instrument(skip(self, params), fields(provider = params.provider, subject = params.subject))]
    pub async fn link_external_identity(
        &self,
        params: ExternalIdentityParams<'_>,
    ) -> Result<oauth2_identity::Model, sea_orm::DbErr> {
        let now = OffsetDateTime::now_utc();

        // Check if this identity already exists
        if let Some(existing) = oauth2_identity::Entity::find()
            .filter(oauth2_identity::Column::Provider.eq(params.provider))
            .filter(oauth2_identity::Column::Subject.eq(params.subject))
            .one(self.db.as_ref())
            .await?
        {
            // Update the existing identity
            let mut active: oauth2_identity::ActiveModel = existing.into();
            active.access_token = Set(params.access_token.map(String::from));
            active.refresh_token = Set(params.refresh_token.map(String::from));
            active.token_expires_at = Set(params.token_expires_at);
            active.updated_at = Set(now);
            if let Some(e) = params.email {
                active.email = Set(Some(e.to_string()));
            }
            if let Some(n) = params.name {
                active.name = Set(Some(n.to_string()));
            }
            return active.update(self.db.as_ref()).await;
        }

        // Create new identity link
        let identity = oauth2_identity::ActiveModel {
            id: Set(uuid::Uuid::new_v4().to_string()),
            user_id: Set(params.user_id.to_string()),
            provider: Set(params.provider.to_string()),
            subject: Set(params.subject.to_string()),
            email: Set(params.email.map(String::from)),
            name: Set(params.name.map(String::from)),
            access_token: Set(params.access_token.map(String::from)),
            refresh_token: Set(params.refresh_token.map(String::from)),
            token_expires_at: Set(params.token_expires_at),
            created_at: Set(now),
            updated_at: Set(now),
        };

        identity.insert(self.db.as_ref()).await
    }

    /// Find a user by external identity (provider + subject).
    #[tracing::instrument(skip(self))]
    pub async fn find_user_by_external_identity(
        &self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<oauth2_user::Model>, sea_orm::DbErr> {
        let identity = oauth2_identity::Entity::find()
            .filter(oauth2_identity::Column::Provider.eq(provider))
            .filter(oauth2_identity::Column::Subject.eq(subject))
            .one(self.db.as_ref())
            .await?;

        match identity {
            Some(id) => {
                oauth2_user::Entity::find_by_id(&id.user_id)
                    .one(self.db.as_ref())
                    .await
            }
            None => Ok(None),
        }
    }

    /// Get all external identities linked to a user.
    #[tracing::instrument(skip(self))]
    pub async fn get_user_identities(
        &self,
        user_id: &str,
    ) -> Result<Vec<oauth2_identity::Model>, sea_orm::DbErr> {
        oauth2_identity::Entity::find()
            .filter(oauth2_identity::Column::UserId.eq(user_id))
            .all(self.db.as_ref())
            .await
    }

    /// Unlink an external identity from a user.
    #[tracing::instrument(skip(self))]
    pub async fn unlink_external_identity(
        &self,
        user_id: &str,
        provider: &str,
    ) -> Result<bool, sea_orm::DbErr> {
        let result = oauth2_identity::Entity::delete_many()
            .filter(oauth2_identity::Column::UserId.eq(user_id))
            .filter(oauth2_identity::Column::Provider.eq(provider))
            .exec(self.db.as_ref())
            .await?;

        Ok(result.rows_affected > 0)
    }

    /// Get all alerts for a user (by user_id or email for backward compatibility).
    ///
    /// ## Security: Email Verification Required for Legacy Alerts
    ///
    /// Legacy alerts (those with `user_id = NULL`) are ONLY returned if
    /// `email_verified = true`. This prevents an attacker from seeing another
    /// user's alerts by creating an OAuth2 account with their email.
    ///
    /// - If `email_verified = true`: Returns alerts by user_id OR email match
    /// - If `email_verified = false`: Returns ONLY alerts explicitly linked by user_id
    #[tracing::instrument(skip(self))]
    pub async fn get_user_alerts(
        &self,
        user_id: &str,
        email: &str,
        email_verified: bool,
    ) -> Result<Vec<alert::Model>, sea_orm::DbErr> {
        if email_verified {
            // User's email is verified - return alerts by user_id OR email match (backward compat)
            alert::Entity::find()
                .filter(
                    alert::Column::UserId.eq(user_id).or(alert::Column::Email
                        .eq(email)
                        .and(alert::Column::UserId.is_null())),
                )
                .all(self.db.as_ref())
                .await
        } else {
            // SECURITY: Email not verified - only return alerts explicitly linked to this user_id
            // This prevents account takeover where an attacker creates an OAuth2 account
            // with someone else's email to view their alerts
            tracing::debug!(
                user_id = user_id,
                email = email,
                "Returning only user_id-linked alerts - email not verified (security protection)"
            );
            alert::Entity::find()
                .filter(alert::Column::UserId.eq(user_id))
                .all(self.db.as_ref())
                .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::{ConnectionTrait, Database, DbBackend, Statement};

    async fn setup_test_db() -> Arc<DatabaseConnection> {
        let db = Database::connect("sqlite::memory:").await.expect("connect");

        // Create required tables
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

        db.execute(Statement::from_string(
            DbBackend::Sqlite,
            r#"CREATE TABLE oauth2_identity (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                provider TEXT NOT NULL,
                subject TEXT NOT NULL,
                email TEXT NULL,
                name TEXT NULL,
                access_token TEXT NULL,
                refresh_token TEXT NULL,
                token_expires_at TEXT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(provider, subject)
            );"#,
        ))
        .await
        .expect("create oauth2_identity table");

        db.execute(Statement::from_string(
            DbBackend::Sqlite,
            r#"CREATE TABLE alert (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                server_name TEXT NOT NULL,
                verified INTEGER NOT NULL DEFAULT 0,
                magic_token TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_check_at TEXT NULL,
                last_failure_at TEXT NULL,
                last_success_at TEXT NULL,
                last_email_sent_at TEXT NULL,
                failure_count INTEGER NOT NULL DEFAULT 0,
                is_currently_failing INTEGER NOT NULL DEFAULT 0,
                last_recovery_at TEXT NULL,
                user_id TEXT NULL
            );"#,
        ))
        .await
        .expect("create alert table");

        Arc::new(db)
    }

    #[tokio::test]
    async fn test_get_or_create_user_new() {
        let db = setup_test_db().await;
        let service = IdentityService::new(db);

        let user = service
            .get_or_create_user("test@example.com")
            .await
            .unwrap();
        assert_eq!(user.email, "test@example.com");
        assert!(!user.email_verified);
    }

    #[tokio::test]
    async fn test_get_or_create_user_existing() {
        let db = setup_test_db().await;
        let service = IdentityService::new(db);

        let user1 = service
            .get_or_create_user("test@example.com")
            .await
            .unwrap();
        let user2 = service
            .get_or_create_user("test@example.com")
            .await
            .unwrap();
        assert_eq!(user1.id, user2.id);
    }

    #[tokio::test]
    async fn test_authenticate_user_updates_last_login() {
        let db = setup_test_db().await;
        let service = IdentityService::new(db);

        let user = service
            .authenticate_user("test@example.com", true)
            .await
            .unwrap();
        assert!(user.last_login_at.is_some());
        assert!(user.email_verified);
    }

    #[tokio::test]
    async fn test_link_external_identity() {
        let db = setup_test_db().await;
        let service = IdentityService::new(db);

        let user = service
            .get_or_create_user("test@example.com")
            .await
            .unwrap();

        let identity = service
            .link_external_identity(ExternalIdentityParams {
                user_id: &user.id,
                provider: "google",
                subject: "google-user-123",
                email: Some("test@gmail.com"),
                name: Some("Test User"),
                access_token: None,
                refresh_token: None,
                token_expires_at: None,
            })
            .await
            .unwrap();

        assert_eq!(identity.provider, "google");
        assert_eq!(identity.subject, "google-user-123");
    }

    #[tokio::test]
    async fn test_find_user_by_external_identity() {
        let db = setup_test_db().await;
        let service = IdentityService::new(db);

        let user = service
            .get_or_create_user("test@example.com")
            .await
            .unwrap();
        service
            .link_external_identity(ExternalIdentityParams {
                user_id: &user.id,
                provider: "github",
                subject: "gh-123",
                email: None,
                name: None,
                access_token: None,
                refresh_token: None,
                token_expires_at: None,
            })
            .await
            .unwrap();

        let found = service
            .find_user_by_external_identity("github", "gh-123")
            .await
            .unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, user.id);

        let not_found = service
            .find_user_by_external_identity("github", "gh-456")
            .await
            .unwrap();
        assert!(not_found.is_none());
    }

    // =========================================================================
    // Security Tests: Email Verification Required for Alert Linking
    // =========================================================================

    async fn create_legacy_alert(
        db: &DatabaseConnection,
        email: &str,
        server_name: &str,
    ) -> alert::Model {
        let now = OffsetDateTime::now_utc();
        let alert = alert::ActiveModel {
            email: Set(email.to_string()),
            server_name: Set(server_name.to_string()),
            verified: Set(true),
            magic_token: Set(String::new()),
            created_at: Set(now),
            user_id: Set(None), // Legacy alert - no user_id
            ..Default::default()
        };
        alert
            .insert(db)
            .await
            .expect("Failed to create legacy alert")
    }

    #[tokio::test]
    async fn test_authenticate_user_links_alerts_when_verified() {
        let db = setup_test_db().await;
        let service = IdentityService::new(db.clone());

        // Create a legacy alert
        create_legacy_alert(db.as_ref(), "test@example.com", "matrix.org").await;

        // Authenticate with verified email
        let user = service
            .authenticate_user("test@example.com", true)
            .await
            .unwrap();

        // Alert should be linked
        let alerts = alert::Entity::find()
            .filter(alert::Column::Email.eq("test@example.com"))
            .all(db.as_ref())
            .await
            .unwrap();

        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].user_id, Some(user.id));
    }

    #[tokio::test]
    async fn test_authenticate_user_does_not_link_alerts_when_unverified() {
        let db = setup_test_db().await;
        let service = IdentityService::new(db.clone());

        // Create a legacy alert
        create_legacy_alert(db.as_ref(), "test@example.com", "matrix.org").await;

        // Authenticate with unverified email
        let _user = service
            .authenticate_user("test@example.com", false)
            .await
            .unwrap();

        // Alert should NOT be linked (security protection)
        let alerts = alert::Entity::find()
            .filter(alert::Column::Email.eq("test@example.com"))
            .all(db.as_ref())
            .await
            .unwrap();

        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].user_id, None); // Still unlinked
    }

    #[tokio::test]
    async fn test_get_user_alerts_returns_legacy_when_verified() {
        let db = setup_test_db().await;
        let service = IdentityService::new(db.clone());

        // Create user
        let user = service
            .get_or_create_user("test@example.com")
            .await
            .unwrap();

        // Create a legacy alert (not linked to user_id)
        create_legacy_alert(db.as_ref(), "test@example.com", "matrix.org").await;

        // With email_verified=true, should see legacy alert
        let alerts = service
            .get_user_alerts(&user.id, "test@example.com", true)
            .await
            .unwrap();

        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].server_name, "matrix.org");
    }

    #[tokio::test]
    async fn test_get_user_alerts_hides_legacy_when_unverified() {
        let db = setup_test_db().await;
        let service = IdentityService::new(db.clone());

        // Create user
        let user = service
            .get_or_create_user("test@example.com")
            .await
            .unwrap();

        // Create a legacy alert (not linked to user_id)
        create_legacy_alert(db.as_ref(), "test@example.com", "matrix.org").await;

        // With email_verified=false, should NOT see legacy alert (security protection)
        let alerts = service
            .get_user_alerts(&user.id, "test@example.com", false)
            .await
            .unwrap();

        assert_eq!(alerts.len(), 0); // Legacy alert hidden
    }

    #[tokio::test]
    async fn test_get_user_alerts_always_returns_user_linked_alerts() {
        let db = setup_test_db().await;
        let service = IdentityService::new(db.clone());

        // Create user
        let user = service
            .get_or_create_user("test@example.com")
            .await
            .unwrap();

        // Create an alert explicitly linked to user_id
        let now = OffsetDateTime::now_utc();
        let linked_alert = alert::ActiveModel {
            email: Set("test@example.com".to_string()),
            server_name: Set("linked.server.com".to_string()),
            verified: Set(true),
            magic_token: Set(String::new()),
            created_at: Set(now),
            user_id: Set(Some(user.id.clone())),
            ..Default::default()
        };
        linked_alert.insert(db.as_ref()).await.unwrap();

        // Even with email_verified=false, should see user_id-linked alerts
        let alerts = service
            .get_user_alerts(&user.id, "test@example.com", false)
            .await
            .unwrap();

        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].server_name, "linked.server.com");
    }
}
