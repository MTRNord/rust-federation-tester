//! OAuth2 state management.
//!
//! Provides the state structures for the OAuth2 authorization server.

use crate::entity::{oauth2_client, oauth2_user};
use crate::oauth2::registrar::DbRegistrar;
use sea_orm::{
    ActiveModelTrait,
    ActiveValue::{NotSet, Set},
    ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter,
};
use std::sync::Arc;
use time::OffsetDateTime;

/// OAuth2 state containing all components needed for the authorization server.
#[derive(Clone)]
pub struct OAuth2State {
    pub registrar: DbRegistrar,
    pub db: Arc<DatabaseConnection>,
    /// Base URL for the OAuth2 server (used for issuer in tokens)
    pub issuer_url: String,
    /// Frontend application URL (used for "back to site" links on auth pages)
    pub frontend_url: String,
    /// Access token lifetime in seconds
    pub access_token_lifetime: i64,
    /// Refresh token lifetime in seconds
    pub refresh_token_lifetime: i64,
    /// Optional GitHub Sponsors URL shown in auth page footers
    pub github_sponsors_url: Option<String>,
    /// Optional Liberapay URL shown in auth page footers
    pub liberapay_url: Option<String>,
}

impl OAuth2State {
    pub fn new(db: Arc<DatabaseConnection>, issuer_url: String, frontend_url: String) -> Self {
        Self {
            registrar: DbRegistrar::new(db.clone()),
            db,
            issuer_url,
            frontend_url,
            access_token_lifetime: 3600,       // 1 hour
            refresh_token_lifetime: 86400 * 7, // 7 days
            github_sponsors_url: None,
            liberapay_url: None,
        }
    }

    /// Create OAuth2State from application config
    pub fn from_config(
        db: Arc<DatabaseConnection>,
        config: &crate::config::OAuth2Config,
        app_config: &crate::config::AppConfig,
    ) -> Self {
        Self {
            registrar: DbRegistrar::new(db.clone()),
            db,
            issuer_url: config.issuer_url.clone(),
            frontend_url: app_config.frontend_url.clone(),
            access_token_lifetime: config.access_token_lifetime,
            refresh_token_lifetime: config.refresh_token_lifetime,
            github_sponsors_url: app_config.github_sponsors_url.clone(),
            liberapay_url: app_config.liberapay_url.clone(),
        }
    }

    /// Ensure the built-in `account-internal` OAuth2 client has the correct
    /// redirect_uri and client_secret for this deployment. Called at startup.
    pub async fn upsert_internal_account_client(
        &self,
        account_client_secret: &str,
    ) -> Result<(), sea_orm::DbErr> {
        let account_redirect_uri =
            format!("{}/oauth2/account", self.issuer_url.trim_end_matches('/'));
        let client_secret = account_client_secret.to_string();

        match oauth2_client::Entity::find_by_id("account-internal")
            .one(self.db.as_ref())
            .await?
        {
            Some(client) => {
                let uris = vec![account_redirect_uri.clone()];
                let uris_json = serde_json::to_string(&uris).unwrap_or_default();
                let mut active: oauth2_client::ActiveModel = client.into();
                active.redirect_uris = Set(uris_json);
                active.secret = Set(Some(client_secret));
                active.is_public = Set(false);
                active.update(self.db.as_ref()).await?;
            }
            None => {
                tracing::warn!(
                    "account-internal OAuth2 client not found; run migrations to create it"
                );
            }
        }

        Ok(())
    }

    /// Generate a secure random token
    pub fn generate_token() -> String {
        use base64::Engine;
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).expect("Failed to generate random bytes");
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Get or create a user by email
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
            receives_alerts: Set(true),
            created_at: Set(now),
            last_login_at: Set(None),
            password_hash: Set(None),
            email_verification_token: Set(None),
            email_verification_expires_at: Set(None),
            password_reset_token: NotSet,
            password_reset_expires_at: NotSet,
            timezone: Set("UTC".to_string()),
        };

        user.insert(self.db.as_ref()).await
    }

    /// Mark a user's email as verified
    pub async fn verify_user_email(&self, user_id: &str) -> Result<(), sea_orm::DbErr> {
        if let Some(user) = oauth2_user::Entity::find_by_id(user_id)
            .one(self.db.as_ref())
            .await?
        {
            let mut active: oauth2_user::ActiveModel = user.into();
            active.email_verified = Set(true);
            active.update(self.db.as_ref()).await?;
        }
        Ok(())
    }

    /// Update user's last login time
    pub async fn update_last_login(&self, user_id: &str) -> Result<(), sea_orm::DbErr> {
        if let Some(user) = oauth2_user::Entity::find_by_id(user_id)
            .one(self.db.as_ref())
            .await?
        {
            let mut active: oauth2_user::ActiveModel = user.into();
            active.last_login_at = Set(Some(OffsetDateTime::now_utc()));
            active.update(self.db.as_ref()).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use migration::{Migrator, MigratorTrait};
    use sea_orm::Database;

    async fn make_db() -> Arc<DatabaseConnection> {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        Arc::new(db)
    }

    fn make_state(db: Arc<DatabaseConnection>) -> OAuth2State {
        OAuth2State::new(
            db,
            "https://auth.example.com".to_string(),
            "https://app.example.com".to_string(),
        )
    }

    // ── generate_token ────────────────────────────────────────────────────────

    #[test]
    fn generate_token_is_non_empty() {
        let tok = OAuth2State::generate_token();
        assert!(!tok.is_empty());
    }

    #[test]
    fn generate_token_is_url_safe_base64() {
        let tok = OAuth2State::generate_token();
        assert!(
            tok.chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        );
    }

    #[test]
    fn generate_token_differs_each_call() {
        let a = OAuth2State::generate_token();
        let b = OAuth2State::generate_token();
        assert_ne!(a, b);
    }

    // ── new ───────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn new_sets_default_lifetimes() {
        let db = make_db().await;
        let state = make_state(db);
        assert_eq!(state.access_token_lifetime, 3600);
        assert_eq!(state.refresh_token_lifetime, 86400 * 7);
        assert_eq!(state.issuer_url, "https://auth.example.com");
        assert_eq!(state.frontend_url, "https://app.example.com");
    }

    // ── get_or_create_user ────────────────────────────────────────────────────

    #[tokio::test]
    async fn get_or_create_user_creates_new_user() {
        let db = make_db().await;
        let state = make_state(db);
        let user = state.get_or_create_user("alice@example.com").await.unwrap();
        assert_eq!(user.email, "alice@example.com");
        assert!(!user.email_verified);
    }

    #[tokio::test]
    async fn get_or_create_user_returns_existing_user() {
        let db = make_db().await;
        let state = make_state(db);
        let first = state.get_or_create_user("bob@example.com").await.unwrap();
        let second = state.get_or_create_user("bob@example.com").await.unwrap();
        assert_eq!(first.id, second.id);
    }

    // ── verify_user_email ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn verify_user_email_sets_verified() {
        let db = make_db().await;
        let state = make_state(db.clone());
        let user = state.get_or_create_user("carol@example.com").await.unwrap();
        assert!(!user.email_verified);

        state.verify_user_email(&user.id).await.unwrap();

        let updated = oauth2_user::Entity::find_by_id(&user.id)
            .one(db.as_ref())
            .await
            .unwrap()
            .unwrap();
        assert!(updated.email_verified);
    }

    // ── update_last_login ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn update_last_login_sets_timestamp() {
        let db = make_db().await;
        let state = make_state(db.clone());
        let user = state.get_or_create_user("dave@example.com").await.unwrap();
        assert!(user.last_login_at.is_none());

        state.update_last_login(&user.id).await.unwrap();

        let updated = oauth2_user::Entity::find_by_id(&user.id)
            .one(db.as_ref())
            .await
            .unwrap()
            .unwrap();
        assert!(updated.last_login_at.is_some());
    }
}
