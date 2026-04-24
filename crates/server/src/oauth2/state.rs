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
        }
    }

    /// Create OAuth2State from application config
    pub fn from_config(
        db: Arc<DatabaseConnection>,
        config: &crate::config::OAuth2Config,
        frontend_url: &str,
    ) -> Self {
        Self {
            registrar: DbRegistrar::new(db.clone()),
            db,
            issuer_url: config.issuer_url.clone(),
            frontend_url: frontend_url.to_string(),
            access_token_lifetime: config.access_token_lifetime,
            refresh_token_lifetime: config.refresh_token_lifetime,
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
