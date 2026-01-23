//! OAuth2 Token entity - access and refresh tokens.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "oauth2_token")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    #[sea_orm(unique)]
    pub access_token: String,
    #[sea_orm(unique)]
    pub refresh_token: Option<String>,
    pub token_type: String,
    pub client_id: String,
    pub user_id: String,
    pub scope: String,
    pub access_token_expires_at: OffsetDateTime,
    pub refresh_token_expires_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl Model {
    /// Check if the access token has expired
    pub fn is_access_token_expired(&self) -> bool {
        self.access_token_expires_at < OffsetDateTime::now_utc()
    }

    /// Check if the refresh token has expired (if present)
    pub fn is_refresh_token_expired(&self) -> bool {
        match self.refresh_token_expires_at {
            Some(expires_at) => expires_at < OffsetDateTime::now_utc(),
            None => true, // No refresh token means it's "expired"
        }
    }

    /// Check if this token has been revoked
    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    /// Check if this token is valid for use
    pub fn is_valid(&self) -> bool {
        !self.is_revoked() && !self.is_access_token_expired()
    }

    /// Parse scopes from space-separated string
    pub fn scopes_list(&self) -> Vec<String> {
        self.scope.split_whitespace().map(String::from).collect()
    }

    /// Check if token has a specific scope
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes_list().iter().any(|s| s == scope)
    }
}
