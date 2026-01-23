//! OAuth2 Identity entity - links users to external identity providers.
//!
//! Supports multiple providers per user (Google, GitHub, Matrix OIDC, etc.)
//! enabling federated identity like Keycloak/Auth0.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Known identity providers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdentityProvider {
    /// Self-hosted email-based identity (magic link upgrade)
    Email,
    /// Google OAuth2
    Google,
    /// GitHub OAuth2
    GitHub,
    /// Generic OIDC provider (name stored as parameter)
    Oidc(String),
}

impl std::fmt::Display for IdentityProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdentityProvider::Email => write!(f, "email"),
            IdentityProvider::Google => write!(f, "google"),
            IdentityProvider::GitHub => write!(f, "github"),
            IdentityProvider::Oidc(name) => write!(f, "oidc:{}", name),
        }
    }
}

impl From<&str> for IdentityProvider {
    fn from(s: &str) -> Self {
        match s {
            "email" => IdentityProvider::Email,
            "google" => IdentityProvider::Google,
            "github" => IdentityProvider::GitHub,
            other if other.starts_with("oidc:") => {
                IdentityProvider::Oidc(other.strip_prefix("oidc:").unwrap_or("").to_string())
            }
            other => IdentityProvider::Oidc(other.to_string()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "oauth2_identity")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    /// Reference to oauth2_user.id
    pub user_id: String,
    /// Identity provider name (e.g., "email", "google", "github", "matrix_oidc")
    pub provider: String,
    /// Provider-specific user identifier (subject claim in OIDC)
    pub subject: String,
    /// Email from the provider (may differ from oauth2_user.email)
    pub email: Option<String>,
    /// Display name from the provider
    pub name: Option<String>,
    /// Stored access token for provider (encrypted in production)
    pub access_token: Option<String>,
    /// Stored refresh token for provider (encrypted in production)
    pub refresh_token: Option<String>,
    /// When the access token expires
    pub token_expires_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl Model {
    /// Get the identity provider enum from the stored string.
    pub fn provider_type(&self) -> IdentityProvider {
        IdentityProvider::from(self.provider.as_str())
    }

    /// Check if the stored tokens are expired.
    pub fn is_token_expired(&self) -> bool {
        self.token_expires_at
            .is_some_and(|exp| exp < OffsetDateTime::now_utc())
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::oauth2_user::Entity",
        from = "Column::UserId",
        to = "super::oauth2_user::Column::Id"
    )]
    User,
}

impl Related<super::oauth2_user::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::User.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
