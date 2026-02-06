//! OAuth2 User entity - represents authenticated users.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "oauth2_user")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    #[sea_orm(unique)]
    pub email: String,
    pub email_verified: bool,
    pub name: Option<String>,
    pub created_at: OffsetDateTime,
    pub last_login_at: Option<OffsetDateTime>,
    /// Argon2 hashed password (NULL for magic link only users)
    #[serde(skip_serializing)]
    pub password_hash: Option<String>,
    /// Token for email verification (used during registration)
    #[serde(skip_serializing)]
    pub email_verification_token: Option<String>,
    /// When the email verification token expires
    #[serde(skip_serializing)]
    pub email_verification_expires_at: Option<OffsetDateTime>,
}

impl Model {
    /// Check if user has a password set (can use password login)
    pub fn has_password(&self) -> bool {
        self.password_hash.is_some()
    }

    /// Check if there's a pending email verification that hasn't expired
    pub fn has_pending_verification(&self) -> bool {
        match (
            &self.email_verification_token,
            &self.email_verification_expires_at,
        ) {
            (Some(_), Some(expires_at)) => *expires_at > OffsetDateTime::now_utc(),
            _ => false,
        }
    }

    /// Check if the email verification token has expired
    pub fn is_verification_expired(&self) -> bool {
        match &self.email_verification_expires_at {
            Some(expires_at) => *expires_at <= OffsetDateTime::now_utc(),
            None => true,
        }
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::alert::Entity")]
    Alerts,
    #[sea_orm(has_many = "super::oauth2_identity::Entity")]
    Identities,
}

impl Related<super::alert::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Alerts.def()
    }
}

impl Related<super::oauth2_identity::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Identities.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
