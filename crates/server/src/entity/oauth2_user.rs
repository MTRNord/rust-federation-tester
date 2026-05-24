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
    /// Whether the primary login email receives alert notification emails.
    pub receives_alerts: bool,
    /// IANA timezone name used for quiet-hours interpretation (e.g. "Europe/Berlin").
    pub timezone: String,
    /// Argon2 hashed password (NULL for magic link only users)
    #[serde(skip_serializing)]
    pub password_hash: Option<String>,
    /// Token for email verification (used during registration)
    #[serde(skip_serializing)]
    pub email_verification_token: Option<String>,
    /// When the email verification token expires
    #[serde(skip_serializing)]
    pub email_verification_expires_at: Option<OffsetDateTime>,
    /// Token for password reset (sent by email)
    #[serde(skip_serializing)]
    pub password_reset_token: Option<String>,
    /// When the password reset token expires
    #[serde(skip_serializing)]
    pub password_reset_expires_at: Option<OffsetDateTime>,
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

    /// Check if the password reset token is still valid
    pub fn is_password_reset_valid(&self) -> bool {
        match (&self.password_reset_token, &self.password_reset_expires_at) {
            (Some(_), Some(expires_at)) => *expires_at > OffsetDateTime::now_utc(),
            _ => false,
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

#[cfg(test)]
mod tests {
    use super::*;
    use time::OffsetDateTime;

    fn base_user() -> Model {
        Model {
            id: "u1".into(),
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
        }
    }

    #[test]
    fn has_password_false_when_none() {
        assert!(!base_user().has_password());
    }

    #[test]
    fn has_password_true_when_set() {
        let mut u = base_user();
        u.password_hash = Some("hash".into());
        assert!(u.has_password());
    }

    #[test]
    fn has_pending_verification_false_when_no_token() {
        assert!(!base_user().has_pending_verification());
    }

    #[test]
    fn has_pending_verification_false_when_only_token_no_expiry() {
        let mut u = base_user();
        u.email_verification_token = Some("tok".into());
        // expires_at is None → false
        assert!(!u.has_pending_verification());
    }

    #[test]
    fn has_pending_verification_true_when_future_expiry() {
        let mut u = base_user();
        u.email_verification_token = Some("tok".into());
        u.email_verification_expires_at =
            Some(OffsetDateTime::now_utc() + time::Duration::hours(1));
        assert!(u.has_pending_verification());
    }

    #[test]
    fn has_pending_verification_false_when_expired() {
        let mut u = base_user();
        u.email_verification_token = Some("tok".into());
        u.email_verification_expires_at =
            Some(OffsetDateTime::now_utc() - time::Duration::seconds(1));
        assert!(!u.has_pending_verification());
    }

    #[test]
    fn is_verification_expired_true_when_no_expiry() {
        assert!(base_user().is_verification_expired());
    }

    #[test]
    fn is_verification_expired_true_when_past() {
        let mut u = base_user();
        u.email_verification_expires_at =
            Some(OffsetDateTime::now_utc() - time::Duration::seconds(1));
        assert!(u.is_verification_expired());
    }

    #[test]
    fn is_verification_expired_false_when_future() {
        let mut u = base_user();
        u.email_verification_expires_at =
            Some(OffsetDateTime::now_utc() + time::Duration::hours(1));
        assert!(!u.is_verification_expired());
    }

    #[test]
    fn is_password_reset_valid_false_when_no_token() {
        assert!(!base_user().is_password_reset_valid());
    }

    #[test]
    fn is_password_reset_valid_false_when_only_token_no_expiry() {
        let mut u = base_user();
        u.password_reset_token = Some("reset".into());
        assert!(!u.is_password_reset_valid());
    }

    #[test]
    fn is_password_reset_valid_true_when_future() {
        let mut u = base_user();
        u.password_reset_token = Some("reset".into());
        u.password_reset_expires_at = Some(OffsetDateTime::now_utc() + time::Duration::hours(1));
        assert!(u.is_password_reset_valid());
    }

    #[test]
    fn is_password_reset_valid_false_when_expired() {
        let mut u = base_user();
        u.password_reset_token = Some("reset".into());
        u.password_reset_expires_at = Some(OffsetDateTime::now_utc() - time::Duration::seconds(1));
        assert!(!u.is_password_reset_valid());
    }
}
