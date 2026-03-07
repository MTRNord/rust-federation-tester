//! Additional email addresses for a user account.
//!
//! The primary login email lives in `oauth2_user.email`.
//! Rows in this table are extra addresses that can receive alert notifications.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "user_email")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub user_id: String,
    #[sea_orm(unique)]
    pub email: String,
    pub verified: bool,
    /// Whether this address receives alert notification emails.
    pub receives_alerts: bool,
    #[serde(skip_serializing)]
    pub verification_token: Option<String>,
    #[serde(skip_serializing)]
    pub verification_expires_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
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

impl Model {
    pub fn is_verification_expired(&self) -> bool {
        match self.verification_expires_at {
            Some(expires_at) => expires_at <= OffsetDateTime::now_utc(),
            None => true,
        }
    }
}
