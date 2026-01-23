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
