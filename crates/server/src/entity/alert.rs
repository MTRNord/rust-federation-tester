use sea_orm::entity::prelude::*;
use serde::Serialize;
use time::OffsetDateTime;
use utoipa::ToSchema;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, ToSchema)]
#[sea_orm(table_name = "alert")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub email: String,
    pub server_name: String,
    pub verified: bool,
    pub magic_token: String,
    pub created_at: OffsetDateTime,
    pub last_check_at: Option<OffsetDateTime>,
    pub last_failure_at: Option<OffsetDateTime>,
    pub last_success_at: Option<OffsetDateTime>,
    pub last_email_sent_at: Option<OffsetDateTime>,
    pub failure_count: i32,
    pub is_currently_failing: bool,
    /// Optional link to OAuth2 user for migrated accounts.
    /// Null for legacy magic-link-only alerts.
    pub user_id: Option<String>,
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
