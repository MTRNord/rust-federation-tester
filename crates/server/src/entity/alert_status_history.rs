use sea_orm::entity::prelude::*;
use serde::Serialize;
use time::OffsetDateTime;
use utoipa::ToSchema;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, ToSchema)]
#[sea_orm(table_name = "alert_status_history")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub alert_id: i32,
    pub server_name: String,
    pub event_type: String, // "check_fail", "check_ok", "email_failure", "email_recovery", "email_reminder"
    pub federation_ok: bool,
    pub failure_count: i32,
    pub created_at: OffsetDateTime,
    pub details: Option<String>,
    pub failure_reason: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
