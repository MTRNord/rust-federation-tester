use sea_orm::entity::prelude::*;
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize)]
#[sea_orm(table_name = "alerts")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub email: String,
    pub server_name: String,
    pub verified: bool,
    pub magic_token: String,
    pub created_at: OffsetDateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
