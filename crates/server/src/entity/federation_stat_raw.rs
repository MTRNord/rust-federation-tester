use sea_orm::entity::prelude::*;
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "federation_stat_raw")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub ts: OffsetDateTime,
    pub server_name: String,
    pub federation_ok: bool,
    pub version_name: Option<String>,
    pub version_string: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
