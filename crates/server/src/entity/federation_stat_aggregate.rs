use sea_orm::entity::prelude::*;
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "federation_stat_aggregate")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub server_name: String,
    pub first_seen_at: OffsetDateTime,
    pub last_seen_at: OffsetDateTime,
    pub req_count: i64,
    pub success_count: i64,
    pub failure_count: i64,
    pub first_version_name: Option<String>,
    pub first_version_string: Option<String>,
    pub last_version_name: Option<String>,
    pub last_version_string: Option<String>,
    pub software_family: Option<String>,
    pub software_version: Option<String>,
    pub unstable_features_enabled: i32,
    pub unstable_features_announced: i32,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
