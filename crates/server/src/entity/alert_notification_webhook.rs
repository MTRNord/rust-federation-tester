use sea_orm::entity::prelude::*;
use serde::Serialize;
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize)]
#[sea_orm(table_name = "alert_notification_webhook")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub alert_id: i32,
    pub url: String,
    /// HMAC-SHA256 secret; never returned in API GET responses.
    #[serde(skip)]
    pub hmac_secret: Option<String>,
    /// HTTP header name for the signature (default "X-Signature-256").
    pub hmac_header: String,
    /// When true, delivery is deferred during the alert's quiet-hours window.
    pub respect_quiet_hours: bool,
    pub created_at: OffsetDateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::alert::Entity",
        from = "Column::AlertId",
        to = "super::alert::Column::Id"
    )]
    Alert,
}

impl Related<super::alert::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Alert.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
