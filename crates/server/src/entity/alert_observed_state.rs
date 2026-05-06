use sea_orm::entity::prelude::*;
use serde::Serialize;
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize)]
#[sea_orm(table_name = "alert_observed_state")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub alert_id: i32,
    /// Self-reported server name from the keys response.
    pub server_name_seen: Option<String>,
    /// JSON array of well-known delegation targets (sorted, deduplicated).
    pub well_known_seen: Option<String>,
    pub version_name_seen: Option<String>,
    pub version_string_seen: Option<String>,
    /// JSON array of TLS cert SHA-256 fingerprints (sorted, deduplicated).
    pub tls_fingerprints_seen: Option<String>,
    /// Earliest certificate expiry across all observed certs.
    pub tls_earliest_expiry_at: Option<OffsetDateTime>,
    /// When the last TLS expiry warning email was sent (for 24-h throttle).
    pub last_tls_expiry_email_at: Option<OffsetDateTime>,
    pub observed_at: OffsetDateTime,
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
