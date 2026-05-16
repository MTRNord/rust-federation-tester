use sea_orm::entity::prelude::*;
use time::OffsetDateTime;

pub const STATUS_PENDING: &str = "pending";
pub const STATUS_DELIVERED: &str = "delivered";
pub const STATUS_FAILED: &str = "failed";

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "webhook_outbox")]
pub struct Model {
    /// UUID v4 string — also used as `event_id` in the delivered payload.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub alert_id: i32,
    pub webhook_id: i32,
    /// e.g. "federation_down", "federation_up", "ping"
    pub event_type: String,
    /// JSON string of the full payload to POST.
    pub payload: String,
    /// One of: "pending", "delivered", "failed".
    pub status: String,
    pub attempts: i32,
    pub max_attempts: i32,
    /// Earliest time the worker may attempt delivery.
    pub next_attempt_at: OffsetDateTime,
    pub last_status_code: Option<i16>,
    pub last_error: Option<String>,
    pub created_at: OffsetDateTime,
    pub delivered_at: Option<OffsetDateTime>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
