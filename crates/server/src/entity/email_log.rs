//! Per-recipient email audit log for GDPR compliance.
//!
//! Records the email address, type, and timing of every notification sent.
//! This table can be cleared on a per-user GDPR erasure request.
//! For internal operational history (without PII), see [`crate::entity::alert_status_history`].

use sea_orm::entity::prelude::*;
use serde::Serialize;
use time::OffsetDateTime;
use utoipa::ToSchema;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, ToSchema)]
#[sea_orm(table_name = "email_log")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub alert_id: i32,
    pub email: String,
    pub server_name: String,
    pub email_type: String, // "failure" or "recovery"
    pub sent_at: OffsetDateTime,
    pub failure_count: Option<i32>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
