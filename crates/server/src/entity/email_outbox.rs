use sea_orm::entity::prelude::*;
use time::OffsetDateTime;

/// Status values for `email_outbox.status`.
pub const STATUS_PENDING: &str = "pending";
pub const STATUS_SENT: &str = "sent";
pub const STATUS_FAILED: &str = "failed";
pub const STATUS_EXPIRED: &str = "expired";

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "email_outbox")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub to_email: String,
    pub subject: String,
    /// `None` for plain-text-only emails.
    pub html_body: Option<String>,
    pub text_body: String,
    /// One of: "pending", "sent", "failed", "expired".
    pub status: String,
    pub attempts: i32,
    pub max_attempts: i32,
    /// Earliest time the worker may attempt delivery.
    pub next_attempt_at: OffsetDateTime,
    /// If set, the email is stale after this time and will not be delivered.
    /// Used for magic-link emails whose embedded JWT token has a 1-hour TTL.
    pub expires_at: Option<OffsetDateTime>,
    pub last_error: Option<String>,
    pub created_at: OffsetDateTime,
    pub sent_at: Option<OffsetDateTime>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
