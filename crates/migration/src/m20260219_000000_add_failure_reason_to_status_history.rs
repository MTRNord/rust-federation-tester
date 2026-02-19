use sea_orm_migration::{prelude::*, schema::*};

use crate::m20260218_000000_add_alert_status_history::AlertStatusHistory;

#[derive(DeriveMigrationName)]
pub struct Migration;

/// Add failure_reason column to alert_status_history for storing the specific
/// error message at the time of a check failure, useful for debugging transient
/// failures that self-resolve before the user can investigate.
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(AlertStatusHistory::Table)
                    .add_column(text_null(AlertStatusHistory::FailureReason).to_owned())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(AlertStatusHistory::Table)
                    .drop_column(AlertStatusHistory::FailureReason)
                    .to_owned(),
            )
            .await
    }
}
