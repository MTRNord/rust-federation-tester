use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

/// Add alert_status_history table for audit trail of check results and email events
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(AlertStatusHistory::Table)
                    .if_not_exists()
                    .col(pk_auto(AlertStatusHistory::Id))
                    .col(integer(AlertStatusHistory::AlertId).not_null())
                    .col(string(AlertStatusHistory::ServerName).not_null())
                    .col(string(AlertStatusHistory::EventType).not_null())
                    .col(boolean(AlertStatusHistory::FederationOk).not_null())
                    .col(
                        integer(AlertStatusHistory::FailureCount)
                            .not_null()
                            .default(0),
                    )
                    .col(
                        timestamp_with_time_zone(AlertStatusHistory::CreatedAt)
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(text_null(AlertStatusHistory::Details))
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_alert_status_history_alert_id")
                    .table(AlertStatusHistory::Table)
                    .col(AlertStatusHistory::AlertId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_alert_status_history_created_at")
                    .table(AlertStatusHistory::Table)
                    .col(AlertStatusHistory::CreatedAt)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name("idx_alert_status_history_created_at")
                    .table(AlertStatusHistory::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_alert_status_history_alert_id")
                    .table(AlertStatusHistory::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_table(Table::drop().table(AlertStatusHistory::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
pub enum AlertStatusHistory {
    Table,
    Id,
    AlertId,
    ServerName,
    EventType,
    FederationOk,
    FailureCount,
    CreatedAt,
    Details,
    FailureReason,
}
