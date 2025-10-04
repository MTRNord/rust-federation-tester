use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

/// Add email log table to track all alert emails sent over time
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Create the table
        manager
            .create_table(
                Table::create()
                    .table(EmailLog::Table)
                    .if_not_exists()
                    .col(pk_auto(EmailLog::Id))
                    .col(integer(EmailLog::AlertId).not_null())
                    .col(string(EmailLog::Email).not_null())
                    .col(string(EmailLog::ServerName).not_null())
                    .col(string(EmailLog::EmailType).not_null())
                    .col(
                        timestamp_with_time_zone(EmailLog::SentAt)
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(integer(EmailLog::FailureCount))
                    .to_owned(),
            )
            .await?;

        // Create indexes
        manager
            .create_index(
                Index::create()
                    .name("idx_email_log_sent_at")
                    .table(EmailLog::Table)
                    .col(EmailLog::SentAt)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_email_log_alert_id")
                    .table(EmailLog::Table)
                    .col(EmailLog::AlertId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_email_log_server_name")
                    .table(EmailLog::Table)
                    .col(EmailLog::ServerName)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Drop indexes first
        manager
            .drop_index(
                Index::drop()
                    .name("idx_email_log_server_name")
                    .table(EmailLog::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_email_log_alert_id")
                    .table(EmailLog::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_email_log_sent_at")
                    .table(EmailLog::Table)
                    .to_owned(),
            )
            .await?;

        // Then drop the table
        manager
            .drop_table(Table::drop().table(EmailLog::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
pub enum EmailLog {
    Table,
    Id,
    AlertId,
    Email,
    ServerName,
    EmailType,
    SentAt,
    FailureCount,
}
