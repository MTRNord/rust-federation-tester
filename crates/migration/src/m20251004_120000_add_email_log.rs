use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

/// Add email log table to track all alert emails sent over time
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(EmailLog::Table)
                    .if_not_exists()
                    .col(pk_auto(EmailLog::Id))
                    .col(integer(EmailLog::AlertId))
                    .col(string(EmailLog::Email))
                    .col(string(EmailLog::ServerName))
                    .col(
                        ColumnDef::new(EmailLog::EmailType)
                            .string()
                            .not_null()
                            .comment("Type of email: 'failure' or 'recovery'"),
                    )
                    .col(
                        timestamp_with_time_zone(EmailLog::SentAt)
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        integer(EmailLog::FailureCount)
                            .comment("Failure count at time of sending (for failure emails)"),
                    )
                    .index(
                        Index::create()
                            .name("idx_email_log_sent_at")
                            .col(EmailLog::SentAt),
                    )
                    .index(
                        Index::create()
                            .name("idx_email_log_alert_id")
                            .col(EmailLog::AlertId),
                    )
                    .index(
                        Index::create()
                            .name("idx_email_log_server_name")
                            .col(EmailLog::ServerName),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
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
