use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(EmailOutbox::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(EmailOutbox::Id)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(EmailOutbox::ToEmail).string().not_null())
                    .col(ColumnDef::new(EmailOutbox::Subject).string().not_null())
                    .col(ColumnDef::new(EmailOutbox::HtmlBody).text().null())
                    .col(ColumnDef::new(EmailOutbox::TextBody).text().not_null())
                    .col(
                        ColumnDef::new(EmailOutbox::Status)
                            .string()
                            .not_null()
                            .default("pending"),
                    )
                    .col(
                        ColumnDef::new(EmailOutbox::Attempts)
                            .integer()
                            .not_null()
                            .default(0),
                    )
                    .col(
                        ColumnDef::new(EmailOutbox::MaxAttempts)
                            .integer()
                            .not_null()
                            .default(5),
                    )
                    .col(
                        ColumnDef::new(EmailOutbox::NextAttemptAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    // Set for emails containing time-sensitive tokens (e.g. magic links).
                    // The worker marks the row "expired" instead of delivering after this time.
                    .col(
                        ColumnDef::new(EmailOutbox::ExpiresAt)
                            .timestamp_with_time_zone()
                            .null(),
                    )
                    .col(ColumnDef::new(EmailOutbox::LastError).text().null())
                    .col(
                        ColumnDef::new(EmailOutbox::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(EmailOutbox::SentAt)
                            .timestamp_with_time_zone()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_email_outbox_status_next_attempt")
                    .table(EmailOutbox::Table)
                    .col(EmailOutbox::Status)
                    .col(EmailOutbox::NextAttemptAt)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name("idx_email_outbox_status_next_attempt")
                    .table(EmailOutbox::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(EmailOutbox::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
pub enum EmailOutbox {
    Table,
    Id,
    ToEmail,
    Subject,
    HtmlBody,
    TextBody,
    Status,
    Attempts,
    MaxAttempts,
    NextAttemptAt,
    ExpiresAt,
    LastError,
    CreatedAt,
    SentAt,
}
