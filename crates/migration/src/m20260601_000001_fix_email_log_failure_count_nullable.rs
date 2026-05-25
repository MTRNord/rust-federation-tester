use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

/// Make email_log.failure_count nullable.
///
/// The original migration used the `integer()` schema helper which adds NOT NULL
/// by default. Recovery and other non-failure emails have no meaningful failure
/// count, so the column must be nullable. SQLite does not support ALTER COLUMN,
/// so we recreate the table.
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == sea_orm::DatabaseBackend::Sqlite {
            manager
                .create_table(
                    Table::create()
                        .table(Alias::new("email_log_new"))
                        .col(
                            ColumnDef::new(EmailLog::Id)
                                .integer()
                                .primary_key()
                                .auto_increment()
                                .not_null(),
                        )
                        .col(ColumnDef::new(EmailLog::AlertId).integer().not_null())
                        .col(ColumnDef::new(EmailLog::Email).string().not_null())
                        .col(ColumnDef::new(EmailLog::ServerName).string().not_null())
                        .col(ColumnDef::new(EmailLog::EmailType).string().not_null())
                        .col(
                            ColumnDef::new(EmailLog::SentAt)
                                .timestamp_with_time_zone()
                                .not_null()
                                .default(Expr::current_timestamp()),
                        )
                        .col(ColumnDef::new(EmailLog::FailureCount).integer().null()) // now nullable
                        .to_owned(),
                )
                .await?;

            manager
                .get_connection()
                .execute_unprepared(
                    "INSERT INTO email_log_new (id, alert_id, email, server_name, email_type, sent_at, failure_count) \
                     SELECT id, alert_id, email, server_name, email_type, sent_at, failure_count FROM email_log",
                )
                .await?;

            manager
                .drop_table(Table::drop().table(Alias::new("email_log")).to_owned())
                .await?;

            manager
                .get_connection()
                .execute_unprepared("ALTER TABLE email_log_new RENAME TO email_log")
                .await?;

            // Recreate indexes
            manager
                .create_index(
                    Index::create()
                        .name("idx_email_log_sent_at")
                        .table(Alias::new("email_log"))
                        .col(EmailLog::SentAt)
                        .to_owned(),
                )
                .await?;
            manager
                .create_index(
                    Index::create()
                        .name("idx_email_log_alert_id")
                        .table(Alias::new("email_log"))
                        .col(EmailLog::AlertId)
                        .to_owned(),
                )
                .await?;
            manager
                .create_index(
                    Index::create()
                        .name("idx_email_log_server_name")
                        .table(Alias::new("email_log"))
                        .col(EmailLog::ServerName)
                        .to_owned(),
                )
                .await?;
        } else {
            // PostgreSQL / MySQL support ALTER COLUMN directly
            manager
                .get_connection()
                .execute_unprepared(
                    "ALTER TABLE email_log ALTER COLUMN failure_count DROP NOT NULL",
                )
                .await?;
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Revert: make the column NOT NULL again (existing NULLs become 0)
        if manager.get_database_backend() == sea_orm::DatabaseBackend::Sqlite {
            manager
                .create_table(
                    Table::create()
                        .table(Alias::new("email_log_new"))
                        .col(
                            ColumnDef::new(EmailLog::Id)
                                .integer()
                                .primary_key()
                                .auto_increment()
                                .not_null(),
                        )
                        .col(ColumnDef::new(EmailLog::AlertId).integer().not_null())
                        .col(ColumnDef::new(EmailLog::Email).string().not_null())
                        .col(ColumnDef::new(EmailLog::ServerName).string().not_null())
                        .col(ColumnDef::new(EmailLog::EmailType).string().not_null())
                        .col(
                            ColumnDef::new(EmailLog::SentAt)
                                .timestamp_with_time_zone()
                                .not_null()
                                .default(Expr::current_timestamp()),
                        )
                        .col(
                            ColumnDef::new(EmailLog::FailureCount)
                                .integer()
                                .not_null()
                                .default(Expr::value(0)),
                        )
                        .to_owned(),
                )
                .await?;

            manager
                .get_connection()
                .execute_unprepared(
                    "INSERT INTO email_log_new (id, alert_id, email, server_name, email_type, sent_at, failure_count) \
                     SELECT id, alert_id, email, server_name, email_type, sent_at, COALESCE(failure_count, 0) FROM email_log",
                )
                .await?;

            manager
                .drop_table(Table::drop().table(Alias::new("email_log")).to_owned())
                .await?;

            manager
                .get_connection()
                .execute_unprepared("ALTER TABLE email_log_new RENAME TO email_log")
                .await?;

            // Recreate indexes
            manager
                .create_index(
                    Index::create()
                        .name("idx_email_log_sent_at")
                        .table(Alias::new("email_log"))
                        .col(EmailLog::SentAt)
                        .to_owned(),
                )
                .await?;
            manager
                .create_index(
                    Index::create()
                        .name("idx_email_log_alert_id")
                        .table(Alias::new("email_log"))
                        .col(EmailLog::AlertId)
                        .to_owned(),
                )
                .await?;
            manager
                .create_index(
                    Index::create()
                        .name("idx_email_log_server_name")
                        .table(Alias::new("email_log"))
                        .col(EmailLog::ServerName)
                        .to_owned(),
                )
                .await?;
        } else {
            manager
                .get_connection()
                .execute_unprepared(
                    "UPDATE email_log SET failure_count = 0 WHERE failure_count IS NULL; \
                     ALTER TABLE email_log ALTER COLUMN failure_count SET NOT NULL",
                )
                .await?;
        }

        Ok(())
    }
}

#[derive(Iden)]
enum EmailLog {
    Id,
    AlertId,
    Email,
    ServerName,
    EmailType,
    SentAt,
    FailureCount,
}
