use sea_orm_migration::prelude::*;

use crate::m20250710_185614_add_alert_table::Alert;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    /// Up:
    /// - SQLite: recreate the `alert` table with `magic_token` nullable, copy data while converting
    ///   empty-string tokens to NULL, then create unique index on `magic_token` and other indexes.
    /// - Postgres/other: ALTER COLUMN to nullable, convert empty-string tokens to NULL, ensure unique index.
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == sea_orm::DatabaseBackend::Sqlite {
            // Create new table with magic_token nullable (preserve other columns)
            manager
                .create_table(
                    Table::create()
                        .table(Alias::new("alert_new"))
                        .col(
                            ColumnDef::new(Alert::Id)
                                .integer()
                                .primary_key()
                                .auto_increment()
                                .not_null(),
                        )
                        .col(ColumnDef::new(Alert::Email).string().not_null())
                        .col(ColumnDef::new(Alert::ServerName).string().not_null())
                        .col(
                            ColumnDef::new(Alert::Verified)
                                .boolean()
                                .default(Expr::value(false))
                                .not_null(),
                        )
                        .col(ColumnDef::new(Alert::MagicToken).string().null()) // now nullable
                        .col(
                            ColumnDef::new(Alert::CreatedAt)
                                .timestamp()
                                .default(Expr::current_timestamp())
                                .not_null(),
                        )
                        .col(ColumnDef::new(Alert::LastCheckAt).timestamp().null())
                        .col(ColumnDef::new(Alert::LastFailureAt).timestamp().null())
                        .col(ColumnDef::new(Alert::LastSuccessAt).timestamp().null())
                        .col(ColumnDef::new(Alert::LastEmailSentAt).timestamp().null())
                        .col(
                            ColumnDef::new(Alert::FailureCount)
                                .integer()
                                .not_null()
                                .default(Expr::value(0)),
                        )
                        .col(
                            ColumnDef::new(Alert::IsCurrentlyFailing)
                                .boolean()
                                .not_null()
                                .default(Expr::value(false)),
                        )
                        .col(ColumnDef::new(Alert::UserId).string().null())
                        .col(ColumnDef::new(Alert::LastRecoveryAt).timestamp().null())
                        .to_owned(),
                )
                .await?;

            // Copy rows, converting empty-string magic_token -> NULL
            let copy_sql = r#"
                INSERT INTO alert_new (
                    id, email, server_name, verified, magic_token, created_at,
                    last_check_at, last_failure_at, last_success_at, last_email_sent_at,
                    failure_count, is_currently_failing, user_id, last_recovery_at
                )
                SELECT
                    id, email, server_name, verified,
                    CASE WHEN magic_token = '' THEN NULL ELSE magic_token END,
                    created_at,
                    last_check_at, last_failure_at, last_success_at, last_email_sent_at,
                    failure_count, is_currently_failing, user_id, last_recovery_at
                FROM alert;
            "#;

            manager
                .get_connection()
                .execute_unprepared(copy_sql)
                .await?;

            // Replace old table with new table
            manager
                .drop_table(Table::drop().table(Alert::Table).to_owned())
                .await?;
            manager
                .rename_table(
                    Table::rename()
                        .table(Alias::new("alert_new"), Alert::Table)
                        .to_owned(),
                )
                .await?;

            // Create unique index on magic_token (unique applies only to non-NULL values in SQLite)
            manager
                .create_index(
                    Index::create()
                        .if_not_exists()
                        .name("idx_magic_token_unique")
                        .table(Alert::Table)
                        .col(Alert::MagicToken)
                        .unique()
                        .to_owned(),
                )
                .await?;

            // Recreate composite unique index (email, server_name) and user_id index
            manager
                .create_index(
                    Index::create()
                        .if_not_exists()
                        .name("idx_email_server_name_unique")
                        .table(Alert::Table)
                        .col(Alert::Email)
                        .col(Alert::ServerName)
                        .unique()
                        .to_owned(),
                )
                .await?;
            manager
                .create_index(
                    Index::create()
                        .if_not_exists()
                        .name("idx_alert_user_id")
                        .table(Alert::Table)
                        .col(Alert::UserId)
                        .to_owned(),
                )
                .await
        } else {
            // Non-SQLite: alter column to be nullable
            manager
                .alter_table(
                    Table::alter()
                        .table(Alert::Table)
                        .modify_column(ColumnDef::new(Alert::MagicToken).string().null())
                        .to_owned(),
                )
                .await?;

            // Convert empty-string tokens to NULL so uniqueness applies only to non-NULL values
            manager
                .get_connection()
                .execute_unprepared("UPDATE alert SET magic_token = NULL WHERE magic_token = ''")
                .await?;

            // Ensure unique index exists on magic_token (unique for non-NULL)
            let _ = manager
                .create_index(
                    Index::create()
                        .if_not_exists()
                        .name("idx_magic_token_unique")
                        .table(Alert::Table)
                        .col(Alert::MagicToken)
                        .unique()
                        .to_owned(),
                )
                .await;

            Ok(())
        }
    }

    /// Down:
    /// - SQLite: recreate table with magic_token NOT NULL (convert NULL -> empty string on copy)
    /// - Non-SQLite: convert NULL -> empty string then alter column to NOT NULL
    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == sea_orm::DatabaseBackend::Sqlite {
            // Create new table with magic_token NOT NULL and unique
            manager
                .create_table(
                    Table::create()
                        .table(Alias::new("alert_new"))
                        .col(
                            ColumnDef::new(Alert::Id)
                                .integer()
                                .primary_key()
                                .auto_increment()
                                .not_null(),
                        )
                        .col(ColumnDef::new(Alert::Email).string().not_null())
                        .col(ColumnDef::new(Alert::ServerName).string().not_null())
                        .col(
                            ColumnDef::new(Alert::Verified)
                                .boolean()
                                .default(Expr::value(false))
                                .not_null(),
                        )
                        .col(
                            ColumnDef::new(Alert::MagicToken)
                                .string()
                                .not_null()
                                .unique_key(), // restore NOT NULL + UNIQUE
                        )
                        .col(
                            ColumnDef::new(Alert::CreatedAt)
                                .timestamp()
                                .default(Expr::current_timestamp())
                                .not_null(),
                        )
                        .col(ColumnDef::new(Alert::LastCheckAt).timestamp().null())
                        .col(ColumnDef::new(Alert::LastFailureAt).timestamp().null())
                        .col(ColumnDef::new(Alert::LastSuccessAt).timestamp().null())
                        .col(ColumnDef::new(Alert::LastEmailSentAt).timestamp().null())
                        .col(
                            ColumnDef::new(Alert::FailureCount)
                                .integer()
                                .not_null()
                                .default(Expr::value(0)),
                        )
                        .col(
                            ColumnDef::new(Alert::IsCurrentlyFailing)
                                .boolean()
                                .not_null()
                                .default(Expr::value(false)),
                        )
                        .col(ColumnDef::new(Alert::UserId).string().null())
                        .col(ColumnDef::new(Alert::LastRecoveryAt).timestamp().null())
                        .to_owned(),
                )
                .await?;

            // Copy data, converting NULL magic_token -> empty string
            let copy_sql = r#"
                INSERT INTO alert_new (
                    id, email, server_name, verified, magic_token, created_at,
                    last_check_at, last_failure_at, last_success_at, last_email_sent_at,
                    failure_count, is_currently_failing, user_id, last_recovery_at
                )
                SELECT
                    id, email, server_name, verified,
                    CASE WHEN magic_token IS NULL THEN '' ELSE magic_token END,
                    created_at,
                    last_check_at, last_failure_at, last_success_at, last_email_sent_at,
                    failure_count, is_currently_failing, user_id, last_recovery_at
                FROM alert;
            "#;

            manager
                .get_connection()
                .execute_unprepared(copy_sql)
                .await?;

            // Replace tables
            manager
                .drop_table(Table::drop().table(Alert::Table).to_owned())
                .await?;
            manager
                .rename_table(
                    Table::rename()
                        .table(Alias::new("alert_new"), Alert::Table)
                        .to_owned(),
                )
                .await?;

            // Recreate indexes: composite unique (email, server_name) and user_id
            manager
                .create_index(
                    Index::create()
                        .if_not_exists()
                        .name("idx_email_server_name_unique")
                        .table(Alert::Table)
                        .col(Alert::Email)
                        .col(Alert::ServerName)
                        .unique()
                        .to_owned(),
                )
                .await?;
            manager
                .create_index(
                    Index::create()
                        .if_not_exists()
                        .name("idx_alert_user_id")
                        .table(Alert::Table)
                        .col(Alert::UserId)
                        .to_owned(),
                )
                .await?;

            Ok(())
        } else {
            // Non-SQLite: convert NULL magic_token -> empty string then alter to NOT NULL
            manager
                .get_connection()
                .execute_unprepared("UPDATE alert SET magic_token = '' WHERE magic_token IS NULL")
                .await?;

            manager
                .alter_table(
                    Table::alter()
                        .table(Alert::Table)
                        .modify_column(ColumnDef::new(Alert::MagicToken).string().not_null())
                        .to_owned(),
                )
                .await?;

            // Ensure unique index exists (attempt create if not present)
            let _ = manager
                .create_index(
                    Index::create()
                        .if_not_exists()
                        .name("idx_magic_token_unique")
                        .table(Alert::Table)
                        .col(Alert::MagicToken)
                        .unique()
                        .to_owned(),
                )
                .await;

            Ok(())
        }
    }
}
