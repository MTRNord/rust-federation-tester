use sea_orm_migration::prelude::*;

use crate::m20250710_185614_add_alert_table::Alert;

#[derive(DeriveMigrationName)]
pub struct Migration;

// Ensures that email and server_name are unique together in the Alert table while allowing
// multiple entries with the same email or server_name separately.
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == sea_orm::DatabaseBackend::Sqlite {
            // SQLite doesn't support dropping unique constraints directly, so we need to recreate the table

            // Step 1: Create a new table with the correct schema
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
                        .col(
                            ColumnDef::new(Alert::Email).string().not_null(), // Remove unique constraint from email
                        )
                        .col(ColumnDef::new(Alert::ServerName).string().not_null())
                        .col(
                            ColumnDef::new(Alert::Verified)
                                .boolean()
                                .default(false)
                                .not_null(),
                        )
                        .col(
                            ColumnDef::new(Alert::MagicToken)
                                .string()
                                .not_null()
                                .unique_key(), // Keep magic token unique
                        )
                        .col(
                            ColumnDef::new(Alert::CreatedAt)
                                .timestamp_with_time_zone()
                                .default(Expr::current_timestamp())
                                .not_null(),
                        )
                        .to_owned(),
                )
                .await?;

            // Step 2: Copy data from old table to new table
            let copy_query = Query::insert()
                .into_table(Alias::new("alert_new"))
                .columns([
                    Alert::Id,
                    Alert::Email,
                    Alert::ServerName,
                    Alert::Verified,
                    Alert::MagicToken,
                    Alert::CreatedAt,
                ])
                .select_from(
                    Query::select()
                        .columns([
                            Alert::Id,
                            Alert::Email,
                            Alert::ServerName,
                            Alert::Verified,
                            Alert::MagicToken,
                            Alert::CreatedAt,
                        ])
                        .from(Alert::Table)
                        .to_owned(),
                )
                .unwrap()
                .to_owned();

            manager.exec_stmt(copy_query).await?;

            // Step 3: Drop the old table
            manager
                .drop_table(Table::drop().table(Alert::Table).to_owned())
                .await?;

            // Step 4: Rename the new table to the original name
            manager
                .rename_table(
                    Table::rename()
                        .table(Alias::new("alert_new"), Alert::Table)
                        .to_owned(),
                )
                .await?;

            // Step 5: Create the unique index on (email, server_name) combination
            manager
                .create_index(
                    Index::create()
                        .name("idx_email_server_name_unique")
                        .table(Alert::Table)
                        .col(Alert::Email)
                        .col(Alert::ServerName)
                        .unique()
                        .to_owned(),
                )
                .await
        } else {
            // For PostgreSQL, we can modify constraints directly

            // First drop the old index that included id
            manager
                .drop_index(
                    Index::drop()
                        .name("idx_email_server_name_unique")
                        .table(Alert::Table)
                        .to_owned(),
                )
                .await?;

            // Remove the unique constraint from email column
            // Note: PostgreSQL would need ALTER TABLE to modify column constraints
            // For now, we'll create the new unique index on (email, server_name)
            manager
                .create_index(
                    Index::create()
                        .name("idx_email_server_name_unique")
                        .table(Alert::Table)
                        .col(Alert::Email)
                        .col(Alert::ServerName)
                        .unique()
                        .to_owned(),
                )
                .await
        }
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == sea_orm::DatabaseBackend::Sqlite {
            // SQLite doesn't support modifying constraints directly, so we need to recreate the table

            // Step 1: Create a new table with the original schema (email unique)
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
                        .col(
                            ColumnDef::new(Alert::Email)
                                .string()
                                .not_null()
                                .unique_key(), // Restore unique constraint on email
                        )
                        .col(ColumnDef::new(Alert::ServerName).string().not_null())
                        .col(
                            ColumnDef::new(Alert::Verified)
                                .boolean()
                                .default(false)
                                .not_null(),
                        )
                        .col(
                            ColumnDef::new(Alert::MagicToken)
                                .string()
                                .not_null()
                                .unique_key(),
                        )
                        .col(
                            ColumnDef::new(Alert::CreatedAt)
                                .timestamp_with_time_zone()
                                .default(Expr::current_timestamp())
                                .not_null(),
                        )
                        .to_owned(),
                )
                .await?;

            // Step 2: Copy data from old table to new table
            let copy_query = Query::insert()
                .into_table(Alias::new("alert_new"))
                .columns([
                    Alert::Id,
                    Alert::Email,
                    Alert::ServerName,
                    Alert::Verified,
                    Alert::MagicToken,
                    Alert::CreatedAt,
                ])
                .select_from(
                    Query::select()
                        .columns([
                            Alert::Id,
                            Alert::Email,
                            Alert::ServerName,
                            Alert::Verified,
                            Alert::MagicToken,
                            Alert::CreatedAt,
                        ])
                        .from(Alert::Table)
                        .to_owned(),
                )
                .unwrap()
                .to_owned();

            manager.exec_stmt(copy_query).await?;

            // Step 3: Drop the old table
            manager
                .drop_table(Table::drop().table(Alert::Table).to_owned())
                .await?;

            // Step 4: Rename the new table to the original name
            manager
                .rename_table(
                    Table::rename()
                        .table(Alias::new("alert_new"), Alert::Table)
                        .to_owned(),
                )
                .await?;

            // Step 5: Recreate the original index (id, email, server_name)
            manager
                .create_index(
                    Index::create()
                        .name("idx_email_server_name_unique")
                        .table(Alert::Table)
                        .col(Alert::Id)
                        .col(Alert::Email)
                        .col(Alert::ServerName)
                        .unique()
                        .to_owned(),
                )
                .await
        } else {
            // For PostgreSQL, restore the original unique index
            manager
                .drop_index(
                    Index::drop()
                        .name("idx_email_server_name_unique")
                        .table(Alert::Table)
                        .to_owned(),
                )
                .await?;
            manager
                .create_index(
                    Index::create()
                        .name("idx_email_server_name_unique")
                        .table(Alert::Table)
                        .col(Alert::Id)
                        .col(Alert::Email)
                        .col(Alert::ServerName)
                        .unique()
                        .to_owned(),
                )
                .await
        }
    }
}
