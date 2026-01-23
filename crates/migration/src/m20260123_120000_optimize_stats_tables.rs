//! Migration to optimize statistics tables.
//!
//! - Adds index on `ts` column in `federation_stat_raw` for efficient time-based queries
//! - Adds index on `server_name` column for efficient lookups

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 1. Add index on ts column in federation_stat_raw for efficient ORDER BY ts queries
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_federation_stat_raw_ts")
                    .table(FederationStatRaw::Table)
                    .col(FederationStatRaw::Ts)
                    .to_owned(),
            )
            .await?;

        // 2. Add index on server_name for efficient lookups and grouping
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_federation_stat_raw_server_name")
                    .table(FederationStatRaw::Table)
                    .col(FederationStatRaw::ServerName)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name("idx_federation_stat_raw_ts")
                    .table(FederationStatRaw::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_federation_stat_raw_server_name")
                    .table(FederationStatRaw::Table)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum FederationStatRaw {
    Table,
    Ts,
    ServerName,
}
