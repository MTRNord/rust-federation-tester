use sea_orm_migration::{prelude::*, schema::*};

use crate::m20250710_185614_add_alert_table::Alert;

#[derive(DeriveMigrationName)]
pub struct Migration;

/// Add last_recovery_at column to alert table for flap detection
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Alert::Table)
                    .add_column(
                        timestamp_with_time_zone_null(Alias::new("last_recovery_at")).to_owned(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Alert::Table)
                    .drop_column(Alias::new("last_recovery_at"))
                    .to_owned(),
            )
            .await
    }
}
