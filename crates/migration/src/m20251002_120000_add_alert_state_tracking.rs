use sea_orm_migration::{prelude::*, schema::*};

use crate::m20250710_185614_add_alert_table::Alert;

#[derive(DeriveMigrationName)]
pub struct Migration;

/// Add fields to track alert state for intelligent email throttling
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Add last_check_at to track when we last checked the server
        manager
            .alter_table(
                Table::alter()
                    .table(Alert::Table)
                    .add_column(
                        timestamp_with_time_zone_null(Alias::new("last_check_at")).to_owned(),
                    )
                    .to_owned(),
            )
            .await?;

        // Add last_failure_at to track when the server last failed
        manager
            .alter_table(
                Table::alter()
                    .table(Alert::Table)
                    .add_column(
                        timestamp_with_time_zone_null(Alias::new("last_failure_at")).to_owned(),
                    )
                    .to_owned(),
            )
            .await?;

        // Add last_success_at to track when the server last succeeded
        manager
            .alter_table(
                Table::alter()
                    .table(Alert::Table)
                    .add_column(
                        timestamp_with_time_zone_null(Alias::new("last_success_at")).to_owned(),
                    )
                    .to_owned(),
            )
            .await?;

        // Add last_email_sent_at to track when we last sent an email
        manager
            .alter_table(
                Table::alter()
                    .table(Alert::Table)
                    .add_column(
                        timestamp_with_time_zone_null(Alias::new("last_email_sent_at")).to_owned(),
                    )
                    .to_owned(),
            )
            .await?;

        // Add failure_count to track consecutive failures
        manager
            .alter_table(
                Table::alter()
                    .table(Alert::Table)
                    .add_column(
                        integer(Alias::new("failure_count"))
                            .default(0)
                            .not_null()
                            .to_owned(),
                    )
                    .to_owned(),
            )
            .await?;

        // Add is_currently_failing to track if the server is currently in a failed state
        manager
            .alter_table(
                Table::alter()
                    .table(Alert::Table)
                    .add_column(
                        boolean(Alias::new("is_currently_failing"))
                            .default(false)
                            .not_null()
                            .to_owned(),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Alert::Table)
                    .drop_column(Alias::new("last_check_at"))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alert::Table)
                    .drop_column(Alias::new("last_failure_at"))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alert::Table)
                    .drop_column(Alias::new("last_success_at"))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alert::Table)
                    .drop_column(Alias::new("last_email_sent_at"))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alert::Table)
                    .drop_column(Alias::new("failure_count"))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alert::Table)
                    .drop_column(Alias::new("is_currently_failing"))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
