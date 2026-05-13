use sea_orm_migration::{prelude::*, schema::*};

use crate::m20250710_185614_add_alert_table::Alert;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Alert::Table)
                    .add_column(
                        boolean(Alias::new("quiet_hours_enabled"))
                            .default(false)
                            .not_null()
                            .to_owned(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alert::Table)
                    .add_column(
                        text(Alias::new("quiet_hours_from"))
                            .default("22:00")
                            .not_null()
                            .to_owned(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alert::Table)
                    .add_column(
                        text(Alias::new("quiet_hours_to"))
                            .default("07:00")
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
                    .drop_column(Alias::new("quiet_hours_to"))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alert::Table)
                    .drop_column(Alias::new("quiet_hours_from"))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alert::Table)
                    .drop_column(Alias::new("quiet_hours_enabled"))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
