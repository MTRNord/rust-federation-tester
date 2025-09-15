use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Add unstable features tracking to federation_stat_aggregate table
        // SQLite requires separate ALTER TABLE statements for each column
        manager
            .alter_table(
                Table::alter()
                    .table(FederationStatAggregate::Table)
                    .add_column(
                        ColumnDef::new(FederationStatAggregate::UnstableFeaturesEnabled)
                            .integer()
                            .not_null()
                            .default(0),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(FederationStatAggregate::Table)
                    .add_column(
                        ColumnDef::new(FederationStatAggregate::UnstableFeaturesAnnounced)
                            .integer()
                            .not_null()
                            .default(0),
                    )
                    .to_owned(),
            )
            .await?;

        // Add unstable features data to federation_stat_raw table
        manager
            .alter_table(
                Table::alter()
                    .table(FederationStatRaw::Table)
                    .add_column(
                        ColumnDef::new(FederationStatRaw::UnstableFeaturesEnabled)
                            .text()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(FederationStatRaw::Table)
                    .add_column(
                        ColumnDef::new(FederationStatRaw::UnstableFeaturesAnnounced)
                            .text()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Drop columns from federation_stat_aggregate table
        // SQLite requires separate ALTER TABLE statements for each column
        manager
            .alter_table(
                Table::alter()
                    .table(FederationStatAggregate::Table)
                    .drop_column(FederationStatAggregate::UnstableFeaturesEnabled)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(FederationStatAggregate::Table)
                    .drop_column(FederationStatAggregate::UnstableFeaturesAnnounced)
                    .to_owned(),
            )
            .await?;

        // Drop columns from federation_stat_raw table
        manager
            .alter_table(
                Table::alter()
                    .table(FederationStatRaw::Table)
                    .drop_column(FederationStatRaw::UnstableFeaturesEnabled)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(FederationStatRaw::Table)
                    .drop_column(FederationStatRaw::UnstableFeaturesAnnounced)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(Iden)]
enum FederationStatRaw {
    Table,
    UnstableFeaturesEnabled,
    UnstableFeaturesAnnounced,
}

#[derive(Iden)]
enum FederationStatAggregate {
    Table,
    UnstableFeaturesEnabled,
    UnstableFeaturesAnnounced,
}
