use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("user_email"))
                    .add_column(
                        text(Alias::new("timezone"))
                            .default("UTC")
                            .not_null()
                            .to_owned(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("oauth2_user"))
                    .add_column(
                        text(Alias::new("timezone"))
                            .default("UTC")
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
                    .table(Alias::new("oauth2_user"))
                    .drop_column(Alias::new("timezone"))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("user_email"))
                    .drop_column(Alias::new("timezone"))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
