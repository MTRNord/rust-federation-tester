use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(AccessTokens::Table)
                    .if_not_exists()
                    .col(pk_auto(AccessTokens::Id))
                    .col(
                        string(AccessTokens::Email)
                            .not_null()
                            .unique_key()
                            .to_owned(),
                    )
                    .col(
                        string(AccessTokens::AccessToken)
                            .not_null()
                            .unique_key()
                            .to_owned(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(AccessTokens::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum AccessTokens {
    Table,
    Id,
    Email,
    AccessToken,
}
