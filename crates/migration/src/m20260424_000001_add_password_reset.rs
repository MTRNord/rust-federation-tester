use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("oauth2_user"))
                    .add_column_if_not_exists(
                        ColumnDef::new(Alias::new("password_reset_token"))
                            .string()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("oauth2_user"))
                    .add_column_if_not_exists(
                        ColumnDef::new(Alias::new("password_reset_expires_at"))
                            .timestamp_with_time_zone()
                            .null(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("oauth2_user"))
                    .drop_column(Alias::new("password_reset_token"))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("oauth2_user"))
                    .drop_column(Alias::new("password_reset_expires_at"))
                    .to_owned(),
            )
            .await
    }
}
