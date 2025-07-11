use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Alert::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Alert::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(Alert::Email).string().not_null())
                    .col(ColumnDef::new(Alert::ServerName).string().not_null())
                    .col(
                        ColumnDef::new(Alert::Verified)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(ColumnDef::new(Alert::MagicToken).string().not_null())
                    .col(
                        ColumnDef::new(Alert::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Alert::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
enum Alert {
    Table,
    Id,
    Email,
    ServerName,
    Verified,
    MagicToken,
    CreatedAt,
}
