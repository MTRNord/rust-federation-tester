use sea_orm_migration::{prelude::*, schema::*};

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
                    .col(pk_uuid(Alert::Id))
                    .col(string(Alert::Email).not_null().unique_key().to_owned())
                    .col(string(Alert::ServerName).not_null().to_owned())
                    .col(
                        boolean(Alert::Verified)
                            .default(false)
                            .not_null()
                            .to_owned(),
                    )
                    .col(string(Alert::MagicToken).not_null().unique_key().to_owned())
                    .col(
                        timestamp(Alert::CreatedAt)
                            .default(Expr::current_timestamp())
                            .not_null()
                            .to_owned(),
                    )
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

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name("idx_email_server_name_unique")
                    .table(Alert::Table)
                    .to_owned(),
            )
            .await?;
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
