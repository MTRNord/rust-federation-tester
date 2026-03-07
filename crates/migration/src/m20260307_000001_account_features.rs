use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260307_000001_account_features"
    }
}

/// Additional email addresses for a user account.
/// The primary login email stays in oauth2_user.email.
/// These are extra emails that can receive alert notifications.
#[derive(DeriveIden)]
enum UserEmail {
    Table,
    Id,
    UserId,
    Email,
    Verified,
    ReceivesAlerts,
    VerificationToken,
    VerificationExpiresAt,
    CreatedAt,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Add receives_alerts to the primary login email row in oauth2_user.
        // Default true so existing accounts keep receiving alerts.
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("oauth2_user"))
                    .add_column(
                        ColumnDef::new(Alias::new("receives_alerts"))
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .to_owned(),
            )
            .await?;

        // Additional notification email addresses per user.
        manager
            .create_table(
                Table::create()
                    .table(UserEmail::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(UserEmail::Id)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(UserEmail::UserId).string().not_null())
                    .col(
                        ColumnDef::new(UserEmail::Email)
                            .string()
                            .not_null()
                            .unique_key(),
                    )
                    .col(
                        ColumnDef::new(UserEmail::Verified)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(UserEmail::ReceivesAlerts)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(ColumnDef::new(UserEmail::VerificationToken).string().null())
                    .col(
                        ColumnDef::new(UserEmail::VerificationExpiresAt)
                            .timestamp_with_time_zone()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(UserEmail::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(UserEmail::Table).to_owned())
            .await?;
        // SQLite does not support DROP COLUMN, so we leave the column in place on rollback.
        Ok(())
    }
}
