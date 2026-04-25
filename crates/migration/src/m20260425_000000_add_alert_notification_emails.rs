use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(AlertNotificationEmail::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(AlertNotificationEmail::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(AlertNotificationEmail::AlertId)
                            .integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(AlertNotificationEmail::Email)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(AlertNotificationEmail::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(
                                AlertNotificationEmail::Table,
                                AlertNotificationEmail::AlertId,
                            )
                            .to(Alias::new("alert"), Alias::new("id"))
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_alert_notification_email_unique")
                    .table(AlertNotificationEmail::Table)
                    .col(AlertNotificationEmail::AlertId)
                    .col(AlertNotificationEmail::Email)
                    .unique()
                    .to_owned(),
            )
            .await?;

        // Backfill: copy existing OAuth2 alerts' email into the new table.
        // Works on both SQLite and PostgreSQL.
        manager
            .get_connection()
            .execute_unprepared(
                "INSERT INTO alert_notification_email (alert_id, email, created_at) \
                 SELECT id, email, created_at FROM alert WHERE user_id IS NOT NULL",
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Restore alert.email from the oldest notification email per alert so no
        // data is lost when rolling back.  The ORDER BY / LIMIT 1 picks the
        // original signup address for unmodified alerts; for alerts where the
        // user added extra recipients, the earliest address survives.
        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE alert \
                 SET email = ( \
                     SELECT email FROM alert_notification_email \
                     WHERE alert_id = alert.id \
                     ORDER BY created_at ASC \
                     LIMIT 1 \
                 ) \
                 WHERE user_id IS NOT NULL \
                   AND EXISTS ( \
                       SELECT 1 FROM alert_notification_email WHERE alert_id = alert.id \
                   )",
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_alert_notification_email_unique")
                    .table(AlertNotificationEmail::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_table(
                Table::drop()
                    .table(AlertNotificationEmail::Table)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
pub enum AlertNotificationEmail {
    Table,
    Id,
    AlertId,
    Email,
    CreatedAt,
}
