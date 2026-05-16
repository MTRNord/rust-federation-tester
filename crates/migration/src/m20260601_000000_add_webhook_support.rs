use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(AlertNotificationWebhook::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(AlertNotificationWebhook::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(AlertNotificationWebhook::AlertId)
                            .integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(AlertNotificationWebhook::Url)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(AlertNotificationWebhook::HmacSecret)
                            .string()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(AlertNotificationWebhook::HmacHeader)
                            .string()
                            .not_null()
                            .default("X-Signature-256"),
                    )
                    .col(
                        ColumnDef::new(AlertNotificationWebhook::RespectQuietHours)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(AlertNotificationWebhook::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(
                                AlertNotificationWebhook::Table,
                                AlertNotificationWebhook::AlertId,
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
                    .name("idx_alert_notification_webhook_unique")
                    .table(AlertNotificationWebhook::Table)
                    .col(AlertNotificationWebhook::AlertId)
                    .col(AlertNotificationWebhook::Url)
                    .unique()
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(WebhookOutbox::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(WebhookOutbox::Id)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(WebhookOutbox::AlertId).integer().not_null())
                    .col(
                        ColumnDef::new(WebhookOutbox::WebhookId)
                            .integer()
                            .not_null(),
                    )
                    .col(ColumnDef::new(WebhookOutbox::EventType).string().not_null())
                    .col(ColumnDef::new(WebhookOutbox::Payload).text().not_null())
                    .col(
                        ColumnDef::new(WebhookOutbox::Status)
                            .string()
                            .not_null()
                            .default("pending"),
                    )
                    .col(
                        ColumnDef::new(WebhookOutbox::Attempts)
                            .integer()
                            .not_null()
                            .default(0),
                    )
                    .col(
                        ColumnDef::new(WebhookOutbox::MaxAttempts)
                            .integer()
                            .not_null()
                            .default(5),
                    )
                    .col(
                        ColumnDef::new(WebhookOutbox::NextAttemptAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(WebhookOutbox::LastStatusCode)
                            .small_integer()
                            .null(),
                    )
                    .col(ColumnDef::new(WebhookOutbox::LastError).text().null())
                    .col(
                        ColumnDef::new(WebhookOutbox::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(WebhookOutbox::DeliveredAt)
                            .timestamp_with_time_zone()
                            .null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(WebhookOutbox::Table, WebhookOutbox::AlertId)
                            .to(Alias::new("alert"), Alias::new("id"))
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(WebhookOutbox::Table, WebhookOutbox::WebhookId)
                            .to(
                                AlertNotificationWebhook::Table,
                                AlertNotificationWebhook::Id,
                            )
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_webhook_outbox_pending")
                    .table(WebhookOutbox::Table)
                    .col(WebhookOutbox::Status)
                    .col(WebhookOutbox::NextAttemptAt)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_webhook_outbox_webhook_id")
                    .table(WebhookOutbox::Table)
                    .col(WebhookOutbox::WebhookId)
                    .col(WebhookOutbox::CreatedAt)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name("idx_webhook_outbox_webhook_id")
                    .table(WebhookOutbox::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_webhook_outbox_pending")
                    .table(WebhookOutbox::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_table(Table::drop().table(WebhookOutbox::Table).to_owned())
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_alert_notification_webhook_unique")
                    .table(AlertNotificationWebhook::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_table(
                Table::drop()
                    .table(AlertNotificationWebhook::Table)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
pub enum AlertNotificationWebhook {
    Table,
    Id,
    AlertId,
    Url,
    HmacSecret,
    HmacHeader,
    RespectQuietHours,
    CreatedAt,
}

#[derive(DeriveIden)]
pub enum WebhookOutbox {
    Table,
    Id,
    AlertId,
    WebhookId,
    EventType,
    Payload,
    Status,
    Attempts,
    MaxAttempts,
    NextAttemptAt,
    LastStatusCode,
    LastError,
    CreatedAt,
    DeliveredAt,
}
