use sea_orm_migration::{prelude::*, schema::*};

use crate::m20250710_185614_add_alert_table::Alert;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Add per-alert change-notification opt-in flags.
        // All default to FALSE so existing alerts never receive unexpected new emails.
        manager
            .alter_table(
                Table::alter()
                    .table(Alert::Table)
                    .add_column(
                        boolean(Alias::new("notify_server_name_change"))
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
                        boolean(Alias::new("notify_version_change"))
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
                        boolean(Alias::new("notify_tls_cert_change"))
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
                        boolean(Alias::new("notify_tls_expiry"))
                            .default(false)
                            .not_null()
                            .to_owned(),
                    )
                    .to_owned(),
            )
            .await?;

        // Create the observed-state table that stores the last-seen values for
        // change-detection comparison.  alert_id is the PK — one row per alert.
        manager
            .create_table(
                Table::create()
                    .table(AlertObservedState::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(AlertObservedState::AlertId)
                            .integer()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(AlertObservedState::ServerNameSeen)
                            .text()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(AlertObservedState::WellKnownSeen)
                            .text()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(AlertObservedState::VersionNameSeen)
                            .text()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(AlertObservedState::VersionStringSeen)
                            .text()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(AlertObservedState::TlsFingerprintsSeen)
                            .text()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(AlertObservedState::TlsEarliestExpiryAt)
                            .timestamp_with_time_zone()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(AlertObservedState::LastTlsExpiryEmailAt)
                            .timestamp_with_time_zone()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(AlertObservedState::ObservedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(AlertObservedState::Table, AlertObservedState::AlertId)
                            .to(Alias::new("alert"), Alias::new("id"))
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(AlertObservedState::Table).to_owned())
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alert::Table)
                    .drop_column(Alias::new("notify_tls_expiry"))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alert::Table)
                    .drop_column(Alias::new("notify_tls_cert_change"))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alert::Table)
                    .drop_column(Alias::new("notify_version_change"))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alert::Table)
                    .drop_column(Alias::new("notify_server_name_change"))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum AlertObservedState {
    Table,
    AlertId,
    ServerNameSeen,
    WellKnownSeen,
    VersionNameSeen,
    VersionStringSeen,
    TlsFingerprintsSeen,
    TlsEarliestExpiryAt,
    LastTlsExpiryEmailAt,
    ObservedAt,
}
