//! Migration to link existing alerts to OAuth2 users and add external identity federation.
//!
//! This migration:
//! 1. Adds user_id column to alert table (nullable for backward compatibility)
//! 2. Creates oauth2_identity table for external provider federation

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 1. Add user_id column to alert table
        // This is nullable to allow existing alerts to work without being linked
        manager
            .alter_table(
                Table::alter()
                    .table(Alert::Table)
                    .add_column(ColumnDef::new(Alert::UserId).string().null())
                    .to_owned(),
            )
            .await?;

        // 2. Create oauth2_identity table for external provider federation
        // This allows users to link multiple identity providers (Google, GitHub, Matrix OIDC, etc.)
        manager
            .create_table(
                Table::create()
                    .table(OAuth2Identity::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(OAuth2Identity::Id)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(OAuth2Identity::UserId).string().not_null())
                    .col(ColumnDef::new(OAuth2Identity::Provider).string().not_null())
                    .col(ColumnDef::new(OAuth2Identity::Subject).string().not_null())
                    .col(ColumnDef::new(OAuth2Identity::Email).string().null())
                    .col(ColumnDef::new(OAuth2Identity::Name).string().null())
                    .col(ColumnDef::new(OAuth2Identity::AccessToken).text().null())
                    .col(ColumnDef::new(OAuth2Identity::RefreshToken).text().null())
                    .col(
                        ColumnDef::new(OAuth2Identity::TokenExpiresAt)
                            .timestamp_with_time_zone()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(OAuth2Identity::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(OAuth2Identity::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        // Create unique constraint on (provider, subject) to prevent duplicate external identities
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_oauth2_identity_provider_subject")
                    .table(OAuth2Identity::Table)
                    .col(OAuth2Identity::Provider)
                    .col(OAuth2Identity::Subject)
                    .unique()
                    .to_owned(),
            )
            .await?;

        // Create index on user_id for efficient lookups
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_oauth2_identity_user_id")
                    .table(OAuth2Identity::Table)
                    .col(OAuth2Identity::UserId)
                    .to_owned(),
            )
            .await?;

        // Create index on alert.user_id for efficient lookups
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_alert_user_id")
                    .table(Alert::Table)
                    .col(Alert::UserId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Drop indexes first
        manager
            .drop_index(Index::drop().name("idx_alert_user_id").to_owned())
            .await?;
        manager
            .drop_index(Index::drop().name("idx_oauth2_identity_user_id").to_owned())
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .name("idx_oauth2_identity_provider_subject")
                    .to_owned(),
            )
            .await?;

        // Drop oauth2_identity table
        manager
            .drop_table(Table::drop().table(OAuth2Identity::Table).to_owned())
            .await?;

        // Remove user_id column from alert table
        manager
            .alter_table(
                Table::alter()
                    .table(Alert::Table)
                    .drop_column(Alert::UserId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum Alert {
    Table,
    UserId,
}

#[derive(DeriveIden)]
enum OAuth2Identity {
    Table,
    Id,
    UserId,
    Provider,
    Subject,
    Email,
    Name,
    AccessToken,
    RefreshToken,
    TokenExpiresAt,
    CreatedAt,
    UpdatedAt,
}
