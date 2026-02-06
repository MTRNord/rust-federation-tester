//! Migration to add password authentication support to OAuth2 users.
//!
//! Adds columns for:
//! - password_hash: Argon2 hashed password (NULL for magic link only users)
//! - email_verification_token: Token sent via email for verification
//! - email_verification_expires_at: When the verification token expires

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Add password_hash column
        manager
            .alter_table(
                Table::alter()
                    .table(OAuth2User::Table)
                    .add_column(
                        ColumnDef::new(OAuth2User::PasswordHash)
                            .string_len(255)
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        // Add email_verification_token column
        manager
            .alter_table(
                Table::alter()
                    .table(OAuth2User::Table)
                    .add_column(
                        ColumnDef::new(OAuth2User::EmailVerificationToken)
                            .string_len(255)
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        // Add email_verification_expires_at column
        manager
            .alter_table(
                Table::alter()
                    .table(OAuth2User::Table)
                    .add_column(
                        ColumnDef::new(OAuth2User::EmailVerificationExpiresAt)
                            .timestamp_with_time_zone()
                            .null(),
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
                    .table(OAuth2User::Table)
                    .drop_column(OAuth2User::PasswordHash)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(OAuth2User::Table)
                    .drop_column(OAuth2User::EmailVerificationToken)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(OAuth2User::Table)
                    .drop_column(OAuth2User::EmailVerificationExpiresAt)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(Iden)]
enum OAuth2User {
    Table,
    PasswordHash,
    EmailVerificationToken,
    EmailVerificationExpiresAt,
}
