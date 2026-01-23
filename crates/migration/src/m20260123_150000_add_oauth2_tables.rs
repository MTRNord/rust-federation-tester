//! Migration to add OAuth2 tables for the central identity manager.
//!
//! Creates tables for:
//! - oauth2_client: Registered OAuth2 clients
//! - oauth2_authorization: Authorization codes (temporary)
//! - oauth2_token: Access and refresh tokens
//! - oauth2_user: User accounts (linked to existing magic link auth)

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 1. OAuth2 Clients table
        manager
            .create_table(
                Table::create()
                    .table(OAuth2Client::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(OAuth2Client::Id)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(OAuth2Client::Secret).string().null())
                    .col(ColumnDef::new(OAuth2Client::Name).string().not_null())
                    .col(ColumnDef::new(OAuth2Client::RedirectUris).text().not_null())
                    .col(
                        ColumnDef::new(OAuth2Client::GrantTypes)
                            .text()
                            .not_null()
                            .default("authorization_code"),
                    )
                    .col(
                        ColumnDef::new(OAuth2Client::Scopes)
                            .text()
                            .not_null()
                            .default("openid profile email"),
                    )
                    .col(
                        ColumnDef::new(OAuth2Client::IsPublic)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(OAuth2Client::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(OAuth2Client::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        // 2. OAuth2 Users table (identity storage)
        manager
            .create_table(
                Table::create()
                    .table(OAuth2User::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(OAuth2User::Id)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(OAuth2User::Email)
                            .string()
                            .not_null()
                            .unique_key(),
                    )
                    .col(
                        ColumnDef::new(OAuth2User::EmailVerified)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(ColumnDef::new(OAuth2User::Name).string().null())
                    .col(
                        ColumnDef::new(OAuth2User::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(OAuth2User::LastLoginAt)
                            .timestamp_with_time_zone()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        // 3. OAuth2 Authorization Codes table (temporary, short-lived)
        manager
            .create_table(
                Table::create()
                    .table(OAuth2Authorization::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(OAuth2Authorization::Code)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(OAuth2Authorization::ClientId)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(OAuth2Authorization::UserId)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(OAuth2Authorization::RedirectUri)
                            .string()
                            .not_null(),
                    )
                    .col(ColumnDef::new(OAuth2Authorization::Scope).text().not_null())
                    .col(ColumnDef::new(OAuth2Authorization::State).string().null())
                    .col(ColumnDef::new(OAuth2Authorization::Nonce).string().null())
                    .col(
                        ColumnDef::new(OAuth2Authorization::CodeChallenge)
                            .string()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(OAuth2Authorization::CodeChallengeMethod)
                            .string()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(OAuth2Authorization::ExpiresAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(OAuth2Authorization::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        // 4. OAuth2 Tokens table (access and refresh tokens)
        manager
            .create_table(
                Table::create()
                    .table(OAuth2Token::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(OAuth2Token::Id)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(OAuth2Token::AccessToken)
                            .string()
                            .not_null()
                            .unique_key(),
                    )
                    .col(
                        ColumnDef::new(OAuth2Token::RefreshToken)
                            .string()
                            .null()
                            .unique_key(),
                    )
                    .col(
                        ColumnDef::new(OAuth2Token::TokenType)
                            .string()
                            .not_null()
                            .default("Bearer"),
                    )
                    .col(ColumnDef::new(OAuth2Token::ClientId).string().not_null())
                    .col(ColumnDef::new(OAuth2Token::UserId).string().not_null())
                    .col(ColumnDef::new(OAuth2Token::Scope).text().not_null())
                    .col(
                        ColumnDef::new(OAuth2Token::AccessTokenExpiresAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(OAuth2Token::RefreshTokenExpiresAt)
                            .timestamp_with_time_zone()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(OAuth2Token::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(OAuth2Token::RevokedAt)
                            .timestamp_with_time_zone()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        // Create indexes for efficient lookups
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_oauth2_authorization_client_id")
                    .table(OAuth2Authorization::Table)
                    .col(OAuth2Authorization::ClientId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_oauth2_authorization_expires_at")
                    .table(OAuth2Authorization::Table)
                    .col(OAuth2Authorization::ExpiresAt)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_oauth2_token_client_id")
                    .table(OAuth2Token::Table)
                    .col(OAuth2Token::ClientId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_oauth2_token_user_id")
                    .table(OAuth2Token::Table)
                    .col(OAuth2Token::UserId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_oauth2_token_expires_at")
                    .table(OAuth2Token::Table)
                    .col(OAuth2Token::AccessTokenExpiresAt)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Drop indexes first
        manager
            .drop_index(Index::drop().name("idx_oauth2_token_expires_at").to_owned())
            .await?;
        manager
            .drop_index(Index::drop().name("idx_oauth2_token_user_id").to_owned())
            .await?;
        manager
            .drop_index(Index::drop().name("idx_oauth2_token_client_id").to_owned())
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .name("idx_oauth2_authorization_expires_at")
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .name("idx_oauth2_authorization_client_id")
                    .to_owned(),
            )
            .await?;

        // Drop tables
        manager
            .drop_table(Table::drop().table(OAuth2Token::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(OAuth2Authorization::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(OAuth2User::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(OAuth2Client::Table).to_owned())
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum OAuth2Client {
    Table,
    Id,
    Secret,
    Name,
    RedirectUris,
    GrantTypes,
    Scopes,
    IsPublic,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum OAuth2User {
    Table,
    Id,
    Email,
    EmailVerified,
    Name,
    CreatedAt,
    LastLoginAt,
}

#[derive(DeriveIden)]
enum OAuth2Authorization {
    Table,
    Code,
    ClientId,
    UserId,
    RedirectUri,
    Scope,
    State,
    Nonce,
    CodeChallenge,
    CodeChallengeMethod,
    ExpiresAt,
    CreatedAt,
}

#[derive(DeriveIden)]
enum OAuth2Token {
    Table,
    Id,
    AccessToken,
    RefreshToken,
    TokenType,
    ClientId,
    UserId,
    Scope,
    AccessTokenExpiresAt,
    RefreshTokenExpiresAt,
    CreatedAt,
    RevokedAt,
}
