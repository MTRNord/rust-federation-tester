use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260307_000002_internal_account_client"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Insert the built-in account-page OAuth2 client.
        // This is a confidential client used by the backend's own account
        // management page (/oauth2/account) for server-side code exchange.
        // The secret and redirect_uri are set/updated at application startup
        // from oauth2.account_client_secret and oauth2.issuer_url in config.
        let db = manager.get_connection();
        db.execute_unprepared(
            r#"
            INSERT INTO oauth2_client
                (id, secret, name, redirect_uris, grant_types, scopes, is_public, created_at, updated_at)
            VALUES
                (
                    'account-internal',
                    NULL,
                    'Account Page (internal)',
                    '[]',
                    'authorization_code refresh_token',
                    'openid email',
                    0,
                    CURRENT_TIMESTAMP,
                    CURRENT_TIMESTAMP
                )
            ON CONFLICT(id) DO NOTHING
            "#,
        )
        .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        db.execute_unprepared("DELETE FROM oauth2_client WHERE id = 'account-internal'")
            .await?;
        Ok(())
    }
}
