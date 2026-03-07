use sea_orm_migration::prelude::*;

/// Rename the o_auth2_* tables created by DeriveIden to oauth2_* to match
/// the explicit table_name attributes in the entity definitions.
pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260307_000000_rename_oauth2_tables"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        db.execute_unprepared("ALTER TABLE o_auth2_client RENAME TO oauth2_client")
            .await?;
        db.execute_unprepared("ALTER TABLE o_auth2_user RENAME TO oauth2_user")
            .await?;
        db.execute_unprepared("ALTER TABLE o_auth2_authorization RENAME TO oauth2_authorization")
            .await?;
        db.execute_unprepared("ALTER TABLE o_auth2_token RENAME TO oauth2_token")
            .await?;
        db.execute_unprepared("ALTER TABLE o_auth2_identity RENAME TO oauth2_identity")
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        db.execute_unprepared("ALTER TABLE oauth2_client RENAME TO o_auth2_client")
            .await?;
        db.execute_unprepared("ALTER TABLE oauth2_user RENAME TO o_auth2_user")
            .await?;
        db.execute_unprepared("ALTER TABLE oauth2_authorization RENAME TO o_auth2_authorization")
            .await?;
        db.execute_unprepared("ALTER TABLE oauth2_token RENAME TO o_auth2_token")
            .await?;
        db.execute_unprepared("ALTER TABLE oauth2_identity RENAME TO o_auth2_identity")
            .await?;
        Ok(())
    }
}
