use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 1. Composite index on alert(verified, is_currently_failing).
        //    Both check loops (healthy and active) filter on this pair every cycle.
        //    Without this, each 5-minute / 1-minute sweep does a full table scan.
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_alert_verified_failing")
                    .table(Alert::Table)
                    .col(Alert::Verified)
                    .col(Alert::IsCurrentlyFailing)
                    .to_owned(),
            )
            .await?;

        // 2. Composite index on alert(verified, created_at).
        //    Used by the housekeeping query that deletes old unverified alerts:
        //    WHERE verified = false AND created_at < cutoff
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_alert_verified_created_at")
                    .table(Alert::Table)
                    .col(Alert::Verified)
                    .col(Alert::CreatedAt)
                    .to_owned(),
            )
            .await?;

        // 3. Index on federation_stat_aggregate.last_seen_at.
        //    Used by the retention pruning query that deletes rows older than the
        //    configured retention window (raw SQL: DELETE WHERE last_seen_at < interval).
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_federation_stat_aggregate_last_seen_at")
                    .table(FederationStatAggregate::Table)
                    .col(FederationStatAggregate::LastSeenAt)
                    .to_owned(),
            )
            .await?;

        // 4. Index on oauth2_authorization.user_id.
        //    Used by GDPR account deletion to find and delete all authorization
        //    codes for a given user.
        //    Note: DeriveIden would snake_case "OAuth2Authorization" → "o_auth2_authorization",
        //    so we use Alias::new() to reference the real table name.
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_oauth2_authorization_user_id")
                    .table(Alias::new("oauth2_authorization"))
                    .col(Alias::new("user_id"))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .name("idx_oauth2_authorization_user_id")
                    .table(Alias::new("oauth2_authorization"))
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .name("idx_federation_stat_aggregate_last_seen_at")
                    .table(FederationStatAggregate::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .name("idx_alert_verified_created_at")
                    .table(Alert::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .name("idx_alert_verified_failing")
                    .table(Alert::Table)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum Alert {
    Table,
    Verified,
    IsCurrentlyFailing,
    CreatedAt,
}

#[derive(DeriveIden)]
enum FederationStatAggregate {
    Table,
    LastSeenAt,
}
