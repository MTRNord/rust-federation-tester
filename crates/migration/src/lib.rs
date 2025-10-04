pub use sea_orm_migration::prelude::*;

mod m20250710_185614_add_alert_table;
mod m20250910_192226_fix_timezone;
mod m20250914_120000_add_federation_stats;
mod m20250915_140000_add_unstable_features;
mod m20250922_174734_fix_uniqueness;
mod m20251002_120000_add_alert_state_tracking;
mod m20251004_120000_add_email_log;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20250710_185614_add_alert_table::Migration),
            Box::new(m20250910_192226_fix_timezone::Migration),
            Box::new(m20250914_120000_add_federation_stats::Migration),
            Box::new(m20250915_140000_add_unstable_features::Migration),
            Box::new(m20250922_174734_fix_uniqueness::Migration),
            Box::new(m20251002_120000_add_alert_state_tracking::Migration),
            Box::new(m20251004_120000_add_email_log::Migration),
        ]
    }
}
