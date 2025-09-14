pub use sea_orm_migration::prelude::*;

mod m20250710_185614_add_alert_table;
mod m20250910_192226_fix_timezone;
mod m20250914_120000_add_federation_stats;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20250710_185614_add_alert_table::Migration),
            Box::new(m20250910_192226_fix_timezone::Migration),
            Box::new(m20250914_120000_add_federation_stats::Migration),
        ]
    }
}
