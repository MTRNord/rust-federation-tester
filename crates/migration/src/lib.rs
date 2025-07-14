pub use sea_orm_migration::prelude::*;

mod m20250710_185614_add_alert_table;
mod m20250712_090549_add_access_tokens_table;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20250710_185614_add_alert_table::Migration),
            Box::new(m20250712_090549_add_access_tokens_table::Migration),
        ]
    }
}
