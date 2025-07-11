use config::Config;
use sea_orm_migration::prelude::*;
use std::env;

#[tokio::main]
async fn main() {
    // Try to get DB URL from CLI arg or env first
    if env::var("DATABASE_URL").is_err() {
        // Fallback: load from config.yaml
        let settings = Config::builder()
            .add_source(config::File::with_name("config.yaml"))
            .build()
            .unwrap();
        if let Ok(url) = settings.get_string("database_url") {
            env::set_var("DATABASE_URL", url);
        }
    }
    cli::run_cli(migration::Migrator).await;
}
