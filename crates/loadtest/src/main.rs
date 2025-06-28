use goose::prelude::*;
use std::env;

async fn health_check(user: &mut GooseUser) -> TransactionResult {
    let _goose_metrics = user.get("/healthz").await?;
    Ok(())
}

async fn get_federation_report(user: &mut GooseUser) -> TransactionResult {
    let server_name = env::var("SERVER_NAME").unwrap_or_else(|_| "matrix.org".to_string());
    let path = format!("/api/report?server_name={server_name}&no_cache=false");
    let _goose_metrics = user.get(&path).await?;
    Ok(())
}

async fn get_federation_ok(user: &mut GooseUser) -> TransactionResult {
    let server_name = env::var("SERVER_NAME").unwrap_or_else(|_| "matrix.org".to_string());
    let path = format!("/api/federation-ok?server_name={server_name}&no_cache=false");
    let _goose_metrics = user.get(&path).await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), GooseError> {
    // Set default server name if not provided
    if env::var("SERVER_NAME").is_err() {
        println!("No SERVER_NAME environment variable set, defaulting to 'matrix.org'");
        env::set_var("SERVER_NAME", "matrix.org");
    }

    println!(
        "Server name for API calls: {}",
        env::var("SERVER_NAME").unwrap_or_else(|_| "matrix.org".to_string())
    );

    GooseAttack::initialize()?
        .register_scenario(
            scenario!("HealthCheck").register_transaction(transaction!(health_check)),
        )
        .register_scenario(
            scenario!("FederationTests")
                .register_transaction(transaction!(get_federation_report))
                .register_transaction(transaction!(get_federation_ok)),
        )
        .execute()
        .await?;

    Ok(())
}
