use serde::Deserialize;

#[derive(Deserialize)]
pub struct SmtpConfig {
    pub server: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub from: String,
}
#[derive(Deserialize)]
pub struct AppConfig {
    pub database_url: String,
    pub smtp: SmtpConfig,
    pub frontend_url: String,
    pub magic_token_secret: String,
}

pub fn load_config() -> AppConfig {
    use config::{Config, Environment, File};
    Config::builder()
        .add_source(File::with_name("config.yaml"))
        .add_source(Environment::default().separator("__"))
        .build()
        .unwrap()
        .try_deserialize()
        .unwrap()
}
