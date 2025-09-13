use config::Config;
use rust_federation_tester::config::{AppConfig, SmtpConfig, load_config};
use std::env;
use std::fs;

#[test]
fn test_smtp_config_deserialization() {
    let yaml_content = r#"
server: "smtp.example.com"
port: 587
username: "user@example.com"
password: "secret123"
from: "noreply@example.com"
"#;

    let config = Config::builder()
        .add_source(config::File::from_str(
            yaml_content,
            config::FileFormat::Yaml,
        ))
        .build()
        .expect("Failed to build config");

    let smtp_config: SmtpConfig = config
        .try_deserialize()
        .expect("Failed to deserialize SMTP config");
    assert_eq!(smtp_config.server, "smtp.example.com");
    assert_eq!(smtp_config.port, 587);
    assert_eq!(smtp_config.username, "user@example.com");
    assert_eq!(smtp_config.password, "secret123");
    assert_eq!(smtp_config.from, "noreply@example.com");
}

#[test]
fn test_app_config_deserialization() {
    let yaml_content = r#"
database_url: "postgres://localhost/test"
frontend_url: "https://example.com"
magic_token_secret: "secret_key_123"
smtp:
  server: "smtp.example.com"
  port: 587
  username: "user@example.com"
  password: "secret123"
  from: "noreply@example.com"
"#;

    let config = Config::builder()
        .add_source(config::File::from_str(
            yaml_content,
            config::FileFormat::Yaml,
        ))
        .build()
        .expect("Failed to build config");

    let app_config: AppConfig = config
        .try_deserialize()
        .expect("Failed to deserialize app config");
    assert_eq!(app_config.database_url, "postgres://localhost/test");
    assert_eq!(app_config.frontend_url, "https://example.com");
    assert_eq!(app_config.magic_token_secret, "secret_key_123");
    assert_eq!(app_config.smtp.server, "smtp.example.com");
    assert_eq!(app_config.smtp.port, 587);
}

#[test]
fn test_config_with_environment_variables() {
    // Create a temporary config file with .yaml extension
    let temp_dir = env::temp_dir();
    let config_path = temp_dir.join("test_config.yaml");
    let config_content = r#"
database_url: "postgres://file/test"
frontend_url: "https://file.example.com"
magic_token_secret: "file_secret"
smtp:
  server: "smtp.file.com"
  port: 587
  username: "file@example.com"
  password: "file_secret"
  from: "noreply@file.com"
"#;
    fs::write(&config_path, config_content).expect("Failed to write temp config");

    // Test environment variable override
    unsafe {
        env::set_var("APP__DATABASE_URL", "postgres://env/test");
        env::set_var("APP__FRONTEND_URL", "https://env.example.com");

        let config = Config::builder()
            .add_source(config::File::from(config_path.clone()))
            .add_source(config::Environment::default().prefix("APP").separator("__"))
            .build()
            .expect("Failed to build config");

        let app_config: AppConfig = config.try_deserialize().expect("Failed to deserialize");

        // Environment variables should override file values
        assert_eq!(app_config.database_url, "postgres://env/test");
        assert_eq!(app_config.frontend_url, "https://env.example.com");
        // Non-overridden values should come from file
        assert_eq!(app_config.magic_token_secret, "file_secret");

        // Clean up
        env::remove_var("APP__DATABASE_URL");
        env::remove_var("APP__FRONTEND_URL");
        let _ = fs::remove_file(config_path);
    }
}

#[test]
#[should_panic(expected = "configuration file")]
fn test_load_config_missing_file() {
    // Save current directory and change to temp location to ensure config.yaml doesn't exist
    let original_dir = env::current_dir().unwrap();
    let temp_dir = env::temp_dir();
    env::set_current_dir(&temp_dir).unwrap();

    // Ensure no config.yaml exists in temp directory
    let config_path = temp_dir.join("config.yaml");
    if config_path.exists() {
        fs::remove_file(&config_path).unwrap();
    }

    // This should panic when config.yaml is not found
    let _ = load_config();

    // Restore original directory (won't reach here due to panic)
    env::set_current_dir(original_dir).unwrap();
}

#[test]
fn test_smtp_config_field_types() {
    // Test that port is correctly parsed as u16
    let yaml_content = r#"
server: "test.com"
port: 65535
username: "test"
password: "test"
from: "test@test.com"
"#;

    let config = Config::builder()
        .add_source(config::File::from_str(
            yaml_content,
            config::FileFormat::Yaml,
        ))
        .build()
        .expect("Failed to build config");

    let smtp_config: SmtpConfig = config.try_deserialize().expect("Failed to deserialize");
    assert_eq!(smtp_config.port, 65535u16);
}

#[test]
fn test_config_partial_structure() {
    // Test error handling when required fields are missing
    let invalid_yaml = r#"
database_url: "postgres://localhost/test"
# Missing smtp section, frontend_url, and magic_token_secret
"#;

    let config = Config::builder()
        .add_source(config::File::from_str(
            invalid_yaml,
            config::FileFormat::Yaml,
        ))
        .build()
        .expect("Failed to build config");

    let result: Result<AppConfig, _> = config.try_deserialize();
    assert!(
        result.is_err(),
        "Should fail when required fields are missing"
    );
}
