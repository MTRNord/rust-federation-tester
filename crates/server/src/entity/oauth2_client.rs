//! OAuth2 Client entity.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "oauth2_client")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    /// Client secret (None for public clients)
    pub secret: Option<String>,
    /// Human-readable client name
    pub name: String,
    /// JSON array of allowed redirect URIs
    pub redirect_uris: String,
    /// Space-separated list of allowed grant types
    pub grant_types: String,
    /// Space-separated list of allowed scopes
    pub scopes: String,
    /// Whether this is a public client (no secret required)
    pub is_public: bool,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl Model {
    /// Parse redirect URIs from JSON string
    pub fn redirect_uris_list(&self) -> Vec<String> {
        serde_json::from_str(&self.redirect_uris).unwrap_or_default()
    }

    /// Parse grant types from space-separated string
    pub fn grant_types_list(&self) -> Vec<String> {
        self.grant_types
            .split_whitespace()
            .map(String::from)
            .collect()
    }

    /// Parse scopes from space-separated string
    pub fn scopes_list(&self) -> Vec<String> {
        self.scopes.split_whitespace().map(String::from).collect()
    }

    /// Check if a redirect URI is allowed for this client
    pub fn is_redirect_uri_allowed(&self, uri: &str) -> bool {
        self.redirect_uris_list()
            .iter()
            .any(|allowed| allowed == uri)
    }

    /// Check if a grant type is allowed for this client
    pub fn is_grant_type_allowed(&self, grant_type: &str) -> bool {
        self.grant_types_list().iter().any(|g| g == grant_type)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::OffsetDateTime;

    fn base_client() -> Model {
        Model {
            id: "c1".into(),
            secret: None,
            name: "Test Client".into(),
            redirect_uris: r#"["https://app.example.com/cb","https://app.example.com/cb2"]"#.into(),
            grant_types: "authorization_code refresh_token".into(),
            scopes: "openid profile email".into(),
            is_public: true,
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
        }
    }

    #[test]
    fn redirect_uris_list_parses_json_array() {
        let uris = base_client().redirect_uris_list();
        assert_eq!(
            uris,
            vec!["https://app.example.com/cb", "https://app.example.com/cb2"]
        );
    }

    #[test]
    fn redirect_uris_list_invalid_json_returns_empty() {
        let mut c = base_client();
        c.redirect_uris = "not json".into();
        assert!(c.redirect_uris_list().is_empty());
    }

    #[test]
    fn redirect_uris_list_empty_array() {
        let mut c = base_client();
        c.redirect_uris = "[]".into();
        assert!(c.redirect_uris_list().is_empty());
    }

    #[test]
    fn grant_types_list_splits_whitespace() {
        let g = base_client().grant_types_list();
        assert_eq!(g, vec!["authorization_code", "refresh_token"]);
    }

    #[test]
    fn grant_types_list_single_entry() {
        let mut c = base_client();
        c.grant_types = "authorization_code".into();
        assert_eq!(c.grant_types_list(), vec!["authorization_code"]);
    }

    #[test]
    fn grant_types_list_empty_string() {
        let mut c = base_client();
        c.grant_types = "".into();
        assert!(c.grant_types_list().is_empty());
    }

    #[test]
    fn scopes_list_splits_whitespace() {
        let s = base_client().scopes_list();
        assert_eq!(s, vec!["openid", "profile", "email"]);
    }

    #[test]
    fn scopes_list_empty_string() {
        let mut c = base_client();
        c.scopes = "".into();
        assert!(c.scopes_list().is_empty());
    }

    #[test]
    fn is_redirect_uri_allowed_true_for_known_uri() {
        assert!(base_client().is_redirect_uri_allowed("https://app.example.com/cb"));
    }

    #[test]
    fn is_redirect_uri_allowed_false_for_unknown_uri() {
        assert!(!base_client().is_redirect_uri_allowed("https://evil.example.com/cb"));
    }

    #[test]
    fn is_redirect_uri_allowed_exact_match_only() {
        // Partial prefix must not match
        assert!(!base_client().is_redirect_uri_allowed("https://app.example.com/cb/extra"));
    }

    #[test]
    fn is_grant_type_allowed_true_for_known_type() {
        assert!(base_client().is_grant_type_allowed("authorization_code"));
        assert!(base_client().is_grant_type_allowed("refresh_token"));
    }

    #[test]
    fn is_grant_type_allowed_false_for_unknown_type() {
        assert!(!base_client().is_grant_type_allowed("client_credentials"));
    }
}
