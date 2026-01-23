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
