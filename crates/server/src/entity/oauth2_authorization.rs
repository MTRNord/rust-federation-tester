//! OAuth2 Authorization Code entity - temporary codes exchanged for tokens.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "oauth2_authorization")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub code: String,
    pub client_id: String,
    pub user_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: Option<String>,
    /// OpenID Connect nonce
    pub nonce: Option<String>,
    /// PKCE code challenge
    pub code_challenge: Option<String>,
    /// PKCE code challenge method (S256 or plain)
    pub code_challenge_method: Option<String>,
    pub expires_at: OffsetDateTime,
    pub created_at: OffsetDateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl Model {
    /// Check if this authorization code has expired
    pub fn is_expired(&self) -> bool {
        self.expires_at < OffsetDateTime::now_utc()
    }

    /// Verify PKCE code verifier against stored challenge
    pub fn verify_pkce(&self, code_verifier: &str) -> bool {
        match (&self.code_challenge, &self.code_challenge_method) {
            (Some(challenge), Some(method)) => match method.as_str() {
                "S256" => {
                    use sha2::{Digest, Sha256};
                    let mut hasher = Sha256::new();
                    hasher.update(code_verifier.as_bytes());
                    let hash = hasher.finalize();
                    let computed = base64_url_encode(&hash);
                    computed == *challenge
                }
                "plain" => code_verifier == challenge,
                _ => false,
            },
            // No PKCE required if not provided during authorization
            (None, None) => true,
            _ => false,
        }
    }
}

fn base64_url_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}
