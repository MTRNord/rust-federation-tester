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

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use time::OffsetDateTime;

    fn base_auth() -> Model {
        Model {
            code: "code123".into(),
            client_id: "c1".into(),
            user_id: "u1".into(),
            redirect_uri: "https://app.example.com/cb".into(),
            scope: "openid".into(),
            state: None,
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(10),
            created_at: OffsetDateTime::now_utc(),
        }
    }

    #[test]
    fn is_expired_false_when_future() {
        assert!(!base_auth().is_expired());
    }

    #[test]
    fn is_expired_true_when_past() {
        let mut a = base_auth();
        a.expires_at = OffsetDateTime::now_utc() - time::Duration::seconds(1);
        assert!(a.is_expired());
    }

    #[test]
    fn verify_pkce_no_challenge_always_true() {
        // (None, None) → no PKCE required
        assert!(base_auth().verify_pkce("anything"));
    }

    #[test]
    fn verify_pkce_plain_correct() {
        let mut a = base_auth();
        a.code_challenge = Some("my-verifier".into());
        a.code_challenge_method = Some("plain".into());
        assert!(a.verify_pkce("my-verifier"));
    }

    #[test]
    fn verify_pkce_plain_wrong() {
        let mut a = base_auth();
        a.code_challenge = Some("my-verifier".into());
        a.code_challenge_method = Some("plain".into());
        assert!(!a.verify_pkce("wrong"));
    }

    #[test]
    fn verify_pkce_s256_correct() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let mut hasher = Sha256::new();
        hasher.update(verifier.as_bytes());
        let hash = hasher.finalize();
        use base64::Engine;
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash);

        let mut a = base_auth();
        a.code_challenge = Some(challenge);
        a.code_challenge_method = Some("S256".into());
        assert!(a.verify_pkce(verifier));
    }

    #[test]
    fn verify_pkce_s256_wrong_verifier() {
        let mut a = base_auth();
        a.code_challenge = Some("correct-challenge".into());
        a.code_challenge_method = Some("S256".into());
        assert!(!a.verify_pkce("wrong-verifier"));
    }

    #[test]
    fn verify_pkce_unknown_method_returns_false() {
        let mut a = base_auth();
        a.code_challenge = Some("challenge".into());
        a.code_challenge_method = Some("RS256".into());
        assert!(!a.verify_pkce("verifier"));
    }

    #[test]
    fn verify_pkce_challenge_without_method_returns_false() {
        // (Some, None) → ambiguous, treated as false
        let mut a = base_auth();
        a.code_challenge = Some("challenge".into());
        a.code_challenge_method = None;
        assert!(!a.verify_pkce("challenge"));
    }

    #[test]
    fn verify_pkce_method_without_challenge_returns_false() {
        // (None, Some) → ambiguous, treated as false
        let mut a = base_auth();
        a.code_challenge = None;
        a.code_challenge_method = Some("plain".into());
        assert!(!a.verify_pkce("verifier"));
    }
}
