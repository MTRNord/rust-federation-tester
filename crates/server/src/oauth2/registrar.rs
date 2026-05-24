//! Database-backed OAuth2 client registrar.
//!
//! Implements the oxide-auth Registrar trait using SeaORM.

use crate::entity::oauth2_client;
use oxide_auth::endpoint::{PreGrant, Registrar, Scope};
use oxide_auth::primitives::registrar::RegistrarError;
use oxide_auth::primitives::registrar::{BoundClient, ClientUrl, ExactUrl, RegisteredUrl};
use sea_orm::{DatabaseConnection, EntityTrait};
use std::borrow::Cow;
use std::sync::Arc;

/// Database-backed client registrar for OAuth2.
#[derive(Clone)]
pub struct DbRegistrar {
    db: Arc<DatabaseConnection>,
}

impl DbRegistrar {
    pub fn new(db: Arc<DatabaseConnection>) -> Self {
        Self { db }
    }

    /// Synchronously fetch a client from the database.
    /// Note: This blocks the current thread. In production, consider using
    /// a caching layer or async-aware registrar.
    fn get_client_sync(&self, client_id: &str) -> Option<oauth2_client::Model> {
        // Use tokio's block_in_place to run async code synchronously
        // This is safe because oxide-auth's Registrar trait is sync
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                oauth2_client::Entity::find_by_id(client_id)
                    .one(self.db.as_ref())
                    .await
                    .ok()
                    .flatten()
            })
        })
    }
}

impl Registrar for DbRegistrar {
    fn bound_redirect<'a>(&self, bound: ClientUrl<'a>) -> Result<BoundClient<'a>, RegistrarError> {
        let client = self
            .get_client_sync(bound.client_id.as_ref())
            .ok_or(RegistrarError::Unspecified)?;

        // Check if the redirect URI is allowed
        let redirect_uri = match bound.redirect_uri {
            Some(uri) => {
                let uri_str = uri.as_str();
                if !client.is_redirect_uri_allowed(uri_str) {
                    return Err(RegistrarError::Unspecified);
                }
                RegisteredUrl::Exact(
                    ExactUrl::new(uri.as_str().to_string())
                        .map_err(|_| RegistrarError::Unspecified)?,
                )
            }
            None => {
                // Use the first registered redirect URI as default
                let uris = client.redirect_uris_list();
                let first = uris.first().ok_or(RegistrarError::Unspecified)?;
                RegisteredUrl::Exact(
                    ExactUrl::new(first.clone()).map_err(|_| RegistrarError::Unspecified)?,
                )
            }
        };

        Ok(BoundClient {
            client_id: bound.client_id,
            redirect_uri: Cow::Owned(redirect_uri),
        })
    }

    fn negotiate(
        &self,
        bound: BoundClient,
        scope: Option<Scope>,
    ) -> Result<PreGrant, RegistrarError> {
        let client = self
            .get_client_sync(bound.client_id.as_ref())
            .ok_or(RegistrarError::Unspecified)?;

        // Validate and filter requested scopes
        let allowed_scopes = client.scopes_list();
        let final_scope = match scope {
            Some(requested) => {
                let requested_str = requested.to_string();
                let requested_scopes: Vec<&str> = requested_str.split_whitespace().collect();
                let validated: Vec<&str> = requested_scopes
                    .into_iter()
                    .filter(|s| allowed_scopes.iter().any(|a| a == *s))
                    .collect();
                if validated.is_empty() {
                    // Default to allowed scopes if none of the requested are valid
                    client.scopes.clone()
                } else {
                    validated.join(" ")
                }
            }
            None => client.scopes.clone(),
        };

        Ok(PreGrant {
            client_id: bound.client_id.into_owned(),
            redirect_uri: bound.redirect_uri.into_owned(),
            scope: final_scope
                .parse()
                .map_err(|_| RegistrarError::Unspecified)?,
        })
    }

    fn check(&self, client_id: &str, passphrase: Option<&[u8]>) -> Result<(), RegistrarError> {
        let client = self
            .get_client_sync(client_id)
            .ok_or(RegistrarError::Unspecified)?;

        // Public clients don't need a secret
        if client.is_public {
            return Ok(());
        }

        // Confidential clients require secret validation
        match (&client.secret, passphrase) {
            (Some(stored_secret), Some(provided)) => {
                let provided_str =
                    std::str::from_utf8(provided).map_err(|_| RegistrarError::Unspecified)?;
                if stored_secret == provided_str {
                    Ok(())
                } else {
                    Err(RegistrarError::Unspecified)
                }
            }
            (None, _) if client.is_public => Ok(()),
            _ => Err(RegistrarError::Unspecified),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use migration::{Migrator, MigratorTrait};
    use oxide_auth::primitives::registrar::{BoundClient, ClientUrl, ExactUrl, RegisteredUrl};
    use sea_orm::{ActiveModelTrait, ActiveValue::Set, Database};
    use std::borrow::Cow;
    use time::OffsetDateTime;

    async fn make_db() -> Arc<DatabaseConnection> {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        Arc::new(db)
    }

    async fn insert_client(
        db: &DatabaseConnection,
        id: &str,
        secret: Option<&str>,
        redirect_uris: &str,
        scopes: &str,
        is_public: bool,
    ) {
        let now = OffsetDateTime::now_utc();
        oauth2_client::ActiveModel {
            id: Set(id.to_string()),
            secret: Set(secret.map(str::to_string)),
            name: Set("Test Client".to_string()),
            redirect_uris: Set(redirect_uris.to_string()),
            grant_types: Set("authorization_code".to_string()),
            scopes: Set(scopes.to_string()),
            is_public: Set(is_public),
            created_at: Set(now),
            updated_at: Set(now),
        }
        .insert(db)
        .await
        .unwrap();
    }

    // ── bound_redirect ────────────────────────────────────────────────────────

    #[tokio::test(flavor = "multi_thread")]
    async fn bound_redirect_unknown_client_returns_error() {
        let db = make_db().await;
        let reg = DbRegistrar::new(db);
        let result = reg.bound_redirect(ClientUrl {
            client_id: Cow::Borrowed("no-such-client"),
            redirect_uri: None,
        });
        assert!(result.is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn bound_redirect_uses_first_uri_when_none_given() {
        let db = make_db().await;
        insert_client(
            db.as_ref(),
            "pub-client",
            None,
            r#"["https://app.example.com/cb"]"#,
            "openid",
            true,
        )
        .await;
        let reg = DbRegistrar::new(db);
        let result = reg.bound_redirect(ClientUrl {
            client_id: Cow::Borrowed("pub-client"),
            redirect_uri: None,
        });
        assert!(result.is_ok());
        assert_eq!(result.unwrap().client_id.as_ref(), "pub-client");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn bound_redirect_accepts_registered_uri() {
        let db = make_db().await;
        insert_client(
            db.as_ref(),
            "pub-client2",
            None,
            r#"["https://app.example.com/cb"]"#,
            "openid",
            true,
        )
        .await;
        let reg = DbRegistrar::new(db);
        let exact = ExactUrl::new("https://app.example.com/cb".to_string()).unwrap();
        let result = reg.bound_redirect(ClientUrl {
            client_id: Cow::Borrowed("pub-client2"),
            redirect_uri: Some(Cow::Owned(exact)),
        });
        assert!(result.is_ok());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn bound_redirect_rejects_unregistered_uri() {
        let db = make_db().await;
        insert_client(
            db.as_ref(),
            "pub-client3",
            None,
            r#"["https://app.example.com/cb"]"#,
            "openid",
            true,
        )
        .await;
        let reg = DbRegistrar::new(db);
        let exact = ExactUrl::new("https://evil.example.com/steal".to_string()).unwrap();
        let result = reg.bound_redirect(ClientUrl {
            client_id: Cow::Borrowed("pub-client3"),
            redirect_uri: Some(Cow::Owned(exact)),
        });
        assert!(result.is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn bound_redirect_no_registered_uris_returns_error() {
        let db = make_db().await;
        insert_client(db.as_ref(), "empty-uris", None, "[]", "openid", true).await;
        let reg = DbRegistrar::new(db);
        let result = reg.bound_redirect(ClientUrl {
            client_id: Cow::Borrowed("empty-uris"),
            redirect_uri: None,
        });
        assert!(result.is_err());
    }

    // ── negotiate ─────────────────────────────────────────────────────────────

    #[tokio::test(flavor = "multi_thread")]
    async fn negotiate_no_scope_uses_client_scopes() {
        let db = make_db().await;
        insert_client(
            db.as_ref(),
            "scope-client",
            None,
            r#"["https://app.example.com/cb"]"#,
            "openid profile",
            true,
        )
        .await;
        let reg = DbRegistrar::new(db);
        let exact = ExactUrl::new("https://app.example.com/cb".to_string()).unwrap();
        let bound = BoundClient {
            client_id: Cow::Borrowed("scope-client"),
            redirect_uri: Cow::Owned(RegisteredUrl::Exact(exact)),
        };
        let grant = reg.negotiate(bound, None).unwrap();
        let scope_str = grant.scope.to_string();
        assert!(
            scope_str.contains("openid"),
            "scope missing 'openid': {scope_str}"
        );
        assert!(
            scope_str.contains("profile"),
            "scope missing 'profile': {scope_str}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn negotiate_valid_scope_subset_is_kept() {
        let db = make_db().await;
        insert_client(
            db.as_ref(),
            "scope-client2",
            None,
            r#"["https://app.example.com/cb"]"#,
            "openid profile email",
            true,
        )
        .await;
        let reg = DbRegistrar::new(db);
        let exact = ExactUrl::new("https://app.example.com/cb".to_string()).unwrap();
        let bound = BoundClient {
            client_id: Cow::Borrowed("scope-client2"),
            redirect_uri: Cow::Owned(RegisteredUrl::Exact(exact)),
        };
        let scope: Scope = "openid".parse().unwrap();
        let grant = reg.negotiate(bound, Some(scope)).unwrap();
        assert_eq!(grant.scope.to_string(), "openid");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn negotiate_unknown_scopes_fall_back_to_client_scopes() {
        let db = make_db().await;
        insert_client(
            db.as_ref(),
            "scope-client3",
            None,
            r#"["https://app.example.com/cb"]"#,
            "openid",
            true,
        )
        .await;
        let reg = DbRegistrar::new(db);
        let exact = ExactUrl::new("https://app.example.com/cb".to_string()).unwrap();
        let bound = BoundClient {
            client_id: Cow::Borrowed("scope-client3"),
            redirect_uri: Cow::Owned(RegisteredUrl::Exact(exact)),
        };
        let scope: Scope = "admin".parse().unwrap();
        let grant = reg.negotiate(bound, Some(scope)).unwrap();
        assert_eq!(grant.scope.to_string(), "openid");
    }

    // ── check ─────────────────────────────────────────────────────────────────

    #[tokio::test(flavor = "multi_thread")]
    async fn check_public_client_no_passphrase_ok() {
        let db = make_db().await;
        insert_client(
            db.as_ref(),
            "pub",
            None,
            r#"["https://app.example.com/cb"]"#,
            "openid",
            true,
        )
        .await;
        let reg = DbRegistrar::new(db);
        assert!(reg.check("pub", None).is_ok());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn check_confidential_correct_secret_ok() {
        let db = make_db().await;
        insert_client(
            db.as_ref(),
            "conf",
            Some("mysecret"),
            r#"["https://app.example.com/cb"]"#,
            "openid",
            false,
        )
        .await;
        let reg = DbRegistrar::new(db);
        assert!(reg.check("conf", Some(b"mysecret")).is_ok());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn check_confidential_wrong_secret_err() {
        let db = make_db().await;
        insert_client(
            db.as_ref(),
            "conf2",
            Some("mysecret"),
            r#"["https://app.example.com/cb"]"#,
            "openid",
            false,
        )
        .await;
        let reg = DbRegistrar::new(db);
        assert!(reg.check("conf2", Some(b"wrongsecret")).is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn check_confidential_no_passphrase_err() {
        let db = make_db().await;
        insert_client(
            db.as_ref(),
            "conf3",
            Some("mysecret"),
            r#"["https://app.example.com/cb"]"#,
            "openid",
            false,
        )
        .await;
        let reg = DbRegistrar::new(db);
        assert!(reg.check("conf3", None).is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn check_missing_client_returns_error() {
        let db = make_db().await;
        let reg = DbRegistrar::new(db);
        assert!(reg.check("nonexistent", None).is_err());
    }
}
