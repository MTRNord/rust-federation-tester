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
