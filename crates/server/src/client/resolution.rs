use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct HomeserverInfo {
    #[serde(rename = "base_url")]
    pub base_url: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct WellKnown {
    #[serde(rename = "m.homeserver")]
    pub m_homeserver: Option<HomeserverInfo>,
}

#[tracing::instrument()]
pub async fn resolve_client_side_api(server_name: &str) -> String {
    // Fetch the well-known configuration
    let url = format!("https://{}/.well-known/matrix/client", server_name);
    let client = reqwest::Client::new();
    let resp = client
        .get(&url)
        .header("User-Agent", "rust-federation-tester/0.1")
        .send()
        .await;
    match resp {
        Ok(response) => {
            if response.status().is_success() {
                let json = response.json::<WellKnown>().await;
                match json {
                    Ok(well_known) => {
                        if let Some(homeserver) = well_known.m_homeserver {
                            if let Some(base_url) = homeserver.base_url {
                                base_url
                            } else {
                                format!("https://{}/", server_name)
                            }
                        } else {
                            format!("https://{}/", server_name)
                        }
                    }
                    Err(_) => format!("https://{}/", server_name),
                }
            } else {
                format!("https://{}/", server_name)
            }
        }
        Err(_) => format!("https://{}/", server_name),
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerVersionInfo {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClientVersions {
    pub versions: Vec<String>,
    pub unstable_features: Option<HashMap<String, bool>>,
    pub server: Option<ServerVersionInfo>,
}

#[tracing::instrument()]
pub async fn fetch_client_server_versions(cs_server_address: &str) -> ClientVersions {
    let url = format!("{}/_matrix/client/versions", cs_server_address);
    tracing::info!(
        name = "client.fetch_client_versions",
        target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
        message = "Fetching client versions",
        url = %url
    );
    let client = reqwest::Client::new();
    let resp = client
        .get(&url)
        .header("User-Agent", "rust-federation-tester/0.1")
        .send()
        .await;
    match resp {
        Ok(response) => {
            if response.status().is_success() {
                let json = response.json::<ClientVersions>().await;
                match json {
                    Ok(versions) => versions,
                    Err(_) => ClientVersions {
                        versions: vec![],
                        unstable_features: None,
                        server: None,
                    },
                }
            } else {
                ClientVersions {
                    versions: vec![],
                    unstable_features: None,
                    server: None,
                }
            }
        }
        Err(_) => ClientVersions {
            versions: vec![],
            unstable_features: None,
            server: None,
        },
    }
}
