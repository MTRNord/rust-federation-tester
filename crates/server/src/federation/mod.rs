//! Federation-related utilities split from the original utils.rs for better maintainability.
//! Modules:
//! - well_known: Matrix well-known lookup and redirect handling
//! - dns: SRV + A/AAAA resolution logic
//! - network: Low-level TLS + HTTP fetch helpers (with certificate extraction)
//! - version: Server version querying (direct + pooled)
//! - keys: Key fetching and verification (ed25519)
//! - connection: Combined connection check orchestrating version + keys
//! - certificate: X509 parsing helpers

pub mod certificate;
pub mod connection;
pub mod dns;
pub mod keys;
pub mod network;
pub mod version;
pub mod well_known;

pub use well_known::{NETWORK_TIMEOUT_SECS, lookup_server_well_known};

pub use dns::{absolutize_srv_target, lookup_server};

pub use network::{FullResponse, fetch_url_custom_sni_host};

pub use certificate::extract_certificate_info;

pub use version::{VersionResp, fetch_url_pooled_simple, query_server_version_pooled};

pub use keys::{FullKeysResponse, fetch_keys, verify_keys};

pub use connection::connection_check;
