use hyper::StatusCode;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum WellKnownError {
    #[error("Timeout after {0:?} while fetching well-known")]
    Timeout(std::time::Duration),
    #[error("HTTP {status} while fetching well-known: {context}")]
    Http { status: StatusCode, context: String },
    #[error("Redirect loop or too many redirects (limit {0})")]
    RedirectLimit(usize),
    #[error("Invalid JSON body: {0}")]
    InvalidJson(String),
    #[error("No A/AAAA records found for host")]
    NoAddresses,
    #[error("Other error: {0}")]
    Other(String),
}

#[derive(Debug, Error)]
pub enum FetchError {
    #[error(transparent)]
    WellKnown(#[from] WellKnownError),
    #[error("TLS error: {0}")]
    Tls(String),
    #[error("Network timeout after {0:?}")]
    Timeout(std::time::Duration),
    #[error("Network error: {0}")]
    Network(String),
    #[error("HTTP status {status}: {context}")]
    Http { status: StatusCode, context: String },
    #[error("JSON parse error: {0}")]
    Json(String),
    #[error("Invalid domain: {0}")]
    InvalidDomain(String),
    #[error("Unexpected content type: {0}")]
    UnexpectedContentType(String),
}

#[derive(Debug, Error)]
pub enum FederationError {
    #[error(transparent)]
    Fetch(#[from] FetchError),
    #[error("DNS resolution failed: {0}")]
    Dns(String),
    #[error("Ed25519 verification failed for key {0}")]
    Ed25519(String),
    #[error("Invalid server name: {0}")]
    InvalidServerName(String),
    #[error("Internal error: {0}")]
    Internal(String),
}

impl FederationError {
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            FederationError::Fetch(FetchError::Timeout(_))
                | FederationError::Fetch(FetchError::Network(_))
                | FederationError::Dns(_)
        )
    }
}
