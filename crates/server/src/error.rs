use crate::response::{Error as ApiError, ErrorCode};
use hyper::StatusCode;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum Phase {
    WellKnown,
    Dns,
    HttpRequest,
    Tls,
    JsonDecode,
    Signature,
    Connection,
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum WellKnownError {
    #[error("Timeout after {0:?} while fetching well-known")]
    Timeout(Duration),
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
#[non_exhaustive]
pub enum FetchError {
    #[error(transparent)]
    WellKnown(#[from] WellKnownError),
    #[error("TLS error: {0}")]
    Tls(String),
    #[error("Network timeout after {0:?}")]
    Timeout(Duration),
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
#[non_exhaustive]
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

    pub fn phase(&self) -> Option<Phase> {
        match self {
            FederationError::Fetch(FetchError::WellKnown(_)) => Some(Phase::WellKnown),
            FederationError::Fetch(FetchError::Tls(_)) => Some(Phase::Tls),
            FederationError::Fetch(FetchError::Timeout(_)) => Some(Phase::HttpRequest),
            FederationError::Fetch(FetchError::Network(_)) => Some(Phase::Connection),
            FederationError::Fetch(FetchError::Http { .. }) => Some(Phase::HttpRequest),
            FederationError::Fetch(FetchError::Json(_)) => Some(Phase::JsonDecode),
            FederationError::Fetch(FetchError::InvalidDomain(_)) => Some(Phase::Dns),
            FederationError::Fetch(FetchError::UnexpectedContentType(_)) => {
                Some(Phase::HttpRequest)
            }
            FederationError::Dns(_) => Some(Phase::Dns),
            FederationError::Ed25519(_) => Some(Phase::Signature),
            FederationError::InvalidServerName(_) => Some(Phase::Dns),
            FederationError::Internal(_) => None,
        }
    }
}

// Adapter: map internal FetchError variants to existing outward-facing API Error struct.
// This is not yet wired globally; call sites can opt-in for late conversion.
impl From<FetchError> for ApiError {
    fn from(fe: FetchError) -> Self {
        match &fe {
            FetchError::Timeout(_) => ApiError {
                error: fe.to_string(),
                error_code: ErrorCode::Timeout,
            },
            FetchError::Network(_) => ApiError {
                error: fe.to_string(),
                error_code: ErrorCode::Unknown,
            },
            FetchError::Tls(_) => ApiError {
                error: fe.to_string(),
                error_code: ErrorCode::UnexpectedContentType("tls".into()),
            },
            FetchError::Http { status, .. } => ApiError {
                error: fe.to_string(),
                error_code: ErrorCode::NotOk(status.to_string()),
            },
            FetchError::Json(e) => ApiError {
                error: e.clone(),
                error_code: ErrorCode::InvalidJson("json".into()),
            },
            FetchError::InvalidDomain(_) => ApiError {
                error: fe.to_string(),
                error_code: ErrorCode::InvalidServerName(
                    crate::response::InvalidServerNameErrorCode::NotValidDNS,
                ),
            },
            FetchError::UnexpectedContentType(ct) => ApiError {
                error: fe.to_string(),
                error_code: ErrorCode::UnexpectedContentType(ct.clone()),
            },
            FetchError::WellKnown(wke) => ApiError {
                error: wke.to_string(),
                error_code: ErrorCode::Unknown,
            },
        }
    }
}
