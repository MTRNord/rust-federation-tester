use tokio::time::Duration;

/// Runtime configuration for federation checks.
///
/// Passed explicitly through the check chain rather than read from global statics,
/// so library callers can control timeout and security settings per-call.
#[derive(Clone, Debug)]
pub struct FederationConfig {
    /// Maximum time to wait for any individual network operation.
    pub network_timeout: Duration,
    /// When `true`, the SSRF check that rejects private/internal IPs is skipped.
    ///
    /// Only enable this for closed-federation or intranet deployments. On a public
    /// instance it would allow users to probe internal network resources.
    pub allow_private_targets: bool,
}

impl Default for FederationConfig {
    fn default() -> Self {
        Self {
            network_timeout: Duration::from_secs(3),
            allow_private_targets: false,
        }
    }
}
