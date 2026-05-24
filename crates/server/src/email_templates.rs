//! Email template rendering with HTML (Askama) and SCSS styling
use askama::Template;
use once_cell::sync::Lazy;

/// Prefix an email subject with the environment name when one is configured.
///
/// `env_subject("Federation Alert: foo is not healthy", Some("staging"))`
/// returns `"[staging] Federation Alert: foo is not healthy"`.
///
/// Returns the subject unchanged when:
/// - `env_name` is `None` (field omitted in config — implies production)
/// - `env_name` is `Some("production")` (explicitly named production)
/// - `env_name` is an empty string
pub fn env_subject(base: &str, env_name: Option<&str>) -> String {
    match env_name {
        Some(name) if !name.is_empty() && name.to_lowercase() != "production" => {
            format!("[{name}] {base}")
        }
        _ => base.to_string(),
    }
}

/// Returns a banner string for plain-text emails, or empty string for production/unset.
pub fn env_banner_text(env_name: Option<&str>) -> String {
    match env_name {
        Some(name) if !name.is_empty() && name.to_lowercase() != "production" => {
            format!(
                "*** Sent from the {} environment ***\n\n",
                name.to_uppercase()
            )
        }
        _ => String::new(),
    }
}

/// Compiled and inlined CSS from SCSS
static COMPILED_CSS: Lazy<String> = Lazy::new(|| {
    let scss = include_str!("../styles/email.scss");
    grass::from_string(scss.to_string(), &grass::Options::default())
        .expect("Failed to compile SCSS")
});

/// Inline CSS into HTML
#[tracing::instrument(skip(html))]
fn inline_css(html: &str) -> String {
    let options = css_inline::InlineOptions {
        load_remote_stylesheets: false,
        ..css_inline::InlineOptions::default()
    };

    let inliner = css_inline::CSSInliner::new(options);

    // Inject the compiled CSS into the HTML
    let html_with_style = html.replace(
        "</head>",
        &format!("<style>{}</style></head>", COMPILED_CSS.as_str()),
    );

    match inliner.inline(&html_with_style) {
        Ok(inlined) => inlined,
        Err(e) => {
            tracing::error!(
                name = "email.inline_css.failed",
                target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
                error = ?e,
                message = "Failed to inline CSS"
            );
            html.to_string()
        }
    }
}

#[derive(Template)]
#[template(path = "failure_email.html")]
pub struct FailureEmailTemplate {
    pub server_name: String,
    pub check_url: String,
    pub failure_count: i32,
    pub reminder_interval: String,
    pub unsubscribe_url: String,
    pub failure_reason: Option<String>,
    pub environment_name: Option<String>,
    /// Set when the email was delayed due to quiet hours.
    pub quiet_hours_note: Option<String>,
    /// When the failure was first detected (formatted, e.g. "2024-01-15 14:32 UTC").
    pub first_detected: Option<String>,
    /// How many minutes the server has been down.
    pub minutes_down: Option<u64>,
    /// When the server was last known-healthy (formatted).
    pub last_healthy: Option<String>,
    /// A human-readable hint explaining what the error likely means.
    pub error_hint: Option<String>,
    /// Ordinal total of reminder emails (e.g. "of 5"), omitted when unknown.
    pub reminder_total: Option<i32>,
    /// Direct link to view or edit this specific alert.
    pub alert_url: String,
    /// Link to the alerts dashboard.
    pub manage_url: String,
    /// Optional sponsor link shown in email footer.
    pub sponsor_url: Option<String>,
}

impl FailureEmailTemplate {
    #[tracing::instrument(skip(self))]
    pub fn render_html(&self) -> Result<String, askama::Error> {
        let html = self.render()?;
        Ok(inline_css(&html))
    }

    #[tracing::instrument(skip(self))]
    pub fn render_text(&self) -> String {
        let env_banner = env_banner_text(self.environment_name.as_deref());

        let reminder_text = if self.failure_count > 1 {
            format!(
                "\nThis is reminder #{} - the server has been failing for a while.\n",
                self.failure_count
            )
        } else {
            String::new()
        };

        let reason_text = if let Some(ref reason) = self.failure_reason {
            format!("\nFailure reason: {}\n", reason)
        } else {
            String::new()
        };

        let quiet_note = if let Some(ref note) = self.quiet_hours_note {
            format!("\nNote: {}\n", note)
        } else {
            String::new()
        };

        format!(
            r#"{}Hello,

Your server '{}' failed the federation health check.{}{}{}

Please review the latest report at {} and take action if needed.

You will receive reminder emails every {} while the issue persists, and a confirmation email once the issue is resolved.

Best regards,
The Federation Tester Team

---
Unsubscribe: {}"#,
            env_banner,
            self.server_name,
            reminder_text,
            reason_text,
            quiet_note,
            self.check_url,
            self.reminder_interval,
            self.unsubscribe_url
        )
    }
}

#[derive(Template)]
#[template(path = "recovery_email.html")]
pub struct RecoveryEmailTemplate {
    pub server_name: String,
    pub check_url: String,
    pub unsubscribe_url: String,
    pub environment_name: Option<String>,
    /// When the server was confirmed healthy again (formatted).
    pub recovered_at: Option<String>,
    /// Approximate time when the failure started (formatted).
    pub first_detected: Option<String>,
    /// Total minutes the server was down.
    pub minutes_down: Option<u64>,
    /// Human-readable downtime string (e.g. "2h 15m").
    pub downtime_human: Option<String>,
    /// Machine-readable signal that confirmed recovery (e.g. a successful endpoint response).
    pub recovery_signal: Option<String>,
    /// Human-readable explanation of what changed.
    pub recovery_hint: Option<String>,
    /// Link to the alerts dashboard.
    pub manage_url: String,
    /// Optional sponsor link shown in email footer.
    pub sponsor_url: Option<String>,
}

impl RecoveryEmailTemplate {
    #[tracing::instrument(skip(self))]
    pub fn render_html(&self) -> Result<String, askama::Error> {
        let html = self.render()?;
        Ok(inline_css(&html))
    }

    #[tracing::instrument(skip(self))]
    pub fn render_text(&self) -> String {
        let env_banner = env_banner_text(self.environment_name.as_deref());

        let downtime_line = match (&self.minutes_down, &self.downtime_human) {
            (_, Some(h)) => format!("\nTotal downtime: {}\n", h),
            (Some(m), None) => format!("\nTotal downtime: {} minutes\n", m),
            _ => String::new(),
        };

        format!(
            r#"{}Hello,

Good news! Your server '{}' has recovered and is now passing federation health checks.{}
You can verify the current status at {}

We'll continue monitoring and will notify you if any issues arise again.

Best regards,
The Federation Tester Team

---
Unsubscribe: {}"#,
            env_banner, self.server_name, downtime_line, self.check_url, self.unsubscribe_url
        )
    }
}

#[derive(Template)]
#[template(path = "verification_email.html")]
pub struct VerificationEmailTemplate {
    pub server_name: String,
    pub verify_url: String,
    pub environment_name: Option<String>,
    pub recipient_email: String,
    pub manage_url: Option<String>,
    pub sponsor_url: Option<String>,
}

impl VerificationEmailTemplate {
    #[tracing::instrument(skip(self))]
    pub fn render_html(&self) -> Result<String, askama::Error> {
        let html = self.render()?;
        Ok(inline_css(&html))
    }

    #[tracing::instrument(skip(self))]
    pub fn render_text(&self) -> String {
        let env_banner = env_banner_text(self.environment_name.as_deref());

        format!(
            r#"{}Someone — hopefully you — added {} to a Connectivity Tester account to receive alerts for {}.

Verify this email address (valid for 1 hour):
{}

Didn't add this address? Safe to ignore — the link expires on its own.
"#,
            env_banner, self.recipient_email, self.server_name, self.verify_url
        )
    }
}

/// Template for account verification emails (OAuth2 registration)
#[derive(Template)]
#[template(path = "account_verification_email.html")]
pub struct AccountVerificationEmailTemplate {
    pub verify_url: String,
    pub environment_name: Option<String>,
    pub recipient_email: String,
    pub manage_url: Option<String>,
    pub sponsor_url: Option<String>,
}

impl AccountVerificationEmailTemplate {
    #[tracing::instrument(skip(self))]
    pub fn render_html(&self) -> Result<String, askama::Error> {
        let html = self.render()?;
        Ok(inline_css(&html))
    }

    #[tracing::instrument(skip(self))]
    pub fn render_text(&self) -> String {
        let env_banner = env_banner_text(self.environment_name.as_deref());

        format!(
            r#"{}Hello,

Thanks for signing up. Confirm that {} is yours and you'll be all set to start watching Matrix homeservers.

Verify and activate your account (valid for 24 hours):
{}

Didn't sign up? Safe to ignore — no account is created until the link is clicked.
"#,
            env_banner, self.recipient_email, self.verify_url
        )
    }
}

/// Template for password reset emails
#[derive(Template)]
#[template(path = "password_reset_email.html")]
pub struct PasswordResetEmailTemplate {
    pub reset_url: String,
    pub environment_name: Option<String>,
    pub recipient_email: String,
    pub manage_url: String,
    pub support_url: Option<String>,
    pub sponsor_url: Option<String>,
}

impl PasswordResetEmailTemplate {
    #[tracing::instrument(skip(self))]
    pub fn render_html(&self) -> Result<String, askama::Error> {
        let html = self.render()?;
        Ok(inline_css(&html))
    }

    #[tracing::instrument(skip(self))]
    pub fn render_text(&self) -> String {
        let env_banner = env_banner_text(self.environment_name.as_deref());

        format!(
            r#"{}Hello,

Someone requested a password reset for the Connectivity Tester account registered to {}.

Click the link below to set a new password (valid for 60 minutes):
{}

If you did not request this, you can safely ignore this email. Your password will not be changed.

Manage your account: {}
"#,
            env_banner, self.recipient_email, self.reset_url, self.manage_url
        )
    }
}

/// Template for server name change notification emails
#[derive(Template)]
#[template(path = "server_name_change_email.html")]
pub struct ServerNameChangeEmailTemplate {
    pub server_name: String,
    pub environment_name: Option<String>,
    pub detected_at: String,
    pub old_delegation_target: String,
    pub old_resolution_method: String,
    pub new_delegation_target: String,
    pub new_resolution_method: String,
    pub server_software: String,
    pub server_version: String,
    pub federation_status: String,
    pub check_url: String,
    pub unsubscribe_url: String,
    pub manage_url: String,
    pub sponsor_url: Option<String>,
}

impl ServerNameChangeEmailTemplate {
    #[tracing::instrument(skip(self))]
    pub fn render_html(&self) -> Result<String, askama::Error> {
        let html = self.render()?;
        Ok(inline_css(&html))
    }

    #[tracing::instrument(skip(self))]
    pub fn render_text(&self) -> String {
        let env_banner = env_banner_text(self.environment_name.as_deref());

        format!(
            r#"{}Federation delegation changed for {}.

  Was:  {} (via {})
  Now:  {} (via {})

  Implementation: {} {}
  Status: {}

This usually comes from a well-known or SRV record change. Worth opening the diagnostic.

Run a diagnostic: {}
Manage alerts: {}
Unsubscribe: {}
"#,
            env_banner,
            self.server_name,
            self.old_delegation_target,
            self.old_resolution_method,
            self.new_delegation_target,
            self.new_resolution_method,
            self.server_software,
            self.server_version,
            self.federation_status,
            self.check_url,
            self.manage_url,
            self.unsubscribe_url,
        )
    }
}

/// Template for server version change notification emails
#[derive(Template)]
#[template(path = "version_change_email.html")]
pub struct VersionChangeEmailTemplate {
    pub server_name: String,
    pub old_version_name: String,
    pub old_version_string: String,
    pub new_version_name: String,
    pub new_version_string: String,
    pub check_url: String,
    pub unsubscribe_url: String,
    pub environment_name: Option<String>,
    pub detected_at: Option<String>,
    pub manage_url: String,
    pub sponsor_url: Option<String>,
    /// URL to the upstream release page (Tier A or B).
    pub release_url: Option<String>,
    /// Plain-text excerpt from the release notes (Tier B only).
    pub release_notes_excerpt: Option<String>,
}

impl VersionChangeEmailTemplate {
    #[tracing::instrument(skip(self))]
    pub fn render_html(&self) -> Result<String, askama::Error> {
        let html = self.render()?;
        Ok(inline_css(&html))
    }

    #[tracing::instrument(skip(self))]
    pub fn render_text(&self) -> String {
        let env_banner = env_banner_text(self.environment_name.as_deref());

        let release_line = match (&self.release_url, &self.release_notes_excerpt) {
            (Some(url), Some(html_excerpt)) => {
                // Strip HTML tags for plain-text variant
                let plain = strip_html_tags(html_excerpt);
                format!(
                    "\nWhat's new:\n{}\n\nFull release notes: {}\n",
                    plain.trim(),
                    url
                )
            }
            (Some(url), None) => format!("\nRelease notes: {}\n", url),
            _ => String::new(),
        };

        format!(
            r#"{}A software update was detected for {}.

  Was: {} {}
  Now: {} {}
{}
This is an informational notification — no action required unless the update was unexpected.

Run a diagnostic: {}
Manage alerts: {}
Unsubscribe: {}
"#,
            env_banner,
            self.server_name,
            self.old_version_name,
            self.old_version_string,
            self.new_version_name,
            self.new_version_string,
            release_line,
            self.check_url,
            self.manage_url,
            self.unsubscribe_url
        )
    }
}

/// Template for TLS certificate change notification emails
#[derive(Template)]
#[template(path = "tls_cert_change_email.html")]
pub struct TlsCertChangeEmailTemplate {
    pub server_name: String,
    pub added_fingerprints: Vec<String>,
    pub removed_fingerprints: Vec<String>,
    pub check_url: String,
    pub unsubscribe_url: String,
    pub environment_name: Option<String>,
    pub detected_at: Option<String>,
    pub old_fingerprint: Option<String>,
    pub old_issuer: Option<String>,
    pub old_expires: Option<String>,
    pub new_fingerprint: Option<String>,
    pub new_issuer: Option<String>,
    pub new_expires: Option<String>,
    pub alert_url: String,
    pub manage_url: String,
    pub sponsor_url: Option<String>,
}

impl TlsCertChangeEmailTemplate {
    #[tracing::instrument(skip(self))]
    pub fn render_html(&self) -> Result<String, askama::Error> {
        let html = self.render()?;
        Ok(inline_css(&html))
    }

    #[tracing::instrument(skip(self))]
    pub fn render_text(&self) -> String {
        let env_banner = env_banner_text(self.environment_name.as_deref());
        let mut body = String::new();

        if !self.added_fingerprints.is_empty() {
            body.push_str("\nNew certificate:\n");
            for fp in &self.added_fingerprints {
                body.push_str(&format!("  {fp}\n"));
            }
        }
        if !self.removed_fingerprints.is_empty() {
            body.push_str("\nOld certificate:\n");
            for fp in &self.removed_fingerprints {
                body.push_str(&format!("  {fp}\n"));
            }
        }

        format!(
            r#"{}The TLS certificate for {} changed{}. This is usually an automatic renewal — verify it was expected.
{}
Manage alerts: {}
Unsubscribe: {}
"#,
            env_banner,
            self.server_name,
            self.detected_at
                .as_deref()
                .map(|d| format!(" at {d}"))
                .unwrap_or_default(),
            body,
            self.manage_url,
            self.unsubscribe_url
        )
    }
}

/// Template for TLS certificate expiry warning emails
#[derive(Template)]
#[template(path = "tls_expiry_email.html")]
pub struct TlsExpiryEmailTemplate {
    pub server_name: String,
    /// Pre-formatted expiry date string (UTC).
    pub expires_at: String,
    /// Human-readable expiry date (e.g. "Jan 15, 2024").
    pub expires_human: String,
    pub days_remaining: i64,
    pub check_url: String,
    pub unsubscribe_url: String,
    pub environment_name: Option<String>,
    pub issued_human: Option<String>,
    pub cert_cn: Option<String>,
    pub cert_san: Option<String>,
    pub cert_issuer: Option<String>,
    pub cert_fingerprint: Option<String>,
    pub manage_url: String,
    pub sponsor_url: Option<String>,
    pub renewal_guide_url: Option<String>,
}

impl TlsExpiryEmailTemplate {
    #[tracing::instrument(skip(self))]
    pub fn render_html(&self) -> Result<String, askama::Error> {
        let html = self.render()?;
        Ok(inline_css(&html))
    }

    #[tracing::instrument(skip(self))]
    pub fn render_text(&self) -> String {
        let env_banner = env_banner_text(self.environment_name.as_deref());
        let urgency = if self.days_remaining <= 7 {
            "URGENT: "
        } else {
            ""
        };
        format!(
            r#"{}{}The TLS certificate for {} expires in {} day{} ({}).

An expired TLS certificate will cause federation checks to fail and prevent other Matrix homeservers from connecting to yours. Renew your certificate before it expires.

Run a diagnostic: {}

Manage alerts: {}
Unsubscribe: {}
"#,
            env_banner,
            urgency,
            self.server_name,
            self.days_remaining,
            if self.days_remaining == 1 { "" } else { "s" },
            self.expires_at,
            self.check_url,
            self.manage_url,
            self.unsubscribe_url
        )
    }
}

/// Template for OAuth2 magic link sign-in emails
#[derive(Template)]
#[template(path = "magic_link_email.html")]
pub struct MagicLinkEmailTemplate {
    pub verify_url: String,
    pub environment_name: Option<String>,
    pub recipient_email: String,
    pub manage_url: String,
    pub sponsor_url: Option<String>,
}

impl MagicLinkEmailTemplate {
    #[tracing::instrument(skip(self))]
    pub fn render_html(&self) -> Result<String, askama::Error> {
        let html = self.render()?;
        Ok(inline_css(&html))
    }

    #[tracing::instrument(skip(self))]
    pub fn render_text(&self) -> String {
        let env_banner = env_banner_text(self.environment_name.as_deref());

        format!(
            r#"{}Use the link below to sign in to the Connectivity Tester as {}. Valid for 60 minutes, single use.

{}

Didn't ask for this? Safe to ignore — the link only works for the person who has access to this inbox.

Manage account: {}
"#,
            env_banner, self.recipient_email, self.verify_url, self.manage_url
        )
    }
}

/// Template for test notification emails (triggered via "Send test email" button)
#[derive(Template)]
#[template(path = "test_email.html")]
pub struct TestEmailTemplate {
    pub server_name: String,
    pub check_url: String,
    pub alert_url: String,
    pub manage_url: String,
    pub environment_name: Option<String>,
    pub sponsor_url: Option<String>,
}

impl TestEmailTemplate {
    #[tracing::instrument(skip(self))]
    pub fn render_html(&self) -> Result<String, askama::Error> {
        let html = self.render()?;
        Ok(inline_css(&html))
    }

    #[tracing::instrument(skip(self))]
    pub fn render_text(&self) -> String {
        let env_banner = env_banner_text(self.environment_name.as_deref());

        format!(
            r#"{}This is a test notification for your federation alert on {}.

If you received this, email delivery is working correctly.

View current status: {}
Manage alert: {}
"#,
            env_banner, self.server_name, self.check_url, self.alert_url
        )
    }
}

fn strip_html_tags(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut in_tag = false;
    for c in html.chars() {
        match c {
            '<' => in_tag = true,
            '>' => {
                in_tag = false;
                out.push(' ');
            }
            _ if !in_tag => {
                // Decode common HTML entities
                out.push(c);
            }
            _ => {}
        }
    }
    // Normalise whitespace runs
    out.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace(" …", "…")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_failure_email_template() {
        let template = FailureEmailTemplate {
            server_name: "example.org".to_string(),
            check_url: "https://test.example.com/results?serverName=example.org".to_string(),
            failure_count: 1,
            reminder_interval: "12 hours".to_string(),
            unsubscribe_url: "https://test.example.com/unsubscribe?token=xyz".to_string(),
            failure_reason: None,
            environment_name: None,
            quiet_hours_note: None,
            first_detected: None,
            minutes_down: None,
            last_healthy: None,
            error_hint: None,
            reminder_total: None,
            alert_url: "https://test.example.com/alerts/edit/1".to_string(),
            manage_url: "https://test.example.com/alerts".to_string(),
            sponsor_url: None,
        };

        let html = template.render_html().expect("Failed to render HTML");
        assert!(html.contains("example.org"));
        assert!(html.contains("style="));

        let text = template.render_text();
        assert!(text.contains("example.org"));
    }

    #[test]
    fn test_recovery_email_template() {
        let template = RecoveryEmailTemplate {
            server_name: "example.org".to_string(),
            check_url: "https://test.example.com/results?serverName=example.org".to_string(),
            unsubscribe_url: "https://test.example.com/unsubscribe?token=xyz".to_string(),
            environment_name: None,
            recovered_at: Some("2024-01-15T16:47:00Z".to_string()),
            first_detected: Some("2024-01-15T14:32:00Z".to_string()),
            minutes_down: Some(135),
            downtime_human: Some("2h 15m".to_string()),
            recovery_signal: None,
            recovery_hint: None,
            manage_url: "https://test.example.com/alerts".to_string(),
            sponsor_url: None,
        };

        let html = template.render_html().expect("Failed to render HTML");
        assert!(html.contains("example.org"));
        assert!(html.contains("recovered"));

        let text = template.render_text();
        assert!(text.contains("Good news!"));
    }

    #[test]
    fn test_verification_email_template() {
        let template = VerificationEmailTemplate {
            server_name: "example.org".to_string(),
            verify_url: "https://test.example.com/verify?token=abc123".to_string(),
            environment_name: None,
            recipient_email: "user@example.com".to_string(),
            manage_url: None,
            sponsor_url: None,
        };

        let html = template.render_html().expect("Failed to render HTML");
        assert!(html.contains("user@example.com"));
        assert!(html.contains("Verify"));
        assert!(html.contains("abc123"));

        let text = template.render_text();
        assert!(text.contains("user@example.com"));
        assert!(text.contains("example.org"));
    }

    #[test]
    fn test_scss_compilation() {
        let css = &*COMPILED_CSS;
        assert!(!css.is_empty());
        assert!(css.contains("email-container"));
    }

    // ── env_subject ───────────────────────────────────────────────────────────

    #[test]
    fn env_subject_prepends_staging() {
        assert_eq!(env_subject("Hello", Some("staging")), "[staging] Hello");
    }

    #[test]
    fn env_subject_prepends_mixed_case() {
        assert_eq!(env_subject("Hello", Some("Staging")), "[Staging] Hello");
    }

    #[test]
    fn env_subject_skips_production() {
        assert_eq!(env_subject("Hello", Some("production")), "Hello");
    }

    #[test]
    fn env_subject_skips_production_upper() {
        assert_eq!(env_subject("Hello", Some("PRODUCTION")), "Hello");
    }

    #[test]
    fn env_subject_skips_empty_string() {
        assert_eq!(env_subject("Hello", Some("")), "Hello");
    }

    #[test]
    fn env_subject_skips_none() {
        assert_eq!(env_subject("Hello", None), "Hello");
    }

    // ── env_banner_text ───────────────────────────────────────────────────────

    #[test]
    fn env_banner_text_staging_is_uppercased() {
        assert_eq!(
            env_banner_text(Some("staging")),
            "*** Sent from the STAGING environment ***\n\n"
        );
    }

    #[test]
    fn env_banner_text_production_is_empty() {
        assert_eq!(env_banner_text(Some("production")), "");
    }

    #[test]
    fn env_banner_text_none_is_empty() {
        assert_eq!(env_banner_text(None), "");
    }

    #[test]
    fn env_banner_text_empty_string_is_empty() {
        assert_eq!(env_banner_text(Some("")), "");
    }

    // ── strip_html_tags ───────────────────────────────────────────────────────

    #[test]
    fn strip_html_plain_text_unchanged() {
        assert_eq!(strip_html_tags("Hello world"), "Hello world");
    }

    #[test]
    fn strip_html_removes_tags() {
        assert_eq!(strip_html_tags("<p>Hello</p>"), "Hello");
    }

    #[test]
    fn strip_html_removes_nested_tags() {
        assert_eq!(
            strip_html_tags("<p><strong>Bold</strong> text</p>"),
            "Bold text"
        );
    }

    #[test]
    fn strip_html_normalises_whitespace() {
        assert_eq!(strip_html_tags("  foo   bar  "), "foo bar");
    }

    #[test]
    fn strip_html_leaves_entities_as_is() {
        // The function does NOT decode HTML entities — they pass through literally.
        assert_eq!(strip_html_tags("&amp;"), "&amp;");
    }

    // ── FailureEmailTemplate::render_text ─────────────────────────────────────

    fn base_failure_template() -> FailureEmailTemplate {
        FailureEmailTemplate {
            server_name: "matrix.example.com".to_string(),
            check_url: "https://checker.example/results?s=matrix.example.com".to_string(),
            failure_count: 1,
            reminder_interval: "12 hours".to_string(),
            unsubscribe_url: "https://checker.example/unsub?t=abc".to_string(),
            failure_reason: None,
            environment_name: None,
            quiet_hours_note: None,
            first_detected: None,
            minutes_down: None,
            last_healthy: None,
            error_hint: None,
            reminder_total: None,
            alert_url: "https://checker.example/alerts/1".to_string(),
            manage_url: "https://checker.example/alerts".to_string(),
            sponsor_url: None,
        }
    }

    #[test]
    fn failure_render_text_count_1_no_reminder_line() {
        let t = base_failure_template();
        let text = t.render_text();
        assert!(
            !text.contains("reminder #"),
            "count=1 should not include reminder line"
        );
    }

    #[test]
    fn failure_render_text_count_2_includes_reminder_line() {
        let t = FailureEmailTemplate {
            failure_count: 2,
            ..base_failure_template()
        };
        let text = t.render_text();
        assert!(text.contains("reminder #2"));
    }

    #[test]
    fn failure_render_text_includes_failure_reason() {
        let t = FailureEmailTemplate {
            failure_reason: Some("TLS handshake timeout".to_string()),
            ..base_failure_template()
        };
        let text = t.render_text();
        assert!(text.contains("TLS handshake timeout"));
    }

    #[test]
    fn failure_render_text_includes_quiet_hours_note() {
        let t = FailureEmailTemplate {
            quiet_hours_note: Some("Email was delayed by quiet hours".to_string()),
            ..base_failure_template()
        };
        let text = t.render_text();
        assert!(text.contains("Email was delayed by quiet hours"));
    }

    #[test]
    fn failure_render_text_staging_banner() {
        let t = FailureEmailTemplate {
            environment_name: Some("staging".to_string()),
            ..base_failure_template()
        };
        let text = t.render_text();
        assert!(text.starts_with("*** Sent from the STAGING environment ***"));
    }

    // ── RecoveryEmailTemplate::render_text ────────────────────────────────────

    fn base_recovery_template() -> RecoveryEmailTemplate {
        RecoveryEmailTemplate {
            server_name: "matrix.example.com".to_string(),
            check_url: "https://checker.example/results".to_string(),
            unsubscribe_url: "https://checker.example/unsub".to_string(),
            environment_name: None,
            recovered_at: None,
            first_detected: None,
            minutes_down: None,
            downtime_human: None,
            recovery_signal: None,
            recovery_hint: None,
            manage_url: "https://checker.example/alerts".to_string(),
            sponsor_url: None,
        }
    }

    #[test]
    fn recovery_render_text_uses_downtime_human_when_available() {
        let t = RecoveryEmailTemplate {
            minutes_down: Some(135),
            downtime_human: Some("2h 15m".to_string()),
            ..base_recovery_template()
        };
        assert!(t.render_text().contains("Total downtime: 2h 15m"));
    }

    #[test]
    fn recovery_render_text_falls_back_to_minutes_when_no_human() {
        let t = RecoveryEmailTemplate {
            minutes_down: Some(45),
            downtime_human: None,
            ..base_recovery_template()
        };
        assert!(t.render_text().contains("Total downtime: 45 minutes"));
    }

    #[test]
    fn recovery_render_text_no_downtime_line_when_none() {
        let t = base_recovery_template();
        let text = t.render_text();
        assert!(
            !text.contains("downtime"),
            "no downtime info should produce no downtime line"
        );
    }

    // ── TlsExpiryEmailTemplate::render_text ───────────────────────────────────

    fn base_expiry_template(days: i64) -> TlsExpiryEmailTemplate {
        TlsExpiryEmailTemplate {
            server_name: "matrix.example.com".to_string(),
            expires_at: "2024-02-01 00:00 UTC".to_string(),
            expires_human: "Feb 1, 2024".to_string(),
            days_remaining: days,
            check_url: "https://checker.example/results".to_string(),
            unsubscribe_url: "https://checker.example/unsub".to_string(),
            environment_name: None,
            issued_human: None,
            cert_cn: None,
            cert_san: None,
            cert_issuer: None,
            cert_fingerprint: None,
            manage_url: "https://checker.example/alerts".to_string(),
            sponsor_url: None,
            renewal_guide_url: None,
        }
    }

    #[test]
    fn tls_expiry_render_text_urgent_when_7_days_or_fewer() {
        let text = base_expiry_template(5).render_text();
        assert!(text.contains("URGENT:"));
    }

    #[test]
    fn tls_expiry_render_text_not_urgent_when_more_than_7_days() {
        let text = base_expiry_template(14).render_text();
        assert!(!text.contains("URGENT:"));
    }

    #[test]
    fn tls_expiry_render_text_singular_day() {
        let text = base_expiry_template(1).render_text();
        assert!(text.contains("1 day "), "should say '1 day' not '1 days'");
    }

    #[test]
    fn tls_expiry_render_text_plural_days() {
        let text = base_expiry_template(3).render_text();
        assert!(text.contains("3 days"));
    }

    // ── VersionChangeEmailTemplate::render_text ───────────────────────────────

    fn base_version_template() -> VersionChangeEmailTemplate {
        VersionChangeEmailTemplate {
            server_name: "matrix.example.com".to_string(),
            old_version_name: "Synapse".to_string(),
            old_version_string: "1.99.0".to_string(),
            new_version_name: "Synapse".to_string(),
            new_version_string: "1.100.0".to_string(),
            check_url: "https://checker.example/results".to_string(),
            unsubscribe_url: "https://checker.example/unsub".to_string(),
            environment_name: None,
            detected_at: None,
            manage_url: "https://checker.example/alerts".to_string(),
            sponsor_url: None,
            release_url: None,
            release_notes_excerpt: None,
        }
    }

    #[test]
    fn version_render_text_shows_versions() {
        let text = base_version_template().render_text();
        assert!(text.contains("1.99.0"));
        assert!(text.contains("1.100.0"));
    }

    #[test]
    fn version_render_text_release_url_only() {
        let t = VersionChangeEmailTemplate {
            release_url: Some("https://github.com/synapse/releases/1.100.0".to_string()),
            ..base_version_template()
        };
        let text = t.render_text();
        assert!(text.contains("Release notes:"));
        assert!(!text.contains("What's new:"));
    }

    #[test]
    fn version_render_text_release_url_with_excerpt() {
        let t = VersionChangeEmailTemplate {
            release_url: Some("https://github.com/synapse/releases/1.100.0".to_string()),
            release_notes_excerpt: Some(
                "<p>Bug fixes and performance improvements</p>".to_string(),
            ),
            ..base_version_template()
        };
        let text = t.render_text();
        assert!(text.contains("What's new:"));
        assert!(text.contains("Bug fixes and performance improvements"));
    }

    // ── TlsCertChangeEmailTemplate::render_text ───────────────────────────────

    #[test]
    fn tls_cert_change_render_text_with_fingerprints() {
        let t = TlsCertChangeEmailTemplate {
            server_name: "matrix.example.com".to_string(),
            added_fingerprints: vec!["AA:BB:CC".to_string()],
            removed_fingerprints: vec!["11:22:33".to_string()],
            check_url: "https://checker.example/results".to_string(),
            unsubscribe_url: "https://checker.example/unsub".to_string(),
            environment_name: None,
            detected_at: Some("2024-01-15 14:32 UTC".to_string()),
            old_fingerprint: None,
            old_issuer: None,
            old_expires: None,
            new_fingerprint: None,
            new_issuer: None,
            new_expires: None,
            alert_url: "https://checker.example/alerts/1".to_string(),
            manage_url: "https://checker.example/alerts".to_string(),
            sponsor_url: None,
        };
        let text = t.render_text();
        assert!(text.contains("AA:BB:CC"));
        assert!(text.contains("11:22:33"));
        assert!(text.contains("2024-01-15 14:32 UTC"));
    }

    // ── ServerNameChangeEmailTemplate::render_text ────────────────────────────

    #[test]
    fn server_name_change_render_text() {
        let t = ServerNameChangeEmailTemplate {
            server_name: "matrix.example.com".to_string(),
            environment_name: None,
            detected_at: "2024-01-15 14:32 UTC".to_string(),
            old_delegation_target: "old.matrix.example.com:8448".to_string(),
            old_resolution_method: "well-known".to_string(),
            new_delegation_target: "new.matrix.example.com:8448".to_string(),
            new_resolution_method: "SRV".to_string(),
            server_software: "Synapse".to_string(),
            server_version: "1.100.0".to_string(),
            federation_status: "OK".to_string(),
            check_url: "https://checker.example/results".to_string(),
            unsubscribe_url: "https://checker.example/unsub".to_string(),
            manage_url: "https://checker.example/alerts".to_string(),
            sponsor_url: None,
        };
        let text = t.render_text();
        assert!(text.contains("old.matrix.example.com"));
        assert!(text.contains("new.matrix.example.com"));
        assert!(text.contains("well-known"));
        assert!(text.contains("SRV"));
    }

    // ── AccountVerificationEmailTemplate::render_text ─────────────────────────

    #[test]
    fn account_verification_render_text() {
        let t = AccountVerificationEmailTemplate {
            verify_url: "https://checker.example/verify?token=abc123".to_string(),
            environment_name: None,
            recipient_email: "user@example.com".to_string(),
            manage_url: None,
            sponsor_url: None,
        };
        let text = t.render_text();
        assert!(text.contains("user@example.com"));
        assert!(text.contains("abc123"));
    }

    // ── PasswordResetEmailTemplate::render_text ───────────────────────────────

    #[test]
    fn password_reset_render_text() {
        let t = PasswordResetEmailTemplate {
            reset_url: "https://checker.example/reset?token=xyz".to_string(),
            environment_name: None,
            recipient_email: "user@example.com".to_string(),
            manage_url: "https://checker.example/account".to_string(),
            support_url: None,
            sponsor_url: None,
        };
        let text = t.render_text();
        assert!(text.contains("user@example.com"));
        assert!(text.contains("xyz"));
    }

    // ── MagicLinkEmailTemplate::render_text ───────────────────────────────────

    #[test]
    fn magic_link_render_text() {
        let t = MagicLinkEmailTemplate {
            verify_url: "https://checker.example/magic?token=tok".to_string(),
            environment_name: None,
            recipient_email: "user@example.com".to_string(),
            manage_url: "https://checker.example/account".to_string(),
            sponsor_url: None,
        };
        let text = t.render_text();
        assert!(text.contains("user@example.com"));
        assert!(text.contains("tok"));
    }

    // ── TestEmailTemplate::render_text ────────────────────────────────────────

    #[test]
    fn test_email_render_text() {
        let t = TestEmailTemplate {
            server_name: "matrix.example.com".to_string(),
            check_url: "https://checker.example/results".to_string(),
            alert_url: "https://checker.example/alerts/1".to_string(),
            manage_url: "https://checker.example/alerts".to_string(),
            environment_name: None,
            sponsor_url: None,
        };
        let text = t.render_text();
        assert!(text.contains("matrix.example.com"));
        assert!(text.contains("test notification"));
    }
}
