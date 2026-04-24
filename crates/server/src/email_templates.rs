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

        format!(
            r#"{}Hello,

Your server '{}' failed the federation health check.{}{}

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

        format!(
            r#"{}Hello,

Good news! Your server '{}' has recovered and is now passing federation health checks.

You can verify the current status at {}

We'll continue monitoring and will notify you if any issues arise again.

Best regards,
The Federation Tester Team

---
Unsubscribe: {}"#,
            env_banner, self.server_name, self.check_url, self.unsubscribe_url
        )
    }
}

#[derive(Template)]
#[template(path = "verification_email.html")]
pub struct VerificationEmailTemplate {
    pub server_name: String,
    pub verify_url: String,
    pub environment_name: Option<String>,
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
            r#"{}Hello,

You requested to receive alerts for your server: {}

Please verify your email address by clicking the link below (valid for 1 hour):
{}

If you did not request this, you can ignore this email.

Best regards,
The Federation Tester Team"#,
            env_banner, self.server_name, self.verify_url
        )
    }
}

/// Template for account verification emails (OAuth2 registration)
#[derive(Template)]
#[template(path = "account_verification_email.html")]
pub struct AccountVerificationEmailTemplate {
    pub verify_url: String,
    pub environment_name: Option<String>,
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

Thanks for creating an account with Federation Tester.

Please verify your email address by clicking the link below (valid for 24 hours):
{}

Once verified, you'll be able to sign in and manage your federation alert subscriptions.

If you did not create this account, you can safely ignore this email.

Best regards,
The Federation Tester Team"#,
            env_banner, self.verify_url
        )
    }
}

/// Template for password reset emails
#[derive(Template)]
#[template(path = "password_reset_email.html")]
pub struct PasswordResetEmailTemplate {
    pub reset_url: String,
    pub environment_name: Option<String>,
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

You requested a password reset for your Federation Tester account.

Click the link below to set a new password (valid for 1 hour):
{}

If you did not request this, you can safely ignore this email. Your password will not be changed.

Best regards,
The Federation Tester Team"#,
            env_banner, self.reset_url
        )
    }
}

/// Template for OAuth2 magic link sign-in emails
#[derive(Template)]
#[template(path = "magic_link_email.html")]
pub struct MagicLinkEmailTemplate {
    pub verify_url: String,
    pub environment_name: Option<String>,
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
            r#"{}Hello,

You requested to sign in to Federation Tester.

Click the link below to sign in (valid for 1 hour):
{}

If you did not request this, you can safely ignore this email.

Best regards,
The Federation Tester Team"#,
            env_banner, self.verify_url
        )
    }
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
        };

        let html = template.render_html().expect("Failed to render HTML");
        assert!(html.contains("example.org"));
        assert!(html.contains("Verify"));
        assert!(html.contains("abc123"));

        let text = template.render_text();
        assert!(text.contains("verify"));
        assert!(text.contains("example.org"));
    }

    #[test]
    fn test_scss_compilation() {
        let css = &*COMPILED_CSS;
        assert!(!css.is_empty());
        assert!(css.contains("email-container"));
    }
}
