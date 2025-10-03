//! Email template rendering with HTML (Askama) and SCSS styling
use askama::Template;
use once_cell::sync::Lazy;

/// Compiled and inlined CSS from SCSS
static COMPILED_CSS: Lazy<String> = Lazy::new(|| {
    let scss = include_str!("../styles/email.scss");
    grass::from_string(scss.to_string(), &grass::Options::default())
        .expect("Failed to compile SCSS")
});

/// Inline CSS into HTML
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
            tracing::error!("Failed to inline CSS: {:?}", e);
            html.to_string()
        }
    }
}

#[derive(Template)]
#[template(path = "failure_email.html")]
pub struct FailureEmailTemplate {
    pub server_name: String,
    pub check_url: String,
    pub is_reminder: bool,
    pub failure_count: i32,
    pub reminder_interval: String,
    pub unsubscribe_url: String,
}

impl FailureEmailTemplate {
    pub fn render_html(&self) -> Result<String, askama::Error> {
        let html = self.render()?;
        Ok(inline_css(&html))
    }

    pub fn render_text(&self) -> String {
        let reminder_text = if self.failure_count > 1 {
            format!(
                "\nThis is reminder #{} - the server has been failing for a while.\n",
                self.failure_count
            )
        } else {
            String::new()
        };

        format!(
            r#"Hello,

Your server '{}' failed the federation health check.{}

Please review the latest report at {} and take action if needed.

You will receive reminder emails every {} while the issue persists, and a confirmation email once the issue is resolved.

Best regards,
The Federation Tester Team

---
Unsubscribe: {}"#,
            self.server_name,
            reminder_text,
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
}

impl RecoveryEmailTemplate {
    pub fn render_html(&self) -> Result<String, askama::Error> {
        let html = self.render()?;
        Ok(inline_css(&html))
    }

    pub fn render_text(&self) -> String {
        format!(
            r#"Hello,

Good news! Your server '{}' has recovered and is now passing federation health checks.

You can verify the current status at {}

We'll continue monitoring and will notify you if any issues arise again.

Best regards,
The Federation Tester Team

---
Unsubscribe: {}"#,
            self.server_name, self.check_url, self.unsubscribe_url
        )
    }
}

#[derive(Template)]
#[template(path = "verification_email.html")]
pub struct VerificationEmailTemplate {
    pub server_name: String,
    pub verify_url: String,
}

impl VerificationEmailTemplate {
    pub fn render_html(&self) -> Result<String, askama::Error> {
        let html = self.render()?;
        Ok(inline_css(&html))
    }

    pub fn render_text(&self) -> String {
        format!(
            r#"Hello,

You requested to receive alerts for your server: {}

Please verify your email address by clicking the link below (valid for 1 hour):
{}

If you did not request this, you can ignore this email.

Best regards,
The Federation Tester Team"#,
            self.server_name, self.verify_url
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
            check_url: "https://test.example.com/?serverName=example.org".to_string(),
            is_reminder: false,
            failure_count: 1,
            reminder_interval: "12 hours".to_string(),
            unsubscribe_url: "https://test.example.com/unsubscribe?token=xyz".to_string(),
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
            check_url: "https://test.example.com/?serverName=example.org".to_string(),
            unsubscribe_url: "https://test.example.com/unsubscribe?token=xyz".to_string(),
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
