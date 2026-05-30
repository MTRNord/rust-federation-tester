//! Backend abstraction traits for email sending.
//!
//! Defines [`EmailSender`] so the alert and outbox subsystems are decoupled from
//! the concrete SMTP transport. Homeservers embedding the alert layer can implement
//! [`EmailSender`] against their own email infrastructure without depending on lettre.

use std::sync::Arc;

/// A fully-rendered outgoing email ready to hand to a transport.
#[derive(Debug, Clone)]
pub struct OutgoingEmail {
    pub from: String,
    pub to: String,
    pub subject: String,
    pub text_body: String,
    /// HTML variant. When absent the message is delivered as plain text only.
    pub html_body: Option<String>,
    /// Value for the `List-Unsubscribe` header (e.g. `<https://…/unsub?token=…>`).
    /// Omitted when `None`.
    pub list_unsubscribe: Option<String>,
}

/// Transport-independent email sender.
///
/// Implementations receive a fully-rendered [`OutgoingEmail`] and are responsible
/// for delivering it however they see fit — SMTP, HTTP API, a log sink for testing, etc.
#[async_trait::async_trait]
pub trait EmailSender: Send + Sync + std::fmt::Debug + 'static {
    async fn send(
        &self,
        email: OutgoingEmail,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

/// [`EmailSender`] backed by a lettre SMTP transport.
#[derive(Debug)]
pub struct LettreSmtpSender {
    transport: Arc<lettre::AsyncSmtpTransport<lettre::Tokio1Executor>>,
}

impl LettreSmtpSender {
    pub fn new(transport: Arc<lettre::AsyncSmtpTransport<lettre::Tokio1Executor>>) -> Self {
        Self { transport }
    }
}

#[async_trait::async_trait]
impl EmailSender for LettreSmtpSender {
    async fn send(
        &self,
        email: OutgoingEmail,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use lettre::AsyncTransport;
        use lettre::message::header::{self};
        use lettre::message::{MultiPart, SinglePart};

        let from: lettre::message::Mailbox = email.from.parse()?;
        let to: lettre::message::Mailbox = email.to.parse()?;

        let mut builder = lettre::Message::builder()
            .from(from)
            .to(to)
            .subject(email.subject)
            .header(header::MIME_VERSION_1_0)
            .message_id(None);

        if let Some(url) = email.list_unsubscribe {
            builder = builder.header(crate::alerts::email::UnsubscribeHeader::from(url));
        }

        let msg = if let Some(html) = email.html_body {
            builder.multipart(
                MultiPart::alternative()
                    .singlepart(
                        SinglePart::builder()
                            .header(header::ContentType::TEXT_PLAIN)
                            .body(email.text_body),
                    )
                    .singlepart(
                        SinglePart::builder()
                            .header(header::ContentType::TEXT_HTML)
                            .body(html),
                    ),
            )?
        } else {
            builder
                .header(header::ContentType::TEXT_PLAIN)
                .body(email.text_body)?
        };

        self.transport.send(msg).await?;
        Ok(())
    }
}
