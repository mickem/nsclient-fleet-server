use anyhow::Result;
use lettre::{
    message::{header::ContentType, Mailbox},
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};

use crate::config::SmtpConfig;

#[derive(Clone)]
pub enum EmailSender {
    Stdout,
    Smtp(Box<SmtpSender>),
}

#[derive(Clone)]
pub struct SmtpSender {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
}

impl EmailSender {
    pub fn from_config(smtp: Option<&SmtpConfig>) -> Result<Self> {
        match smtp {
            None => {
                // Startup refuses this combination anywhere that terminates TLS, so
                // reaching here means a development server or an explicit opt-in. Say what
                // it costs anyway: a sign-in link in a log is a credential in a log.
                tracing::warn!(
                    "SMTP not configured — every sign-in link will be written to the log in \
                     full, and anyone who can read the log can use it"
                );
                Ok(Self::Stdout)
            }
            Some(cfg) => {
                // Port 465 expects implicit TLS (`relay`); 587 and 25 expect a plaintext
                // greeting followed by STARTTLS (`starttls_relay`).
                let builder = if cfg.port == 465 {
                    AsyncSmtpTransport::<Tokio1Executor>::relay(&cfg.host)?
                } else {
                    AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&cfg.host)?
                };
                let transport = builder
                    .port(cfg.port)
                    .credentials(Credentials::new(cfg.user.clone(), cfg.password.clone()))
                    .build();
                let from: Mailbox = cfg.from.parse()?;
                Ok(Self::Smtp(Box::new(SmtpSender { transport, from })))
            }
        }
    }

    pub async fn send_magic_link(&self, to_email: &str, link: &str) -> Result<()> {
        match self {
            Self::Stdout => {
                tracing::info!(target: "magic_link", email = to_email, %link, "[DEV] magic link");
                Ok(())
            }
            Self::Smtp(s) => {
                let to: Mailbox = to_email.parse()?;
                let body = format!(
                    "Sign in to NSClient Fleet:\n\n{link}\n\nThis link expires in 15 minutes and can be used once."
                );
                let msg = Message::builder()
                    .from(s.from.clone())
                    .to(to)
                    .subject("Sign in to NSClient Fleet")
                    .header(ContentType::TEXT_PLAIN)
                    .body(body)?;
                s.transport.send(msg).await?;
                Ok(())
            }
        }
    }
}
