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
                tracing::warn!("SMTP not configured — magic links will be logged to stdout");
                Ok(Self::Stdout)
            }
            Some(cfg) => {
                let transport = AsyncSmtpTransport::<Tokio1Executor>::relay(&cfg.host)?
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
