use std::net::IpAddr;

use serde::Deserialize;

#[derive(Clone)]
pub enum Turnstile {
    Disabled,
    Enabled {
        secret: String,
        client: reqwest::Client,
    },
}

#[derive(Debug, Deserialize)]
struct VerifyResponse {
    success: bool,
}

impl Turnstile {
    pub fn from_secret(secret: Option<String>) -> Self {
        match secret {
            None => {
                tracing::info!("Turnstile not configured — signup will accept any token");
                Self::Disabled
            }
            Some(s) => Self::Enabled {
                secret: s,
                client: reqwest::Client::new(),
            },
        }
    }

    pub async fn verify(&self, token: &str, ip: IpAddr) -> bool {
        match self {
            Self::Disabled => true,
            Self::Enabled { secret, client } => {
                let res = client
                    .post("https://challenges.cloudflare.com/turnstile/v0/siteverify")
                    .form(&[
                        ("secret", secret.as_str()),
                        ("response", token),
                        ("remoteip", &ip.to_string()),
                    ])
                    .send()
                    .await;
                match res {
                    Ok(r) => r
                        .json::<VerifyResponse>()
                        .await
                        .map(|v| v.success)
                        .unwrap_or(false),
                    Err(e) => {
                        tracing::warn!(error = %e, "turnstile verify failed");
                        false
                    }
                }
            }
        }
    }
}
