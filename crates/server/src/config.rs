use std::path::PathBuf;

use fleet_core::aead::MasterKey;

#[derive(Clone)]
pub struct Config {
    pub listen: String,
    pub listen_https: String,
    /// Dedicated agent-mTLS listen address, or empty to serve agents on `listen_https`
    /// via the shared-port mux. Empty is the default whenever ACME is enabled.
    pub listen_mtls: String,
    /// Base URL handed to agents at enrollment for every `/agent/v1/*` call. Derived from
    /// `base_url` plus whichever port actually carries agent traffic; `MTLS_URL` overrides.
    pub agent_mtls_url: String,
    pub database_path: PathBuf,
    pub base_url: String,
    pub on_prem: bool,
    pub on_prem_admin_email: Option<String>,
    pub on_prem_admin_password: Option<String>,
    /// Addresses that are granted the platform-admin flag at startup (and when they sign up).
    /// This is the bootstrap only: the flag lives in the database and is granted and revoked
    /// from the console after that. Lowercased on load so comparisons match stored addresses.
    pub platform_admin_emails: Vec<String>,
    pub magic_link_ttl_secs: i64,
    pub session_ttl_secs: i64,
    pub bootstrap_ttl_secs: i64,
    pub client_cert_lifetime_days: i64,
    pub cookie_secure: bool,
    pub daily_email_budget: u32,
    pub smtp: Option<SmtpConfig>,
    pub turnstile_secret: Option<String>,
    pub master_key: MasterKey,
    pub bootstrap_jwt_secret: Vec<u8>,
    pub acme: Option<AcmeConfig>,
}

#[derive(Clone, Debug)]
pub struct AcmeConfig {
    pub domains: Vec<String>,
    pub contact_email: String,
    pub cache_dir: PathBuf,
    /// True for Let's Encrypt production; false for the staging directory (use during testing).
    pub production: bool,
}

#[derive(Clone, Debug)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    pub from: String,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let on_prem = bool_env("ON_PREM", false);

        let smtp = match (
            std::env::var("SMTP_HOST").ok(),
            std::env::var("SMTP_USER").ok(),
            std::env::var("SMTP_PASSWORD").ok(),
            std::env::var("SMTP_FROM").ok(),
        ) {
            (Some(host), Some(user), Some(password), Some(from)) => Some(SmtpConfig {
                host,
                port: std::env::var("SMTP_PORT")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(587),
                user,
                password,
                from,
            }),
            _ => None,
        };

        let master_key = MasterKey::from_env().map_err(|e| anyhow::anyhow!(
            "MASTER_KEY required (32 bytes, base64-encoded). \
             Generate one with `openssl rand -base64 32` or via the `fleet_core::aead::MasterKey::generate_b64` helper. \
             Underlying error: {e}"
        ))?;

        let bootstrap_jwt_secret = match std::env::var("BOOTSTRAP_JWT_SECRET") {
            Ok(s) => {
                use base64::{engine::general_purpose::STANDARD, Engine as _};
                STANDARD
                    .decode(s)
                    .map_err(|e| anyhow::anyhow!("BOOTSTRAP_JWT_SECRET base64: {e}"))?
            }
            // Reuse master key bytes for JWT signing if no separate secret is configured.
            // Same key, same trust boundary; we still get integrity + expiry checking.
            Err(_) => MasterKey::from_env()
                .map_err(|e| anyhow::anyhow!("MASTER_KEY: {e}"))
                .and_then(|_| {
                    use base64::{engine::general_purpose::STANDARD, Engine as _};
                    STANDARD
                        .decode(std::env::var("MASTER_KEY").unwrap())
                        .map_err(|e| anyhow::anyhow!("master key base64: {e}"))
                })?,
        };

        let acme = match (
            std::env::var("ACME_DOMAINS").ok(),
            std::env::var("ACME_CONTACT").ok(),
        ) {
            (Some(domains), Some(contact)) if !domains.trim().is_empty() => {
                let parsed: Vec<String> = domains
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                if parsed.is_empty() {
                    None
                } else {
                    Some(AcmeConfig {
                        domains: parsed,
                        contact_email: contact,
                        cache_dir: std::env::var("ACME_CACHE_DIR")
                            .unwrap_or_else(|_| "data/acme".into())
                            .into(),
                        production: !bool_env("ACME_STAGING", false),
                    })
                }
            }
            _ => None,
        };

        let listen_https = std::env::var("LISTEN_HTTPS").unwrap_or_else(|_| "0.0.0.0:443".into());
        let base_url = std::env::var("BASE_URL").unwrap_or_else(|_| "http://localhost:3000".into());

        // With ACME on, agents share the HTTPS port (routed by ALPN — see `crate::mux`), so
        // there is nothing to bind separately and the firewall only needs 443. Setting
        // LISTEN_MTLS explicitly opts back into a dedicated port: useful on-prem, behind a
        // load balancer that can't pass ALPN through, or while migrating a live fleet.
        let listen_mtls = match (std::env::var("LISTEN_MTLS").ok(), acme.is_some()) {
            (Some(addr), _) => addr,
            (None, true) => String::new(),
            (None, false) => "0.0.0.0:9443".into(),
        };
        let agent_mtls_url = std::env::var("MTLS_URL")
            .unwrap_or_else(|_| derive_agent_mtls_url(&base_url, &listen_https, &listen_mtls));

        Ok(Self {
            listen: std::env::var("LISTEN").unwrap_or_else(|_| "0.0.0.0:3000".into()),
            listen_https,
            listen_mtls,
            agent_mtls_url,
            database_path: std::env::var("DATABASE_PATH")
                .unwrap_or_else(|_| "data/fleet.db".into())
                .into(),
            base_url,
            on_prem,
            on_prem_admin_email: std::env::var("ON_PREM_ADMIN_EMAIL").ok(),
            on_prem_admin_password: std::env::var("ON_PREM_ADMIN_PASSWORD").ok(),
            platform_admin_emails: csv_env("PLATFORM_ADMIN_EMAILS"),
            magic_link_ttl_secs: 900,
            session_ttl_secs: 604_800,
            bootstrap_ttl_secs: 3600,
            client_cert_lifetime_days: 90,
            cookie_secure: bool_env("COOKIE_SECURE", false),
            daily_email_budget: std::env::var("DAILY_EMAIL_BUDGET")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(5000),
            smtp,
            turnstile_secret: std::env::var("TURNSTILE_SECRET").ok(),
            master_key,
            bootstrap_jwt_secret,
            acme,
        })
    }
}

/// Build the URL agents dial for `/agent/v1/*`.
///
/// The hostname always comes from `base_url` — that is the name agents can resolve and the
/// name the pinned mTLS server certificate must cover (see `MTLS_HOST`). Only the port
/// varies: the dedicated mTLS port when one is bound, otherwise the shared HTTPS port.
/// `:443` is left implicit so the URL matches what an operator would type.
fn derive_agent_mtls_url(base_url: &str, listen_https: &str, listen_mtls: &str) -> String {
    let host = base_url
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap_or("localhost")
        .split(':')
        .next()
        .unwrap_or("localhost");

    let port_of = |addr: &str, fallback: u16| -> u16 {
        addr.rsplit(':')
            .next()
            .and_then(|p| p.parse().ok())
            .unwrap_or(fallback)
    };

    let port = if listen_mtls.is_empty() {
        port_of(listen_https, 443)
    } else {
        port_of(listen_mtls, 9443)
    };

    if port == 443 {
        format!("https://{host}")
    } else {
        format!("https://{host}:{port}")
    }
}

impl Config {
    /// Whether this address is listed in `PLATFORM_ADMIN_EMAILS`. Such a user can still have
    /// the flag revoked in the console, but the next restart grants it back — the env var is
    /// the way in when nobody has the flag, so it has to keep working.
    pub fn is_bootstrap_platform_admin(&self, email: &str) -> bool {
        let email = email.trim().to_lowercase();
        self.platform_admin_emails.contains(&email)
    }
}

/// A comma-separated env var as a list of lowercased, trimmed, non-empty entries.
fn csv_env(key: &str) -> Vec<String> {
    std::env::var(key)
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

fn bool_env(key: &str, default: bool) -> bool {
    std::env::var(key)
        .ok()
        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::derive_agent_mtls_url;

    #[test]
    fn muxed_deployment_drops_the_implicit_443() {
        assert_eq!(
            derive_agent_mtls_url("https://app.example.com", "0.0.0.0:443", ""),
            "https://app.example.com"
        );
    }

    #[test]
    fn dedicated_port_is_kept() {
        assert_eq!(
            derive_agent_mtls_url("https://app.example.com", "0.0.0.0:443", "0.0.0.0:9443"),
            "https://app.example.com:9443"
        );
    }

    #[test]
    fn base_url_port_never_leaks_into_the_agent_url() {
        // Dev: BASE_URL carries :3000, but agents must dial the mTLS port, not that one.
        assert_eq!(
            derive_agent_mtls_url("http://localhost:3000", "0.0.0.0:443", "0.0.0.0:9443"),
            "https://localhost:9443"
        );
    }

    #[test]
    fn non_standard_https_port_is_explicit() {
        assert_eq!(
            derive_agent_mtls_url("https://app.example.com", "0.0.0.0:8443", ""),
            "https://app.example.com:8443"
        );
    }
}
