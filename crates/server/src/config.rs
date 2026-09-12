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
    /// Silence after which an enrolled host reads `lost` rather than `offline`, from
    /// `HOST_LOST_AFTER_HOURS`. Purely a reporting threshold — nothing is disabled, revoked
    /// or deleted when a host crosses it. Floored per tenant at the offline grace; see
    /// [`fleet_core::host::StatusThresholds`].
    pub host_lost_after_secs: i64,
    pub client_cert_lifetime_days: i64,
    pub cookie_secure: bool,
    pub daily_email_budget: u32,
    pub smtp: Option<SmtpConfig>,
    pub turnstile_secret: Option<String>,
    pub master_key: MasterKey,
    pub bootstrap_jwt_secret: Vec<u8>,
    pub acme: Option<AcmeConfig>,
    /// TLS from certificate files rather than Let's Encrypt. Mutually exclusive with
    /// [`Config::acme`] — see [`StaticTlsConfig`].
    pub tls: Option<StaticTlsConfig>,
}

/// Serve the operator UI over TLS using a certificate on disk instead of ACME.
///
/// ACME needs a publicly resolvable name and outbound reachability, which an on-prem or
/// air-gapped install does not have — so without this the only remaining option was plain
/// HTTP, and the choice was "a public certificate or none". The mux is unchanged: the same
/// port still carries the UI and agent mTLS, because nothing about branch selection depends
/// on where the web certificate came from.
#[derive(Clone, Debug)]
pub struct StaticTlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    /// Names the certificate must cover when this config generates it. Empty when the
    /// operator supplied the files, which are then used exactly as they are.
    pub self_signed_hosts: Vec<String>,
}

impl StaticTlsConfig {
    /// True when the pair is ours to create and re-create, false when an operator handed us
    /// files we must not overwrite.
    pub fn is_self_signed(&self) -> bool {
        !self.self_signed_hosts.is_empty()
    }
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

        let tls = static_tls_from_env(&base_url)?;
        if tls.is_some() && acme.is_some() {
            anyhow::bail!(
                "ACME_DOMAINS and TLS_CERT/TLS_SELF_SIGNED are both set, but the web listener \
                 can only have one certificate source. Use ACME_DOMAINS for a publicly \
                 resolvable name, or the TLS_* variables for an install that Let's Encrypt \
                 cannot reach — not both."
            );
        }

        // With a TLS terminator of our own, agents share the HTTPS port (routed by ALPN —
        // see `crate::mux`), so there is nothing to bind separately and the firewall only
        // needs one port. Setting LISTEN_MTLS explicitly opts back into a dedicated port:
        // useful behind a load balancer that can't pass ALPN through, or while migrating a
        // live fleet. Without TLS there is no listener to mux onto, so agents need their own
        // port and get 9443.
        let terminates_tls = acme.is_some() || tls.is_some();
        let listen_mtls = match (std::env::var("LISTEN_MTLS").ok(), terminates_tls) {
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
            host_lost_after_secs: host_lost_after_secs(),
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
            tls,
        })
    }
}

/// Read `TLS_CERT` / `TLS_KEY` / `TLS_SELF_SIGNED` into a [`StaticTlsConfig`].
///
/// The two ways in are kept apart on purpose. Supplying `TLS_CERT`+`TLS_KEY` means "use
/// these files"; they are never written to, and a missing one is a startup error rather
/// than an invitation to generate something over the top of a path the operator named —
/// a typo there would otherwise look like a working server presenting a certificate
/// nobody trusts. `TLS_SELF_SIGNED=true` is the opposite request, so it owns its own
/// paths under `TLS_STATE_DIR` and may create and re-create them.
fn static_tls_from_env(base_url: &str) -> anyhow::Result<Option<StaticTlsConfig>> {
    let cert = std::env::var("TLS_CERT").ok().filter(|s| !s.is_empty());
    let key = std::env::var("TLS_KEY").ok().filter(|s| !s.is_empty());
    let self_signed = bool_env("TLS_SELF_SIGNED", false);

    match (cert, key, self_signed) {
        (Some(_), Some(_), true) | (Some(_), None, true) | (None, Some(_), true) => {
            anyhow::bail!(
                "TLS_SELF_SIGNED cannot be combined with TLS_CERT/TLS_KEY: either we generate \
                 the certificate or you supply it. Drop TLS_SELF_SIGNED to use your files."
            )
        }
        (Some(cert), Some(key), false) => Ok(Some(StaticTlsConfig {
            cert_path: cert.into(),
            key_path: key.into(),
            self_signed_hosts: Vec::new(),
        })),
        (Some(_), None, false) | (None, Some(_), false) => anyhow::bail!(
            "TLS_CERT and TLS_KEY must be set together — one without the other leaves the web \
             listener with no usable certificate."
        ),
        (None, None, true) => {
            let dir: PathBuf = std::env::var("TLS_STATE_DIR")
                .unwrap_or_else(|_| "data".into())
                .into();
            Ok(Some(StaticTlsConfig {
                cert_path: dir.join("web-server.crt"),
                key_path: dir.join("web-server.key"),
                self_signed_hosts: self_signed_hosts(base_url),
            }))
        }
        (None, None, false) => Ok(None),
    }
}

/// Names a generated web certificate covers.
///
/// `TLS_HOSTS` when set, otherwise the host from `BASE_URL` plus loopback. Loopback is
/// included by default because the first thing anyone does with a fresh install is open it
/// from the machine it runs on — and a certificate that only names `fleet.internal` turns
/// that into a second warning to click through, on top of the untrusted-issuer one it
/// already has.
fn self_signed_hosts(base_url: &str) -> Vec<String> {
    let configured: Vec<String> = std::env::var("TLS_HOSTS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if !configured.is_empty() {
        return configured;
    }

    let host = host_of(base_url);
    let mut hosts = vec![host.clone()];
    for extra in ["localhost", "127.0.0.1", "::1"] {
        if extra != host {
            hosts.push(extra.to_string());
        }
    }
    hosts
}

/// The hostname part of a URL, without scheme, port or path.
pub fn host_of(url: &str) -> String {
    let rest = url
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let host = rest.split('/').next().unwrap_or(rest);
    // An IPv6 literal is bracketed in a URL (`https://[::1]:443`); strip the brackets and
    // keep the address, rather than splitting it to pieces on its own colons.
    if let Some(inner) = host.strip_prefix('[') {
        return inner.split(']').next().unwrap_or(inner).to_string();
    }
    host.split(':').next().unwrap_or(host).to_string()
}

/// Build the URL agents dial for `/agent/v1/*`.
///
/// The hostname always comes from `base_url` — that is the name agents can resolve and the
/// name the pinned mTLS server certificate must cover (see `MTLS_HOST`). The port depends
/// on which listener agents land on:
///
/// - A dedicated mTLS listener: its bind port. `base_url` may point at a plain-HTTP dev
///   port that agents must never dial.
/// - The shared TLS listener: `base_url`'s port. Agents and browsers then hit the *same*
///   listener, and `base_url` is by definition its reachable address — the bind port is
///   only right when nothing rewrites ports in between, and a container's `-p 9443:8443`
///   or a NAT rule routinely does. `MTLS_URL` remains the override for setups where even
///   `base_url` is not what agents can reach.
///
/// `:443` is left implicit so the URL matches what an operator would type.
fn derive_agent_mtls_url(base_url: &str, listen_https: &str, listen_mtls: &str) -> String {
    let host = host_of(base_url);

    let port_of = |addr: &str, fallback: u16| -> u16 {
        addr.rsplit(':')
            .next()
            .and_then(|p| p.parse().ok())
            .unwrap_or(fallback)
    };

    let port = if !listen_mtls.is_empty() {
        port_of(listen_mtls, 9443)
    } else if base_url.starts_with("https://") {
        port_of_url(base_url).unwrap_or(443)
    } else {
        // A plain-HTTP base_url with a shared TLS listener is a misconfiguration (browsers
        // would be sent somewhere agents are not), but the bind port is the best guess.
        port_of(listen_https, 443)
    };

    if port == 443 {
        format!("https://{host}")
    } else {
        format!("https://{host}:{port}")
    }
}

/// The explicit port in a URL's authority, if any. Understands bracketed IPv6 literals.
fn port_of_url(url: &str) -> Option<u16> {
    let authority = url
        .split("//")
        .nth(1)
        .unwrap_or(url)
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("");
    let after_host = if let Some(rest) = authority.strip_prefix('[') {
        rest.split(']').nth(1).unwrap_or("")
    } else {
        authority
    };
    after_host
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse().ok())
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

/// `HOST_LOST_AFTER_HOURS` in seconds, or the default.
///
/// In hours because that is the unit the decision is made in — "a day", "a long weekend" —
/// and nobody should have to multiply. A value that is missing, unparseable or non-positive
/// falls back to the default with a warning rather than failing startup: this only decides
/// which chip an operator sees, and refusing to boot over it would be out of proportion.
/// Zero in particular is rejected because it would report the entire fleet lost.
fn host_lost_after_secs() -> i64 {
    parse_lost_after_hours(std::env::var("HOST_LOST_AFTER_HOURS").ok().as_deref())
}

/// Split from the env lookup so it can be tested without mutating process environment,
/// which is shared by every test in the binary.
fn parse_lost_after_hours(raw: Option<&str>) -> i64 {
    let Some(raw) = raw else {
        return fleet_core::host::DEFAULT_LOST_AFTER_SECS;
    };
    match raw.trim().parse::<i64>() {
        // Capped so the multiplication cannot overflow on a nonsense value; a century of
        // silence and two days are the same answer in practice.
        Ok(hours) if hours > 0 => hours.min(24 * 365 * 100) * 3_600,
        _ => {
            tracing::warn!(
                value = %raw,
                default_hours = fleet_core::host::DEFAULT_LOST_AFTER_SECS / 3_600,
                "HOST_LOST_AFTER_HOURS must be a positive whole number of hours; using the default"
            );
            fleet_core::host::DEFAULT_LOST_AFTER_SECS
        }
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
    use super::{derive_agent_mtls_url, host_of, parse_lost_after_hours, port_of_url};
    use fleet_core::host::DEFAULT_LOST_AFTER_SECS;

    #[test]
    fn host_of_drops_scheme_port_and_path() {
        assert_eq!(host_of("https://app.example.com"), "app.example.com");
        assert_eq!(host_of("http://localhost:3000"), "localhost");
        assert_eq!(
            host_of("https://app.example.com:8443/x/y"),
            "app.example.com"
        );
        assert_eq!(host_of("https://10.0.0.7:443"), "10.0.0.7");
    }

    /// An IPv6 literal is bracketed in a URL, and splitting it on ':' the way a host:port
    /// pair is split would truncate it to "[" — a SAN that matches nothing.
    #[test]
    fn host_of_keeps_an_ipv6_literal_whole() {
        assert_eq!(host_of("https://[::1]:8443"), "::1");
        assert_eq!(host_of("https://[2001:db8::1]"), "2001:db8::1");
    }

    #[test]
    fn lost_after_hours_defaults_to_two_days() {
        assert_eq!(DEFAULT_LOST_AFTER_SECS, 172_800);
        assert_eq!(parse_lost_after_hours(None), DEFAULT_LOST_AFTER_SECS);
    }

    #[test]
    fn lost_after_hours_is_read_in_hours() {
        assert_eq!(parse_lost_after_hours(Some("48")), 172_800);
        assert_eq!(parse_lost_after_hours(Some("4")), 14_400);
        assert_eq!(parse_lost_after_hours(Some(" 12 ")), 43_200);
    }

    /// A bad value falls back rather than failing startup — this decides which chip an
    /// operator sees, and refusing to boot over it would be out of proportion. Zero matters
    /// most: taken literally it would report the entire fleet lost.
    #[test]
    fn a_nonsense_lost_after_hours_falls_back() {
        for bad in ["0", "-1", "", "soon", "1.5", "48h"] {
            assert_eq!(
                parse_lost_after_hours(Some(bad)),
                DEFAULT_LOST_AFTER_SECS,
                "{bad:?} must not be taken literally"
            );
        }
        // Absurd but positive: clamped rather than overflowed into something negative.
        assert!(parse_lost_after_hours(Some("999999999999")) > 0);
    }

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
    fn dedicated_port_ignores_the_base_url_port() {
        // Dev: BASE_URL carries :3000, but agents must dial the mTLS port, not that one.
        assert_eq!(
            derive_agent_mtls_url("http://localhost:3000", "0.0.0.0:443", "0.0.0.0:9443"),
            "https://localhost:9443"
        );
    }

    #[test]
    fn non_standard_https_port_is_explicit() {
        assert_eq!(
            derive_agent_mtls_url("https://app.example.com:9443", "0.0.0.0:9443", ""),
            "https://app.example.com:9443"
        );
    }

    #[test]
    fn shared_listener_uses_the_published_port_not_the_bind_port() {
        // Container: bound on 8443 inside, published as 9443 outside, BASE_URL says so.
        assert_eq!(
            derive_agent_mtls_url("https://fleet.example.internal:9443", "0.0.0.0:8443", ""),
            "https://fleet.example.internal:9443"
        );
        // `-p 443:9443`: BASE_URL carries no port, so neither does the agent URL.
        assert_eq!(
            derive_agent_mtls_url("https://fleet.example.com", "0.0.0.0:9443", ""),
            "https://fleet.example.com"
        );
    }

    #[test]
    fn shared_listener_with_http_base_url_falls_back_to_the_bind_port() {
        assert_eq!(
            derive_agent_mtls_url("http://localhost:3000", "0.0.0.0:8443", ""),
            "https://localhost:8443"
        );
    }

    #[test]
    fn port_of_url_reads_the_authority_only() {
        assert_eq!(
            port_of_url("https://app.example.com:9443/x?y=1:2"),
            Some(9443)
        );
        assert_eq!(port_of_url("https://app.example.com/a:b"), None);
        assert_eq!(port_of_url("https://[::1]:8443"), Some(8443));
        assert_eq!(port_of_url("https://[::1]"), None);
        assert_eq!(port_of_url("https://10.0.0.5:9443"), Some(9443));
    }
}
