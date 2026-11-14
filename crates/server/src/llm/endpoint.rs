//! Where a model call is allowed to go.
//!
//! A tenant's `base_url` is a URL this server will POST to on that tenant's say-so, and the
//! provider's answer — or the first few hundred characters of its refusal — goes back to
//! whoever asked. On an install shared by several tenants that is a request forged from
//! inside our network: the cloud metadata address, another service's admin port on loopback,
//! anything else that trusts a caller for being local.
//!
//! So an endpoint a *tenant* configured has to be on the public internet, unless the operator
//! of the server has said otherwise. Two things say otherwise:
//!
//! * `ON_PREM=1`: one organisation runs the server and is its only tenant, and a model on
//!   their own network is exactly what they want to reach.
//! * `LLM_ALLOW_PRIVATE_ENDPOINTS=1`, for a shared install whose tenants are trusted with the
//!   network it sits on.
//!
//! The server-wide default from `LLM_*` is never restricted: whoever set the environment
//! already has a shell on the machine.
//!
//! The check is made where it cannot be talked round:
//!
//! * A literal address is checked before the request ([`check`]), because nothing resolves
//!   it. The URL parser has already folded the spellings people use to hide one
//!   (`http://2130706433/`, `http://0x7f.1/`) into the address they mean.
//! * A name is checked *as it is resolved*, by the client's own resolver ([`client`]) —
//!   not looked up once here and again by the client, which is the gap a DNS answer that
//!   changes between the two walks through.
//! * No client follows redirects. A model API has no reason to send one, and a redirect is
//!   the other way a public endpoint hands a request to a private address — carrying the
//!   tenant's API key with it.
//! * The restricted client ignores `HTTP(S)_PROXY`. Through a proxy it is the proxy that
//!   resolves the name, and the check above would be made against the proxy's address
//!   instead of the endpoint's.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};

static ALLOW_PRIVATE: AtomicBool = AtomicBool::new(false);

/// Record the operator's `LLM_ALLOW_PRIVATE_ENDPOINTS`. Called once at startup.
pub fn set_private_endpoints_allowed(allowed: bool) {
    ALLOW_PRIVATE.store(allowed, Ordering::Relaxed);
}

/// Whether the operator has allowed tenant-configured endpoints on private addresses.
/// `ON_PREM` allows it too; the caller has the config that says so.
pub fn private_endpoints_allowed() -> bool {
    ALLOW_PRIVATE.load(Ordering::Relaxed)
}

/// True for an address on the public internet: not loopback, not a private or link-local
/// range, not one of the reserved blocks that route nowhere or somewhere special.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local() // 169.254/16, the cloud metadata address among them
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        || o[0] == 0 // "this network"
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64/10, carrier-grade NAT
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0/24, protocol assignments
        || (o[0] == 198 && (o[1] & 0xfe) == 18) // 198.18/15, benchmarking
        || o[0] >= 240) // reserved
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    // An IPv4 address wearing IPv6 is judged as the IPv4 address it reaches.
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_public_v4(v4);
    }
    let s = ip.segments();
    // 64:ff9b::/96, NAT64: the last 32 bits are the IPv4 destination.
    if s[0] == 0x64 && s[1] == 0xff9b && s[2..6].iter().all(|x| *x == 0) {
        let [a, b] = s[6].to_be_bytes();
        let [c, d] = s[7].to_be_bytes();
        return is_public_v4(Ipv4Addr::new(a, b, c, d));
    }
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (s[0] & 0xfe00) == 0xfc00 // fc00::/7, unique local
        || (s[0] & 0xffc0) == 0xfe80 // fe80::/10, link-local
        || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
        || s[..6].iter().all(|x| *x == 0)) // ::/96, IPv4-compatible and friends
}

/// Check an endpoint URL before anything is sent to it.
///
/// Always: it must parse, be `http` or `https`, name a host and carry no credentials of its
/// own. With `public_only`, a literal address must also be a public one. A *name* passes
/// here whatever it resolves to — that is checked when it is resolved, by [`client`].
pub fn check(base_url: &str, public_only: bool) -> Result<(), String> {
    let url = url::Url::parse(base_url.trim())
        .map_err(|_| "base_url must be an http or https URL".to_string())?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err("base_url must be an http or https URL".into());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("base_url must not carry a username or password".into());
    }
    let ip = match url.host() {
        None => return Err("base_url must name a host".into()),
        Some(url::Host::Domain(_)) => return Ok(()),
        Some(url::Host::Ipv4(v4)) => IpAddr::V4(v4),
        Some(url::Host::Ipv6(v6)) => IpAddr::V6(v6),
    };
    if public_only && !is_public(ip) {
        return Err(private_refusal(&ip.to_string()));
    }
    Ok(())
}

fn private_refusal(what: &str) -> String {
    format!(
        "the model endpoint {what} is not on the public internet, and this server only \
         allows tenants to configure public endpoints (its operator can allow private ones \
         with LLM_ALLOW_PRIVATE_ENDPOINTS)"
    )
}

/// Resolves names with the system resolver and keeps only public addresses.
struct PublicOnly;

impl Resolve for PublicOnly {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let host = name.as_str().to_string();
            let found: Vec<SocketAddr> =
                tokio::net::lookup_host((host.as_str(), 0)).await?.collect();
            let public: Vec<SocketAddr> = found.into_iter().filter(|a| is_public(a.ip())).collect();
            if public.is_empty() {
                // One refusal whether the name has no addresses or only private ones: the
                // difference would tell a caller which internal names exist.
                return Err(private_refusal(&host).into());
            }
            Ok(Box::new(public.into_iter()) as Addrs)
        })
    }
}

fn build(public_only: bool) -> Option<reqwest::Client> {
    let mut b = reqwest::Client::builder()
        .timeout(super::CALL_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none());
    if public_only {
        b = b.no_proxy().dns_resolver(PublicOnly);
    }
    b.build()
        .map_err(|e| tracing::error!(error = %e, "could not build the HTTP client"))
        .ok()
}

/// The client for a model call: one per kind for the life of the process, since connection
/// reuse matters against a provider on the other side of a TLS handshake.
///
/// With `public_only` it will not connect to a name that resolves to a private address.
/// Literal addresses never reach a resolver, so [`check`] has to have passed first.
pub fn client(public_only: bool) -> Option<&'static reqwest::Client> {
    static RESTRICTED: OnceLock<Option<reqwest::Client>> = OnceLock::new();
    static OPEN: OnceLock<Option<reqwest::Client>> = OnceLock::new();
    let slot = if public_only { &RESTRICTED } else { &OPEN };
    slot.get_or_init(|| build(public_only)).as_ref()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn addresses_inside_a_network_are_not_public() {
        for private in [
            "127.0.0.1",
            "127.8.9.10",
            "10.0.0.5",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254", // cloud metadata
            "100.64.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "::1",
            "::",
            "fe80::1",
            "fd00::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "64:ff9b::7f00:1",
        ] {
            assert!(!is_public(ip(private)), "{private} was taken for public");
        }
        for public in [
            "1.1.1.1",
            "160.79.104.10",
            "2606:4700::1111",
            "64:ff9b::101:101",
        ] {
            assert!(is_public(ip(public)), "{public} was refused");
        }
    }

    #[test]
    fn a_literal_private_address_is_refused_however_it_is_spelled() {
        for url in [
            "http://127.0.0.1:11434",
            "http://169.254.169.254/latest/meta-data",
            "http://[::1]:8080/v1",
            "http://[::ffff:10.0.0.5]/v1",
            // The spellings that get past a string comparison.
            "http://2130706433/",
            "http://0x7f.1/",
            "http://017700000001/",
        ] {
            assert!(check(url, true).is_err(), "{url} was accepted");
            assert!(
                check(url, false).is_ok(),
                "{url} must stay usable where the operator allows private endpoints"
            );
        }
    }

    #[test]
    fn a_name_or_a_public_address_passes_the_literal_check() {
        // A name is judged when it resolves, not here.
        assert!(check("https://api.openai.com/v1", true).is_ok());
        assert!(check("https://gateway.internal/v1", true).is_ok());
        assert!(check("https://1.1.1.1/v1", true).is_ok());
    }

    #[test]
    fn a_url_that_is_not_an_http_endpoint_is_refused_either_way() {
        for url in [
            "not a url",
            "file:///etc/passwd",
            "ftp://example.com",
            "https://user:pw@example.com/v1",
        ] {
            assert!(check(url, false).is_err(), "{url} was accepted");
        }
    }

    #[tokio::test]
    async fn a_name_that_resolves_to_loopback_is_not_connected_to() {
        // `localhost` is the name every machine has for a private address.
        let name: Name = "localhost".parse().unwrap();
        let err = match PublicOnly.resolve(name).await {
            Ok(_) => panic!("localhost resolved to something we would connect to"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("not on the public internet"), "{err}");
    }
}
