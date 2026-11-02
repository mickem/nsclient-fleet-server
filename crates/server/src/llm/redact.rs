//! Stripping the obvious credentials out of alert evidence before it is sent to a model.
//!
//! # What this is, and what it is not
//!
//! Alert context is collected by running commands on a monitored host and keeping what they
//! printed. Some of those commands print credentials: a process table shows command lines,
//! and command lines carry `--password` and connection strings; a configuration check
//! prints an INI file; a failing service logs the token it tried to use. None of that is
//! the point of the alert, and all of it would otherwise be posted to a third party.
//!
//! This is a coarse net over the shapes that recur, and it is **not** a guarantee. A secret
//! that does not look like one gets through, and pretending otherwise would be worse than
//! not doing it — so the defence that actually carries the weight is consent: enrichment is
//! off until a tenant turns it on, and [`super::ProviderKind::Ollama`] exists so that
//! "never send this anywhere" is a configuration and not a refusal to use the feature.
//! This layer is what stops the most common accident on top of that.
//!
//! Written by hand rather than with a regex crate: the patterns are `key`-then-`value` with
//! a handful of separators, the input is bounded, and this crate has no regex dependency
//! to spend on it.

/// What replaces a redacted value. Deliberately conspicuous: a reader of the description
/// should be able to tell that something was withheld rather than that the host had an
/// empty password.
const MASK: &str = "«redacted»";

/// Key fragments that make whatever follows a secret. Matched case-insensitively, as a
/// substring of the key, so `pgpassword`, `--api-key` and `AWS_SECRET_ACCESS_KEY` all hit.
const SECRET_KEYS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "api-key",
    "credential",
    "private_key",
    "privatekey",
    "access_key",
    "accesskey",
    "auth",
    "bearer",
    "session_id",
    "sessionid",
    "connectionstring",
    "connection_string",
];

/// Separators between a key and its value, longest first so `":"` is tried before `":"`
/// inside a longer form.
const SEPARATORS: &[char] = &['=', ':'];

/// Redact secret-looking `key=value` and `key: value` pairs, and whole PEM private-key
/// blocks, anywhere in `input`.
pub fn redact(input: &str) -> String {
    let with_pem = redact_pem_blocks(input);
    redact_key_values(&with_pem)
}

/// Replace the body of any `-----BEGIN ... PRIVATE KEY-----` block.
///
/// Handled separately from the key/value pass because a PEM body is base64 across many
/// lines with no key in front of it — the shape the key/value scanner cannot see.
fn redact_pem_blocks(input: &str) -> String {
    const BEGIN: &str = "-----BEGIN";
    const END: &str = "-----END";
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    loop {
        let Some(begin) = rest.find(BEGIN) else {
            out.push_str(rest);
            return out;
        };
        // Only private material: a certificate is public and is often the useful evidence
        // in an expiry alert.
        let header_end = rest[begin..]
            .find('\n')
            .map(|i| begin + i)
            .unwrap_or(rest.len());
        let header = &rest[begin..header_end];
        if !header.to_ascii_uppercase().contains("PRIVATE KEY") {
            out.push_str(&rest[..header_end]);
            rest = &rest[header_end..];
            // Nothing left after the header line: emit and stop.
            if rest.is_empty() {
                return out;
            }
            continue;
        }
        out.push_str(&rest[..header_end]);
        out.push('\n');
        out.push_str(MASK);
        match rest[header_end..].find(END) {
            Some(off) => {
                let end_start = header_end + off;
                out.push('\n');
                rest = &rest[end_start..];
            }
            None => {
                // An unterminated block: everything after the header is suspect, so none
                // of it survives.
                return out;
            }
        }
    }
}

fn redact_key_values(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0usize;

    while i < bytes.len() {
        let Some(sep_off) = bytes[i..]
            .iter()
            .position(|b| SEPARATORS.contains(&(*b as char)))
        else {
            out.push_str(&input[i..]);
            break;
        };
        let sep = i + sep_off;

        // The key is the run of key-ish characters immediately before the separator.
        let key_start = input[i..sep]
            .char_indices()
            .rev()
            .take_while(|(_, c)| c.is_alphanumeric() || *c == '_' || *c == '-' || *c == '.')
            .last()
            .map(|(off, _)| i + off)
            .unwrap_or(sep);
        let key = &input[key_start..sep];
        let lower = key.to_ascii_lowercase();

        if !key.is_empty() && SECRET_KEYS.iter().any(|k| lower.contains(k)) {
            let separator = input[sep..].chars().next().expect("separator exists");
            out.push_str(&input[i..sep]);
            out.push(separator);

            let after = sep + 1;
            // A `key: value` pair may have spaces after the colon; they are kept so the
            // line still reads naturally.
            let value_start = after
                + input[after..]
                    .char_indices()
                    .take_while(|(_, c)| *c == ' ' || *c == '\t')
                    .map(|(off, c)| off + c.len_utf8())
                    .last()
                    .unwrap_or(0);
            out.push_str(&input[after..value_start]);

            // How far the value runs depends on which separator introduced it, because the
            // two appear in different kinds of output:
            //
            //   `=` is the dense form — a command line or a query string, where the next
            //       space starts an unrelated argument that is usually worth keeping
            //       (`--password=x --host=db01` must not lose the host).
            //   `:` is the line-oriented form — an HTTP header, a YAML or INI line, a log
            //       field — where the secret is the remainder of the line. Stopping at the
            //       first space here is what let `Authorization: Bearer <token>` through
            //       with only the word `Bearer` masked.
            //
            // A quoted value ends at its closing quote under either separator.
            let quoted =
                input[value_start..].starts_with('"') || input[value_start..].starts_with('\'');
            let value_end = if quoted {
                let q = input[value_start..].chars().next().expect("quote exists");
                value_start
                    + 1
                    + input[value_start + 1..]
                        .find(q)
                        .map(|off| off + 1)
                        .unwrap_or_else(|| input.len() - value_start - 1)
            } else if separator == ':' {
                value_start
                    + input[value_start..]
                        .find('\n')
                        .unwrap_or(input.len() - value_start)
            } else {
                value_start
                    + input[value_start..]
                        .find(|c: char| c.is_whitespace() || c == ',' || c == ';' || c == '&')
                        .unwrap_or(input.len() - value_start)
            };

            if value_end > value_start {
                out.push_str(MASK);
                i = value_end;
                continue;
            }
            // An empty value: nothing to hide, carry on after the separator.
            i = after;
            continue;
        }

        out.push_str(&input[i..=sep]);
        i = sep + 1;
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_password_on_a_command_line_does_not_reach_the_model() {
        let got = redact("sqlcmd -S db01 -U sa -P Hunter2! -Q \"SELECT 1\"");
        assert!(got.contains("sqlcmd -S db01"), "{got}");

        // The common shapes, all of which appear in a real process table.
        for input in [
            "mysql --password=s3cr3t --host=db",
            "PGPASSWORD=letmein psql",
            "connect --api-key=sk-abcdef123456",
            "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.x.y",
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG",
            "password: \"quoted secret\"",
            "token:abc123",
        ] {
            let got = redact(input);
            assert!(
                got.contains(MASK),
                "nothing redacted in {input:?} → {got:?}"
            );
            for leak in [
                "s3cr3t",
                "letmein",
                "sk-abcdef123456",
                "eyJhbGciOiJIUzI1NiJ9.x.y",
                "wJalrXUtnFEMI/K7MDENG",
                "quoted secret",
                "abc123",
            ] {
                assert!(
                    !got.contains(leak),
                    "{leak} leaked from {input:?} → {got:?}"
                );
            }
        }
    }

    #[test]
    fn the_key_survives_so_the_line_still_reads() {
        let got = redact("mysql --password=s3cr3t --host=db01");
        assert!(got.contains("--password="), "{got}");
        assert!(
            got.contains("--host=db01"),
            "an innocent value next to a secret one must survive: {got}"
        );
    }

    #[test]
    fn a_colon_secret_ends_at_the_line_and_not_at_the_file() {
        // The `:` rule takes the rest of the line, so the next line has to survive it —
        // otherwise a header at the top of a process dump would erase the dump.
        let got = redact("Authorization: Bearer eyJabc.def\nstate=running pid=4211\ndisk 95% full");
        assert!(!got.contains("eyJabc.def"), "{got}");
        assert!(got.contains("state=running pid=4211"), "{got}");
        assert!(got.contains("disk 95% full"), "{got}");
    }

    #[test]
    fn the_evidence_itself_is_left_alone() {
        // These are the lines the alert is actually about; redacting them would make the
        // feature useless in the name of protecting nothing.
        for input in [
            "C:\\ used 95.2% > 90%",
            "state=running pid=4211 cpu=97%",
            "disk: /dev/sda1 99% full",
            "time=12:30:01 level=error msg=connection refused",
            "http://example.com:8080/health returned 503",
        ] {
            assert_eq!(redact(input), input, "over-redacted: {input:?}");
        }
    }

    #[test]
    fn a_private_key_block_is_replaced_wholesale() {
        let pem =
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\nAAAA...\n-----END RSA PRIVATE KEY-----";
        let got = redact(pem);
        assert!(!got.contains("MIIEow"), "{got}");
        assert!(!got.contains("AAAA"), "{got}");
        assert!(got.contains(MASK));
        assert!(got.contains("-----END RSA PRIVATE KEY-----"));
    }

    #[test]
    fn a_certificate_is_not_a_secret() {
        // An expiring certificate is exactly the evidence a cert-expiry alert needs.
        let pem = "-----BEGIN CERTIFICATE-----\nMIIDdzCC...\n-----END CERTIFICATE-----";
        assert_eq!(redact(pem), pem);
    }

    #[test]
    fn an_unterminated_private_key_does_not_leak_its_tail() {
        let got = redact("-----BEGIN PRIVATE KEY-----\nMIIEvQIBADAN...truncated");
        assert!(!got.contains("MIIEvQIBADAN"), "{got}");
    }

    #[test]
    fn multibyte_evidence_survives_intact() {
        // Truncation and slicing bugs here would panic rather than misbehave, so this is
        // worth a case of its own: service names and paths are not ASCII.
        let input = "service=Überwachung state=stopped path=/var/log/größe.log";
        assert_eq!(redact(input), input);
        let got = redact("user=Ünicode password=gehéimnis rest=ok");
        assert!(got.contains("Ünicode"), "{got}");
        assert!(!got.contains("gehéimnis"), "{got}");
        assert!(got.contains("rest=ok"), "{got}");
    }

    #[test]
    fn redaction_is_idempotent() {
        let once = redact("password=abc token=def");
        assert_eq!(redact(&once), once, "a second pass must not eat the mask");
    }

    #[test]
    fn degenerate_input_does_not_panic() {
        for input in [
            "",
            "=",
            ":",
            "password=",
            "password:",
            "::::",
            "a=b=c=d",
            "&&&",
        ] {
            let _ = redact(input);
        }
    }

    #[test]
    fn several_secrets_on_one_line_are_all_caught() {
        let got = redact("cmd --password=one --api-key=two --token=three --port=8080");
        for leak in ["one", "two", "three"] {
            assert!(!got.contains(leak), "{leak} leaked → {got}");
        }
        assert!(got.contains("--port=8080"));
        assert_eq!(got.matches(MASK).count(), 3);
    }
}
