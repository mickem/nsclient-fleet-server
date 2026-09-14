//! Loading configuration from a file of `KEY=VALUE` lines.
//!
//! Every setting arrives through the environment, which on Linux is systemd's job:
//! `EnvironmentFile=/etc/nsclient-fleet/env` in the unit, a file mode 640 that only root and
//! the service account can read. Windows has no equivalent — the service control manager
//! hands a service the *machine-wide* environment, and putting `MASTER_KEY` there would
//! publish it to every process on the box, including every unprivileged one.
//!
//! So `--env-file` reads the same file systemd would, and the Windows service registers
//! itself with that flag in its command line. One format, one file, both platforms; the
//! file's ACL is what protects it, exactly as the file's mode does under systemd.
//!
//! The subset of shell syntax understood here is the subset systemd understands, and for
//! the same reason: the file is read by a program, not sourced by a shell, so `$VAR`
//! expansion, command substitution and line continuations are not supported and a value
//! containing them is taken literally.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};

/// Read `path` and set each variable in it that is not already set in the environment.
///
/// Variables already present win, so a value can be overridden for one run —
/// `MASTER_KEY=… nsclient-fleet --env-file …` — without editing a file the service also
/// reads. Returns the names it set, for logging; values are never logged, since the point
/// of the file is that it holds the ones that must not be.
pub fn load(path: &Path) -> Result<Vec<String>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading env file {}", path.display()))?;
    let parsed = parse(&text).with_context(|| format!("parsing env file {}", path.display()))?;

    let mut applied = Vec::new();
    for (key, value) in parsed {
        if std::env::var_os(&key).is_some() {
            continue;
        }
        // Safety-adjacent, not unsafe: this runs during startup, before any thread that
        // might read the environment concurrently has been spawned.
        std::env::set_var(&key, value);
        applied.push(key);
    }
    Ok(applied)
}

/// Parse `KEY=VALUE` lines into pairs, in file order with later lines winning.
///
/// Blank lines and lines whose first non-space character is `#` are skipped, as is a
/// leading `export `. A value may be wrapped in single or double quotes, which is how a
/// value with leading or trailing spaces is written; quotes are stripped and the contents
/// taken literally.
fn parse(text: &str) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    // Notepad and PowerShell's `Out-File` write a UTF-8 BOM by default, and it is not
    // whitespace — left in place it becomes part of the first line's variable name, and
    // the file reads as though its first setting were missing.
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    for (number, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
        let Some((key, value)) = line.split_once('=') else {
            anyhow::bail!("line {}: expected KEY=VALUE, found {raw:?}", number + 1);
        };
        let key = key.trim();
        if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            anyhow::bail!("line {}: {key:?} is not a usable variable name", number + 1);
        }
        out.insert(key.to_string(), unquote(value.trim()));
    }
    Ok(out)
}

/// Strip one matched pair of surrounding quotes, if there is one.
fn unquote(value: &str) -> String {
    let bytes = value.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if (first == b'"' || first == b'\'') && first == last {
            return value[1..value.len() - 1].to_string();
        }
    }
    value.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(text: &str) -> BTreeMap<String, String> {
        parse(text).expect("parses")
    }

    #[test]
    fn reads_plain_assignments() {
        let env = parsed("MASTER_KEY=abc\nBASE_URL=https://fleet.example.internal:9443\n");
        assert_eq!(env["MASTER_KEY"], "abc");
        assert_eq!(env["BASE_URL"], "https://fleet.example.internal:9443");
    }

    #[test]
    fn skips_comments_and_blank_lines() {
        let env = parsed("# a comment\n\n   \n  # indented\nON_PREM=true\n");
        assert_eq!(env.len(), 1);
        assert_eq!(env["ON_PREM"], "true");
    }

    /// A `#` after a value is part of the value. systemd treats it the same way, and a
    /// base64 master key or a password can contain one — stripping it would silently
    /// truncate a credential, which fails as "bad password" long after the fact.
    #[test]
    fn a_hash_inside_a_value_is_kept() {
        let env = parsed("ON_PREM_ADMIN_PASSWORD=pass#word\n");
        assert_eq!(env["ON_PREM_ADMIN_PASSWORD"], "pass#word");
    }

    #[test]
    fn strips_one_pair_of_quotes() {
        let env = parsed("A=\"spaced value \"\nB='single'\nC=\"unbalanced\nD='mixed\"\n");
        assert_eq!(env["A"], "spaced value ");
        assert_eq!(env["B"], "single");
        assert_eq!(env["C"], "\"unbalanced");
        assert_eq!(env["D"], "'mixed\"");
    }

    #[test]
    fn accepts_an_export_prefix() {
        let env = parsed("export MASTER_KEY=abc\n");
        assert_eq!(env["MASTER_KEY"], "abc");
    }

    /// Base64 keys end in `=` padding, and a URL can carry a query string. Only the first
    /// `=` separates.
    #[test]
    fn splits_on_the_first_equals_only() {
        let env = parsed("MASTER_KEY=c29tZSBrZXkgbWF0ZXJpYWw=\nX=a=b=c\n");
        assert_eq!(env["MASTER_KEY"], "c29tZSBrZXkgbWF0ZXJpYWw=");
        assert_eq!(env["X"], "a=b=c");
    }

    #[test]
    fn later_lines_win() {
        let env = parsed("LISTEN=0.0.0.0:3000\nLISTEN=0.0.0.0:8080\n");
        assert_eq!(env["LISTEN"], "0.0.0.0:8080");
    }

    #[test]
    fn a_line_without_an_equals_is_an_error() {
        let err = parse("MASTER_KEY\n").unwrap_err().to_string();
        assert!(err.contains("line 1"), "{err}");
    }

    #[test]
    fn a_nonsense_name_is_an_error() {
        assert!(parse("not a name=x\n").is_err());
        assert!(parse("=x\n").is_err());
    }

    /// A file written on Windows arrives with CRLF endings; the trailing `\r` must not
    /// become part of the last value on every line.
    #[test]
    fn crlf_line_endings_do_not_leak_into_values() {
        let env = parsed("MASTER_KEY=abc\r\nON_PREM=true\r\n");
        assert_eq!(env["MASTER_KEY"], "abc");
        assert_eq!(env["ON_PREM"], "true");
    }

    /// A UTF-8 BOM is what Notepad and `Out-File` write by default on Windows, and it
    /// would otherwise make the first line's variable name unusable.
    #[test]
    fn a_byte_order_mark_is_ignored() {
        let env = parsed("\u{feff}MASTER_KEY=abc\n");
        assert_eq!(env["MASTER_KEY"], "abc");
    }
}
