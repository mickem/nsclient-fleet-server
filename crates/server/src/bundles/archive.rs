use anyhow::Result;

use super::valid_bundle_token;

/// The bundle.toml the compose paths (server here, browser in web/src/bundles/bundlezip.ts) write.
/// All values are token-validated before this is called, so the quoting cannot be broken.
pub(super) fn manifest_toml(name: &str, version: &str, template: Option<&str>) -> String {
    let mut m = format!("name = \"{name}\"\nversion = \"{version}\"\nschema_version = 1\n");
    if let Some(t) = template {
        m.push_str(&format!("template = \"{t}\"\n"));
    }
    m
}

/// Pull the `template = "<token>"` line back out of a stored bundle's manifest. The
/// manifest is machine-written, so a line parse suffices; token validation keeps anything
/// odd from a hand-built zip out of the API.
pub(super) fn template_from_manifest(bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?;
    text.lines().find_map(|line| {
        let rest = line.trim().strip_prefix("template")?.trim_start();
        let value = rest.strip_prefix('=')?.trim();
        let value = value.strip_prefix('"')?.strip_suffix('"')?;
        valid_bundle_token(value).then(|| value.to_string())
    })
}

pub(super) fn build_zip(
    manifest_toml: &str,
    config_json: &str,
    carried: &[(String, Vec<u8>)],
) -> Result<Vec<u8>> {
    use std::io::Write;
    let mut cursor = std::io::Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut cursor);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        writer.start_file("bundle.toml", opts)?;
        writer.write_all(manifest_toml.as_bytes())?;
        writer.start_file("config.json", opts)?;
        writer.write_all(config_json.as_bytes())?;
        for (name, data) in carried {
            writer.start_file(name, opts)?;
            writer.write_all(data)?;
        }
        writer.finish()?;
    }
    Ok(cursor.into_inner())
}

/// Most a bundle may expand to across all its entries.
///
/// Bundles carry configuration, scripts and small assets; the largest tier allows a 250 MB
/// upload, and nothing legitimate inflates far past that. The cap is on the *total*, so a
/// thousand small entries cannot add up to the same attack a single large one would.
const MAX_INFLATED_TOTAL: u64 = 512 * 1024 * 1024;

/// Most entries we will walk. A zip can declare millions of them in a few kilobytes.
const MAX_ZIP_ENTRIES: usize = 10_000;

/// Read a bundle zip into memory, refusing anything that would cost more than it should.
///
/// Three separate limits, because a zip's header is written by whoever made the file and
/// none of it is evidence of anything:
///
/// - the output buffer is never pre-sized from the declared size. `Vec::with_capacity` on
///   an attacker-chosen `u64` is an allocation failure, and an allocation failure aborts
///   the process — so a crafted header was a remote kill, reachable through the config-read
///   endpoint by any tenant session.
/// - inflation is read through `take`, against a budget shared by every entry, so the
///   compression ratio cannot turn a 2 MiB upload into gigabytes of resident memory.
/// - entry names must stay inside the archive. The server never extracts, so traversal is
///   an agent-side risk rather than ours, but propagating `../../etc/…` from a hand-crafted
///   upload into a composed bundle we sign makes it our problem.
///
/// Upload does not parse, so a crafted file is stored first and opened later by whoever
/// reads the config — which is why this is a refusal and not a panic.
pub(super) fn read_zip_entries(bytes: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    read_zip_entries_within(bytes, MAX_INFLATED_TOTAL)
}

/// As [`read_zip_entries`], with the budget spelled out so tests can exercise the refusal
/// without actually inflating half a gigabyte.
fn read_zip_entries_within(bytes: &[u8], mut budget: u64) -> Result<Vec<(String, Vec<u8>)>> {
    use std::io::Read;
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))?;
    if archive.len() > MAX_ZIP_ENTRIES {
        anyhow::bail!(
            "bundle declares {} entries (limit {MAX_ZIP_ENTRIES})",
            archive.len()
        );
    }

    let mut out = Vec::with_capacity(archive.len().min(1024));
    for i in 0..archive.len() {
        let file = archive.by_index(i)?;
        if file.is_dir() {
            continue;
        }

        // `enclosed_name` is the library's own answer to "is this name safe to join onto a
        // directory": it rejects parent components that climb out. Since zip 9 it no longer
        // rejects a leading root or drive prefix — it drops it, so `/etc/shadow` comes back
        // as `etc/shadow`. That is contained, but it is still a hand-crafted name we would
        // be rewriting into a bundle we sign, so absolute names are refused here first.
        let raw = String::from_utf8_lossy(file.name_raw());
        let absolute = raw.starts_with(['/', '\\'])
            || matches!(raw.as_bytes(), [d, b':', ..] if d.is_ascii_alphabetic());
        let safe = if absolute { None } else { file.enclosed_name() };
        let Some(safe) = safe else {
            anyhow::bail!("bundle entry {raw:?} escapes the archive");
        };
        let name = safe
            .components()
            .map(|c| c.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");
        if name.is_empty() {
            continue;
        }

        // Read against the shared budget, one byte past it so overrun is detectable rather
        // than a silent truncation that we would then sign.
        let mut data = Vec::new();
        let read = file.take(budget + 1).read_to_end(&mut data)? as u64;
        if read > budget {
            anyhow::bail!("bundle expands past {} MiB", budget / (1024 * 1024));
        }
        budget -= read;
        out.push((name, data));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn zip_of(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut cursor = std::io::Cursor::new(Vec::new());
        {
            let mut w = zip::ZipWriter::new(&mut cursor);
            let opts = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            for (name, data) in entries {
                w.start_file(*name, opts).unwrap();
                w.write_all(data).unwrap();
            }
            w.finish().unwrap();
        }
        cursor.into_inner()
    }

    #[test]
    fn inflation_is_capped_across_all_entries_together() {
        // Four megabytes of zeros deflate to a few kilobytes. A per-entry cap would let a
        // thousand of these add up to the same attack, so the budget is shared.
        let blob = zip_of(&[
            ("a.bin", vec![0u8; 4 * 1024 * 1024]),
            ("b.bin", vec![0u8; 4 * 1024 * 1024]),
        ]);
        assert!(blob.len() < 64 * 1024, "the crafted input is small");

        // Either entry fits on its own; together they do not.
        read_zip_entries_within(&blob, 6 * 1024 * 1024)
            .expect_err("two 4 MiB entries must not pass a 6 MiB budget");
        let ok = read_zip_entries_within(&blob, 16 * 1024 * 1024).expect("within budget");
        assert_eq!(ok.len(), 2);
    }

    #[test]
    fn a_declared_size_never_becomes_an_allocation() {
        // The output buffer used to be pre-sized from the zip header. A crafted entry
        // declaring a terabyte was therefore an allocation failure, and an allocation
        // failure aborts the process — a remote kill through the config-read endpoint.
        // We cannot assert "did not abort" directly, so assert the behaviour that replaced
        // it: the refusal is by bytes actually read, and it is an error, not a panic.
        let blob = zip_of(&[("pad.bin", vec![7u8; 1024 * 1024])]);
        let err = read_zip_entries_within(&blob, 1024).unwrap_err();
        assert!(
            err.to_string().contains("expands past"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn entries_that_escape_the_archive_are_refused() {
        for name in [
            "../../etc/cron.d/pwn",
            "/etc/shadow",
            "a/../../b",
            "\\Windows\\System32\\evil.dll",
            "C:\\Windows\\evil.dll",
            "C:/Windows/evil.dll",
            "\\\\server\\share\\evil",
        ] {
            let blob = zip_of(&[(name, b"x".to_vec())]);
            let err = read_zip_entries_within(&blob, 1024 * 1024)
                .unwrap_err_or_ok_names()
                .unwrap_or_else(|| panic!("{name} should be refused"));
            assert!(err.contains("escapes the archive"), "{name}: {err}");
        }
    }

    /// Small helper so the loop above reads as "this must be refused" rather than as
    /// unwrapping in two directions.
    trait RefusalExt {
        fn unwrap_err_or_ok_names(self) -> Option<String>;
    }
    impl RefusalExt for Result<Vec<(String, Vec<u8>)>> {
        fn unwrap_err_or_ok_names(self) -> Option<String> {
            match self {
                Ok(_) => None,
                Err(e) => Some(e.to_string()),
            }
        }
    }

    #[test]
    fn ordinary_entries_survive_normalisation() {
        let blob = zip_of(&[
            ("config.json", b"{}".to_vec()),
            ("scripts/check_disk.ps1", b"Write-Output 'ok'".to_vec()),
        ]);
        let entries = read_zip_entries_within(&blob, 1024 * 1024).unwrap();
        let names: Vec<&str> = entries.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["config.json", "scripts/check_disk.ps1"]);
    }
}
