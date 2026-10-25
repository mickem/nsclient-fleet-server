// Client-side bundle zip build/read — the browser twin of the server's compose path
// (`build_zip` / `read_zip_entries` in crates/server/src/bundles/archive.rs). Keep the two in sync:
// a bundle is a zip of `bundle.toml` (manifest), `config.json` (merge-patch fragment), the
// scripts/ files the editor edits, and any other entries carried between versions unchanged.
//
// The server path exists so plain bundles need no zip tooling in the browser; this module
// exists for encrypted bundles, whose plaintext the server must never see — so the zip has
// to be (re)built where the plaintext is.

import { strToU8, unzipSync, zipSync } from "fflate";

/** A bundle name, version or template id. Mirrors the server's `valid_bundle_token` — also
 *  what keeps the manifest's quoting and the encryption AAD unambiguous. */
export const TOKEN_RE = /^[A-Za-z0-9._-]{1,128}$/;

/** Zip entries other than the manifest, config and scripts: `[path, bytes]`, carried
 *  between versions unchanged. */
export type CarriedEntries = [string, Uint8Array][];

/** A file under scripts/, which the editor shows and edits. */
export type BundleScript = { path: string; data: Uint8Array };

/** A script path the editor may write. Mirrors the server's `valid_script_path`: scripts/
 *  then up to eight segments of [A-Za-z0-9._-], none of them "." or "..". */
const SCRIPT_PATH_RE = /^scripts(\/[A-Za-z0-9._-]+){1,8}$/;

export function validScriptPath(path: string): boolean {
  return (
    path.length <= 256 &&
    SCRIPT_PATH_RE.test(path) &&
    path.split("/").every((s) => s !== "." && s !== "..")
  );
}

/** Another of `paths` that `path` cannot sit beside on an agent: the same name in another
 *  case (Windows file systems ignore case), or a file where `path` needs a folder or the
 *  other way round. Exact duplicates are not reported. Mirrors `path_clash` in
 *  crates/server/src/bundles/archive.rs. */
export function scriptPathClash(path: string, paths: Iterable<string>): string | undefined {
  const lower = path.toLowerCase();
  for (const other of paths) {
    const o = other.toLowerCase();
    if (other === path) continue;
    if (o === lower || o.startsWith(`${lower}/`) || lower.startsWith(`${o}/`)) return other;
  }
  return undefined;
}

/** The manifest is machine-written (see buildBundleZip / the server's manifest_toml),
 *  so a line match suffices; the token charset keeps hand-built zips from smuggling
 *  anything odd into the UI. */
function templateFromManifest(data: Uint8Array): string | null {
  const m = new TextDecoder()
    .decode(data)
    .match(/^\s*template\s*=\s*"([A-Za-z0-9._-]{1,128})"\s*$/m);
  return m ? m[1] : null;
}

export function readBundleZip(bytes: Uint8Array): {
  configJson: Record<string, unknown>;
  /** Files under scripts/, sorted by path. */
  scripts: BundleScript[];
  /** Template id recorded in bundle.toml, if the bundle was created from one. */
  template: string | null;
  carried: CarriedEntries;
} {
  let files: Record<string, Uint8Array>;
  try {
    files = unzipSync(bytes);
  } catch (e) {
    throw new Error(`bundle is not a readable zip: ${e instanceof Error ? e.message : e}`);
  }
  let configJson: Record<string, unknown> = {};
  const scripts: BundleScript[] = [];
  let template: string | null = null;
  const carried: CarriedEntries = [];
  for (const [rawName, data] of Object.entries(files)) {
    let name = rawName.replace(/\\/g, "/");
    if (name.startsWith("./")) name = name.slice(2);
    if (name.endsWith("/")) continue; // directory entry
    if (name === "config.json") {
      try {
        configJson = JSON.parse(new TextDecoder().decode(data)) as Record<string, unknown>;
      } catch (e) {
        throw new Error(`bundle config.json is invalid JSON: ${e instanceof Error ? e.message : e}`);
      }
    } else if (name === "bundle.toml") {
      // Regenerated on save from the (name, version) being written; only the template
      // association survives the round-trip.
      template = templateFromManifest(data);
    } else if (name.startsWith("scripts/")) {
      scripts.push({ path: name, data });
    } else {
      carried.push([name, data]);
    }
  }
  scripts.sort((a, b) => a.path.localeCompare(b.path));
  return { configJson, scripts, template, carried };
}

export function buildBundleZip(
  name: string,
  version: string,
  configJson: Record<string, unknown>,
  carried: CarriedEntries,
  scripts: BundleScript[],
  template: string | null = null,
): Uint8Array<ArrayBuffer> {
  // Same manifest the server's compose writes (manifest_toml). Name/version/template are
  // validated to the token charset before this is called, so the quoting cannot be broken.
  let manifest = `name = "${name}"\nversion = "${version}"\nschema_version = 1\n`;
  if (template !== null) manifest += `template = "${template}"\n`;
  const files: Record<string, Uint8Array> = {
    "bundle.toml": strToU8(manifest),
    "config.json": strToU8(JSON.stringify(configJson, null, 2)),
  };
  for (const [entryName, data] of carried) files[entryName] = data;
  for (const s of scripts) files[s.path] = s.data;
  // fflate types its output as ArrayBufferLike, but zipSync always allocates a fresh
  // ArrayBuffer — never a SharedArrayBuffer.
  return zipSync(files) as Uint8Array<ArrayBuffer>;
}
