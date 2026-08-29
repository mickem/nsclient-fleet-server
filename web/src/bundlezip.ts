// Client-side bundle zip build/read — the browser twin of the server's compose path
// (`build_zip` / `read_zip_entries` in crates/server/src/bundles.rs). Keep the two in sync:
// a bundle is a zip of `bundle.toml` (manifest), `config.json` (merge-patch fragment), and
// any other entries (scripts, assets) carried between versions unchanged.
//
// The server path exists so plain bundles need no zip tooling in the browser; this module
// exists for encrypted bundles, whose plaintext the server must never see — so the zip has
// to be (re)built where the plaintext is.

import { strToU8, unzipSync, zipSync } from "fflate";

/** Zip entries other than the manifest and config: `[path, bytes]`, e.g. scripts. */
export type CarriedEntries = [string, Uint8Array][];

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
  /** Paths under scripts/ — the read-only listing the editor shows. */
  scripts: string[];
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
  const scripts: string[] = [];
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
    } else {
      carried.push([name, data]);
      if (name.startsWith("scripts/")) scripts.push(name);
    }
  }
  scripts.sort();
  return { configJson, scripts, template, carried };
}

export function buildBundleZip(
  name: string,
  version: string,
  configJson: Record<string, unknown>,
  carried: CarriedEntries,
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
  // fflate types its output as ArrayBufferLike, but zipSync always allocates a fresh
  // ArrayBuffer — never a SharedArrayBuffer.
  return zipSync(files) as Uint8Array<ArrayBuffer>;
}
