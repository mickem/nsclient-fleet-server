// The commands that enroll a new host, built here rather than on the server because one
// ingredient never reaches the server: the bundle encryption key lives in this browser
// (and on agents) only. The server hands back the address and the one-time token; the
// browser adds the key it holds, if any.

export type InstallInputs = {
  serverUrl: string;
  token: string;
  /** The tenant's bundle encryption key, when unlocked in this session. Omitted → the
   *  agent enrolls without it and cannot open encrypted bundles until it is added. */
  bundleKey?: string | null;
};

/** `nscp enroll …` for a host that already has the agent (Windows or Linux). The key is
 *  base64 — `+ / =` — which no shell treats specially outside quotes. */
export function enrollCommand({ serverUrl, token, bundleKey }: InstallInputs): string {
  const parts = ["nscp enroll --server", serverUrl, "--token", token];
  if (bundleKey) parts.push("--bundle-key", bundleKey);
  return parts.join(" ");
}

/** `msiexec …` with the fleet properties, for a Windows host that does not have the agent
 *  yet. The MSI file name is a placeholder: the installer build being rolled out is not
 *  something the server knows. Property values are quoted: the key can end in `=`, which
 *  msiexec would otherwise read as part of the PROPERTY=value split. */
export function msiCommand({ serverUrl, token, bundleKey }: InstallInputs): string {
  const props = [`FLEET_SERVER="${serverUrl}"`, `FLEET_TOKEN="${token}"`];
  if (bundleKey) props.push(`FLEET_BUNDLE_KEY="${bundleKey}"`);
  return ["msiexec /qn /i NSCP-<version>-x64.msi", ...props].join(" ");
}
