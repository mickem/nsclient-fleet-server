import { useEffect, useState } from "react";
import {
  Alert,
  Button,
  Card,
  CardContent,
  Checkbox,
  Chip,
  FormControlLabel,
  Stack,
  TextField,
  Tooltip,
  Typography,
} from "@mui/material";
import {
  apiGet,
  apiGetBytes,
  apiSend,
  apiUpload,
  BundleConfigView,
  BundleView,
} from "../api";
import {
  buildBundleZip,
  type BundleScript,
  CarriedEntries,
  readBundleZip,
  TOKEN_RE,
} from "./bundlezip";
import { bytesToBase64, scriptBytes } from "./scriptFiles";
import { ScriptsEditor } from "./ScriptsEditor";
import { decryptBundle, encryptBundle, recalledKey } from "./crypto";
import { ConfigObject, iniToJson, jsonToIni, suggestNextVersion } from "../config/ini";
import { ConfigEditor } from "../config/ConfigEditor";
import { TemplatePicker } from "../config/TemplatePicker";
import { templateById } from "../config/templates";

type Props = {
  /** When set, the editor loads this bundle's config and saves as a new version. Plain
   *  bundles are read/composed by the server; encrypted ones are downloaded, opened, and
   *  rebuilt entirely in the browser — the server never sees their plaintext. */
  editBundle: BundleView | null;
  /** Registered-key state from the page. Encrypted work needs `unlocked`. */
  keyState: { fingerprint: string | null; unlocked: boolean };
  onSaved: () => void;
  onCancel: () => void;
};

const NEW_BUNDLE_TEMPLATE = `; Bundle configuration (NSClient INI).
; Sections are configuration paths, e.g.:
;
; [/settings/system/windows]
; enable=true

`;


export function BundleEditor({ editBundle, keyState, onSaved, onCancel }: Props) {
  const [loading, setLoading] = useState(editBundle !== null);
  // New bundles start at the template picker; edits go straight to the INI.
  const [picking, setPicking] = useState(editBundle === null);
  const [name, setName] = useState("");
  const [version, setVersion] = useState("1.0.0");
  const [ini, setIni] = useState(NEW_BUNDLE_TEMPLATE);
  // Template this bundle was created from (kept through edits via bundle.toml metadata).
  const [template, setTemplate] = useState<string | null>(null);
  const [scripts, setScripts] = useState<BundleScript[]>([]);
  const [encrypt, setEncrypt] = useState(editBundle?.format === "enc-v1");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // Zip entries of the base other than manifest, config and scripts — read at load when the
  // base was opened in the browser (encrypted, or plain with scripts). Otherwise null: they
  // are carried server-side by compose, or fetched lazily on an encrypting save.
  const [carried, setCarried] = useState<CarriedEntries | null>(null);

  const encBase = editBundle?.format === "enc-v1";
  const keyReady = keyState.fingerprint !== null && keyState.unlocked;

  useEffect(() => {
    if (editBundle === null) return;
    const load = async () => {
      if (editBundle.format === "enc-v1") {
        const key = recalledKey();
        if (!key || !keyState.unlocked) {
          throw new Error("Unlock the encryption key first (see the Encryption key section).");
        }
        const sealed = await apiGetBytes(`/api/bundles/${editBundle.id}/download`);
        const zip = await decryptBundle(key, editBundle.name, editBundle.version, sealed);
        const opened = readBundleZip(zip);
        setIni(jsonToIni(opened.configJson as ConfigObject));
        setScripts(opened.scripts);
        setTemplate(opened.template);
        setCarried(opened.carried);
      } else {
        const cfg = await apiGet<BundleConfigView>(`/api/bundles/${editBundle.id}/config`);
        setIni(jsonToIni(cfg.config_json as ConfigObject));
        setTemplate(cfg.template);
        // The config view only lists the scripts; their contents come from the zip itself.
        if (cfg.scripts.length > 0) {
          const opened = readBundleZip(
            await apiGetBytes(`/api/bundles/${editBundle.id}/download`),
          );
          setScripts(opened.scripts);
          setCarried(opened.carried);
        }
      }
      setName(editBundle.name);
      setVersion(suggestNextVersion(editBundle.version));
    };
    load().then(
      () => setLoading(false),
      (e) => {
        setError(e instanceof Error ? e.message : String(e));
        setLoading(false);
      },
    );
    // The page remounts the editor per bundle (keyed), so this runs once per bundle.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  /** Entries to carry into a client-built zip: decrypted ones if the base was encrypted,
   *  the base zip's if it was plain (fetched here, only when actually needed), none for a
   *  brand-new bundle. */
  const carriedEntries = async (): Promise<CarriedEntries> => {
    if (carried !== null) return carried;
    if (editBundle === null) return [];
    return readBundleZip(await apiGetBytes(`/api/bundles/${editBundle.id}/download`)).carried;
  };

  const save = async () => {
    setError(null);
    const n = name.trim();
    const v = version.trim();
    if (!TOKEN_RE.test(n) || !TOKEN_RE.test(v)) {
      setError(
        "Name and version may only contain letters, digits, dot, dash and underscore " +
          "(max 128 characters).",
      );
      return;
    }
    let config: ConfigObject;
    try {
      config = iniToJson(ini);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return;
    }
    // Belt-and-braces: template ids are ours and read back token-validated, but the
    // manifest quoting must never be breakable.
    const tmpl = template !== null && TOKEN_RE.test(template) ? template : null;
    setBusy(true);
    try {
      if (encrypt) {
        const key = recalledKey();
        if (!key || !keyState.unlocked) {
          throw new Error("Unlock the encryption key first (see the Encryption key section).");
        }
        const zip = buildBundleZip(n, v, config, await carriedEntries(), scripts, tmpl);
        const sealed = await encryptBundle(key, n, v, zip);
        const form = new FormData();
        form.set("name", n);
        form.set("version", v);
        form.set("format", "enc-v1");
        form.set("bundle", new Blob([sealed]), `${n}-${v}.nseb`);
        // Saved against the bundle this was opened from: if it has been renamed (or
        // deleted) meanwhile, the server refuses rather than recreate the old name.
        if (editBundle) form.set("base_bundle_id", editBundle.id);
        await apiUpload<BundleView>("/api/bundles", form);
      } else if (encBase) {
        // The base was decrypted in this browser; the server cannot compose from a bundle
        // it cannot read, so the plain zip is built here too and uploaded as-is.
        const zip = buildBundleZip(n, v, config, await carriedEntries(), scripts, tmpl);
        const form = new FormData();
        form.set("name", n);
        form.set("version", v);
        form.set("bundle", new Blob([zip], { type: "application/zip" }), `${n}-${v}.zip`);
        // Saved against the bundle this was opened from: if it has been renamed (or
        // deleted) meanwhile, the server refuses rather than recreate the old name.
        if (editBundle) form.set("base_bundle_id", editBundle.id);
        await apiUpload<BundleView>("/api/bundles", form);
      } else {
        await apiSend<BundleView>("POST", "/api/bundles/compose", {
          name: n,
          version: v,
          config_json: config,
          base_bundle_id: editBundle?.id ?? null,
          template: tmpl,
          // The complete scripts/ set; the server replaces the base's with it.
          scripts: scripts.map((s) => ({ path: s.path, content_b64: bytesToBase64(s.data) })),
        });
      }
      onSaved();
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setError(
        msg.includes("already exists")
          ? `Version ${v} of ${n} already exists — pick another version.`
          : msg,
      );
    } finally {
      setBusy(false);
    }
  };

  if (loading) return <Typography>Loading bundle…</Typography>;

  const tmplInfo = template !== null ? templateById(template) : undefined;

  if (picking) {
    return (
      <Card sx={{ my: 2 }}>
        <CardContent>
          <Typography variant="h5" gutterBottom>
            New bundle
          </Typography>
          <TemplatePicker
            onPick={(t) => {
              if (t !== null) {
                setTemplate(t.id);
                setName(t.id);
                setIni(t.ini);
                setScripts(
                  (t.scripts ?? []).map((s) => ({
                    path: s.path,
                    data: scriptBytes(s.path, s.content),
                  })),
                );
              }
              setPicking(false);
            }}
            onCancel={onCancel}
          />
        </CardContent>
      </Card>
    );
  }

  return (
    <Card sx={{ my: 2 }}>
      <CardContent>
        <Typography variant="h5" gutterBottom>
          {editBundle
            ? `Edit ${editBundle.name}@${editBundle.version} → new version`
            : "New bundle"}
        </Typography>
        <Stack
          direction="row"
          spacing={2}
          useFlexGap
          sx={{ alignItems: "center", flexWrap: "wrap", mb: 2 }}>
          <TextField
            size="small"
            label="Name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            disabled={editBundle !== null}
            placeholder="sql-monitoring"
          />
          <TextField
            size="small"
            label="Version"
            value={version}
            onChange={(e) => setVersion(e.target.value)}
            sx={{ width: "10rem" }}
          />
          <Tooltip
            title={
              keyReady
                ? "Seal this version in your browser before upload — the server stores only " +
                  "ciphertext it can neither read nor edit. For bundles carrying secrets."
                : "Register and unlock the encryption key (see the Encryption key section) " +
                  "to save encrypted bundles."
            }
          >
            <FormControlLabel
              control={
                <Checkbox
                  size="small"
                  checked={encrypt}
                  onChange={(e) => setEncrypt(e.target.checked)}
                  disabled={!keyReady && !encrypt}
                />
              }
              label="Encrypted"
            />
          </Tooltip>
          {template !== null && (
            <Tooltip
              title={
                tmplInfo?.description ??
                "Created from a template this UI no longer knows. Remove to detach."
              }
            >
              <Chip
                size="small"
                variant="outlined"
                label={`template: ${tmplInfo?.title ?? template}`}
                onDelete={() => setTemplate(null)}
              />
            </Tooltip>
          )}
        </Stack>
        {tmplInfo?.sensitive && !encrypt && (
          <Alert severity="info" sx={{ mb: 2 }}>
            This template carries credentials — consider ticking <strong>Encrypted</strong>{" "}
            so the server only ever stores ciphertext.
          </Alert>
        )}
        {encBase && !encrypt && (
          <Alert severity="warning" sx={{ mb: 2 }}>
            The new version will be saved <strong>unencrypted</strong> — its contents,
            including any secrets, become readable by the server. The existing encrypted
            versions are unaffected.
          </Alert>
        )}
        {editBundle && !encBase && encrypt && (
          <Alert severity="info" sx={{ mb: 2 }}>
            The new version will be encrypted. Agents can only open it if they have the
            bundle key in their local configuration.
          </Alert>
        )}
        <ConfigEditor template={tmplInfo} ini={ini} onChange={setIni} />
        <ScriptsEditor scripts={scripts} onChange={setScripts} ini={ini} onIniChange={setIni} />
        {error && (
          <Alert severity="error" sx={{ mt: 1 }}>
            {error}
          </Alert>
        )}
        <Stack direction="row" spacing={1} sx={{ mt: 2 }}>
          <Button
            variant="contained"
            onClick={save}
            disabled={busy || !name.trim() || !version.trim()}
          >
            {busy
              ? "Saving…"
              : encrypt
                ? editBundle
                  ? "Encrypt & save as new version"
                  : "Encrypt & create bundle"
                : editBundle
                  ? "Save as new version"
                  : "Create bundle"}
          </Button>
          <Button onClick={onCancel} disabled={busy}>
            Cancel
          </Button>
        </Stack>
        <Typography variant="caption" sx={{ color: "text.secondary" }}>
          Saved bundles are immutable — saving creates a new (name, version) that you can then
          assign to groups. Values are written to the agent&apos;s <code>fleet.ini</code>{" "}
          exactly as typed.
        </Typography>
      </CardContent>
    </Card>
  );
}
