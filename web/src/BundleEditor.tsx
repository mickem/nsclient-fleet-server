import { useEffect, useState } from "react";
import {
  Alert,
  Button,
  Card,
  CardContent,
  Checkbox,
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
} from "./api";
import { buildBundleZip, CarriedEntries, readBundleZip } from "./bundlezip";
import { decryptBundle, encryptBundle, recalledKey } from "./crypto";
import { ConfigObject, iniToJson, jsonToIni, suggestNextVersion } from "./ini";

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

/** Mirrors the server's `valid_bundle_token` — also what keeps the client-built manifest's
 *  quoting and the encryption AAD unambiguous. */
const TOKEN_RE = /^[A-Za-z0-9._-]{1,128}$/;

export function BundleEditor({ editBundle, keyState, onSaved, onCancel }: Props) {
  const [loading, setLoading] = useState(editBundle !== null);
  const [name, setName] = useState("");
  const [version, setVersion] = useState("1.0.0");
  const [ini, setIni] = useState(NEW_BUNDLE_TEMPLATE);
  const [scripts, setScripts] = useState<string[]>([]);
  const [encrypt, setEncrypt] = useState(editBundle?.format === "enc-v1");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // Non-config zip entries of an encrypted base, decrypted at load. Plain bases leave this
  // null — their entries are carried server-side by compose, or fetched lazily on an
  // encrypting save.
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
        setCarried(opened.carried);
      } else {
        const cfg = await apiGet<BundleConfigView>(`/api/bundles/${editBundle.id}/config`);
        setIni(jsonToIni(cfg.config_json as ConfigObject));
        setScripts(cfg.scripts);
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
    setBusy(true);
    try {
      if (encrypt) {
        const key = recalledKey();
        if (!key || !keyState.unlocked) {
          throw new Error("Unlock the encryption key first (see the Encryption key section).");
        }
        const zip = buildBundleZip(n, v, config, await carriedEntries());
        const sealed = await encryptBundle(key, n, v, zip);
        const form = new FormData();
        form.set("name", n);
        form.set("version", v);
        form.set("format", "enc-v1");
        form.set("bundle", new Blob([sealed]), `${n}-${v}.nseb`);
        await apiUpload<BundleView>("/api/bundles", form);
      } else if (encBase) {
        // The base was decrypted in this browser; the server cannot compose from a bundle
        // it cannot read, so the plain zip is built here too and uploaded as-is.
        const zip = buildBundleZip(n, v, config, await carriedEntries());
        const form = new FormData();
        form.set("name", n);
        form.set("version", v);
        form.set("bundle", new Blob([zip], { type: "application/zip" }), `${n}-${v}.zip`);
        await apiUpload<BundleView>("/api/bundles", form);
      } else {
        await apiSend<BundleView>("POST", "/api/bundles/compose", {
          name: n,
          version: v,
          config_json: config,
          base_bundle_id: editBundle?.id ?? null,
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
          alignItems="center"
          sx={{ mb: 2 }}
          useFlexGap
          flexWrap="wrap"
        >
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
        </Stack>
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
        {scripts.length > 0 && (
          <Alert severity="info" sx={{ mb: 2 }}>
            {scripts.length} script file(s) will be carried over unchanged:{" "}
            <code>{scripts.join(", ")}</code> (script editing comes later).
          </Alert>
        )}
        <TextField
          multiline
          minRows={14}
          fullWidth
          spellCheck={false}
          value={ini}
          onChange={(e) => setIni(e.target.value)}
          slotProps={{
            input: {
              sx: { fontFamily: "monospace", fontSize: "0.9rem", whiteSpace: "pre" },
            },
          }}
        />
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
        <Typography variant="caption" color="text.secondary">
          Saved bundles are immutable — saving creates a new (name, version) that you can then
          assign to groups. Values are written to the agent&apos;s <code>fleet.ini</code>{" "}
          exactly as typed.
        </Typography>
      </CardContent>
    </Card>
  );
}
