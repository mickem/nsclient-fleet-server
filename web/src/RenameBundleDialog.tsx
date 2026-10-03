import { useEffect, useState } from "react";
import {
  Alert,
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogContentText,
  DialogTitle,
  TextField,
} from "@mui/material";
import { apiGetBytes, apiUpload, BundleView } from "./api";
import { TOKEN_RE } from "./bundlezip";
import { decryptBundle, encryptBundle, recalledKey } from "./crypto";

type Props = {
  /** Every version of the bundle being renamed; empty closes the dialog. */
  versions: BundleView[];
  /** Names already in use, which the new name may not take. */
  takenNames: Set<string>;
  /** Fingerprint of the key this browser holds unlocked, or null. */
  unlockedFingerprint: string | null;
  onClose: () => void;
  onRenamed: () => void;
};

/** Rename a bundle: every version of its name at once, so the versions stay one bundle.
 *  Groups keep carrying the same versions. Encrypted versions bind their name into the
 *  encryption, so this browser opens each with the old name and seals it again under the
 *  new one — which is why it needs the key unlocked. */
export function RenameBundleDialog({
  versions,
  takenNames,
  unlockedFingerprint,
  onClose,
  onRenamed,
}: Props) {
  const from = versions[0]?.name ?? "";
  const [to, setTo] = useState(from);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    setTo(from);
    setError(null);
  }, [from]);

  const encrypted = versions.filter((v) => v.format === "enc-v1");
  const sealedElsewhere = encrypted.filter((v) => v.key_fingerprint !== unlockedFingerprint);
  const target = to.trim();
  const problem =
    target === from
      ? null
      : !TOKEN_RE.test(target)
        ? "1-128 letters, digits, '.', '_' or '-'."
        : takenNames.has(target)
          ? "A bundle with this name already exists."
          : null;
  const blocked =
    encrypted.length > 0 && unlockedFingerprint === null
      ? "Unlock the encryption key first: the encrypted versions have to be re-sealed under " +
        "the new name, and only this browser can do that."
      : sealedElsewhere.length > 0
        ? `Version ${sealedElsewhere.map((v) => v.version).join(", ")} is sealed with a ` +
          "different key than the one unlocked here, so it cannot be re-sealed."
        : null;

  const rename = async () => {
    setBusy(true);
    setError(null);
    try {
      const form = new FormData();
      form.set("from", from);
      form.set("to", target);
      const key = recalledKey();
      for (const v of encrypted) {
        if (!key) throw new Error("The encryption key is no longer unlocked.");
        const sealed = await apiGetBytes(`/api/bundles/${v.id}/download`);
        const plain = await decryptBundle(key, from, v.version, sealed);
        const resealed = await encryptBundle(key, target, v.version, plain);
        form.set(`sealed:${v.id}`, new Blob([resealed]), `${target}-${v.version}.nseb`);
      }
      await apiUpload("/api/bundles/rename", form);
      onRenamed();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={versions.length > 0} onClose={busy ? undefined : onClose} fullWidth maxWidth="sm">
      <DialogTitle>Rename {from}</DialogTitle>
      <DialogContent>
        <DialogContentText sx={{ mb: 2 }}>
          {versions.length === 1
            ? "The bundle keeps its version and contents"
            : `All ${versions.length} versions (${versions.map((v) => v.version).join(", ")}) ` +
              "are renamed together, keeping their contents"}
          , and every group keeps carrying it. Hosts pick up the new name on their next poll.
        </DialogContentText>
        <TextField
          autoFocus
          fullWidth
          size="small"
          label="New name"
          value={to}
          disabled={busy || blocked !== null}
          onChange={(e) => setTo(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !problem && !blocked && target !== from) void rename();
          }}
          error={problem !== null}
          helperText={problem ?? " "}
        />
        {blocked && <Alert severity="info">{blocked}</Alert>}
        {error && (
          <Alert severity="error" sx={{ mt: 1 }}>
            {error}
          </Alert>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={busy}>
          Cancel
        </Button>
        <Button
          variant="contained"
          onClick={() => void rename()}
          disabled={busy || problem !== null || blocked !== null || target === from}
        >
          {busy ? "Renaming…" : "Rename"}
        </Button>
      </DialogActions>
    </Dialog>
  );
}
