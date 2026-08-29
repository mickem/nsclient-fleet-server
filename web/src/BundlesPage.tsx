import { useEffect, useRef, useState } from "react";
import {
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Checkbox,
  Chip,
  FormControlLabel,
  IconButton,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Tooltip,
  Typography,
} from "@mui/material";
import AddIcon from "@mui/icons-material/Add";
import DownloadIcon from "@mui/icons-material/Download";
import EditIcon from "@mui/icons-material/Edit";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import LockIcon from "@mui/icons-material/Lock";
import {
  apiGet,
  apiSend,
  apiUpload,
  BundleKeyView,
  BundleView,
  canWriteConfig,
  fmtBytes,
  fmtTime,
  Me,
} from "./api";
import {
  encryptBundle,
  forgetKey,
  generateKeyB64,
  keyFingerprintHex,
  recalledKey,
  rememberKey,
} from "./crypto";
import { BundleEditor } from "./BundleEditor";
import { RefreshButton } from "./RefreshButton";

type EditorState = null | { bundle: BundleView | null };

/** Registered-key state plus whether this browser session holds the matching key. */
function useBundleKey() {
  const [fingerprint, setFingerprint] = useState<string | null>(null);
  const [unlocked, setUnlocked] = useState(false);

  const sync = async () => {
    const v = await apiGet<BundleKeyView>("/api/bundle-key");
    setFingerprint(v.fingerprint);
    const key = recalledKey();
    setUnlocked(
      key !== null && v.fingerprint !== null && (await keyFingerprintHex(key)) === v.fingerprint,
    );
  };
  useEffect(() => {
    void sync().catch(() => {});
  }, []);
  return { fingerprint, unlocked, sync, setUnlocked };
}

/** Key registration, unlock, and rotation. The key exists only in this browser and on
 *  agents — the server sees the fingerprint alone, so losing the key loses the bundles. */
function EncryptionKeyCard({
  keyState,
  onError,
}: {
  keyState: ReturnType<typeof useBundleKey>;
  onError: (msg: string) => void;
}) {
  const { fingerprint, unlocked, sync, setUnlocked } = keyState;
  const [pasted, setPasted] = useState("");
  const [freshKey, setFreshKey] = useState<string | null>(null);

  const generate = async () => {
    if (
      fingerprint &&
      !window.confirm(
        "Rotate the encryption key? Existing encrypted bundles keep the old key — agents need " +
          "both keys until those bundles are re-encrypted and re-uploaded.",
      )
    )
      return;
    try {
      const key = generateKeyB64();
      const fp = await keyFingerprintHex(key);
      await apiSend<BundleKeyView>("PUT", "/api/bundle-key", { fingerprint: fp });
      rememberKey(key);
      setFreshKey(key);
      setUnlocked(true);
      await sync();
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    }
  };

  const unlock = async () => {
    try {
      const fp = await keyFingerprintHex(pasted);
      if (fp !== fingerprint) {
        onError(
          `That key's fingerprint (${fp}) does not match the registered one (${fingerprint}). ` +
            'To switch this tenant to the pasted key, use "Register pasted key" instead.',
        );
        return;
      }
      rememberKey(pasted.trim());
      setPasted("");
      setUnlocked(true);
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    }
  };

  /** Register a pasted, already-deployed key as the tenant key — the "my agents already
   *  have a key" path, where generating a fresh one would be exactly wrong. The server
   *  only ever learns the fingerprint. */
  const registerPasted = async () => {
    try {
      const key = pasted.trim();
      const fp = await keyFingerprintHex(key);
      if (
        fingerprint !== null &&
        fp !== fingerprint &&
        !window.confirm(
          `Replace the registered key (${fingerprint}) with the pasted one (${fp})? New ` +
            "encrypted bundles will be sealed with the pasted key. Existing encrypted bundles " +
            "keep the key they were sealed with — agents need both until those are " +
            "re-encrypted and re-uploaded.",
        )
      )
        return;
      await apiSend<BundleKeyView>("PUT", "/api/bundle-key", { fingerprint: fp });
      rememberKey(key);
      setPasted("");
      setUnlocked(true);
      await sync();
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <Accordion sx={{ mt: 3 }} disableGutters>
      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
        <Stack direction="row" spacing={1} alignItems="center">
          <LockIcon fontSize="small" color={unlocked ? "success" : "disabled"} />
          <Typography color="text.secondary">
            Encryption key{" "}
            {fingerprint
              ? unlocked
                ? "(unlocked for this session)"
                : "(locked)"
              : "(none registered)"}
          </Typography>
        </Stack>
      </AccordionSummary>
      <AccordionDetails>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          Encrypted bundles are sealed in your browser with this key before upload; the server
          stores only the ciphertext and the key fingerprint. Generate a fresh key, or paste
          the one your agents already carry to keep working with a deployed fleet. Give the
          key to your agents via their local configuration.{" "}
          <strong>It cannot be recovered</strong> — anything encrypted with a lost key is
          gone.
        </Typography>
        {freshKey && (
          <Alert severity="warning" sx={{ mb: 2 }} onClose={() => setFreshKey(null)}>
            <Typography variant="body2" sx={{ mb: 1 }}>
              Your new key — shown once. Store it in a password manager and add it to your
              agents' configuration now:
            </Typography>
            <Stack direction="row" spacing={1} alignItems="center">
              <Typography component="code" sx={{ wordBreak: "break-all" }}>
                {freshKey}
              </Typography>
              <Button size="small" onClick={() => void navigator.clipboard.writeText(freshKey)}>
                Copy
              </Button>
            </Stack>
          </Alert>
        )}
        <Stack direction="row" spacing={1} alignItems="center" useFlexGap flexWrap="wrap">
          {fingerprint && (
            <Typography variant="body2">
              Fingerprint: <code>{fingerprint}</code>
            </Typography>
          )}
          {!unlocked && (
            <>
              <TextField
                size="small"
                label={fingerprint ? "paste key to unlock" : "paste existing key"}
                type="password"
                value={pasted}
                onChange={(e) => setPasted(e.target.value)}
              />
              {fingerprint && (
                <Button variant="outlined" onClick={unlock} disabled={!pasted.trim()}>
                  Unlock
                </Button>
              )}
              <Tooltip
                title={
                  fingerprint
                    ? "Make the pasted key this tenant's bundle key instead of the " +
                      "registered one — for switching to a key your agents already carry."
                    : "Register a key your agents already carry, instead of generating a " +
                      "new one."
                }
              >
                <span>
                  <Button
                    variant={fingerprint ? "text" : "outlined"}
                    onClick={registerPasted}
                    disabled={!pasted.trim()}
                  >
                    {fingerprint ? "Register pasted key" : "Use existing key"}
                  </Button>
                </span>
              </Tooltip>
            </>
          )}
          {fingerprint && unlocked && (
            <Button
              size="small"
              onClick={() => {
                forgetKey();
                setUnlocked(false);
              }}
            >
              Lock
            </Button>
          )}
          <Button variant={fingerprint ? "text" : "contained"} onClick={generate}>
            {fingerprint ? "Rotate key" : "Generate key"}
          </Button>
        </Stack>
      </AccordionDetails>
    </Accordion>
  );
}

export function BundlesPage({ me }: { me: Me }) {
  const [bundles, setBundles] = useState<BundleView[] | null>(null);
  const [editor, setEditor] = useState<EditorState>(null);
  const [name, setName] = useState("");
  const [version, setVersion] = useState("");
  const [encrypt, setEncrypt] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);
  const keyState = useBundleKey();

  // Returns void, not the promise: `useEffect` below takes this directly, and a returned
  // promise would be mistaken for a cleanup function.
  const refresh = () => {
    setRefreshing(true);
    setError(null);
    void apiGet<BundleView[]>("/api/bundles")
      .then(setBundles, (e) => setError(e.message))
      .finally(() => setRefreshing(false));
  };
  useEffect(refresh, []);

  const upload = async () => {
    const file = fileRef.current?.files?.[0];
    if (!file || !name.trim() || !version.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const form = new FormData();
      form.set("name", name.trim());
      form.set("version", version.trim());
      if (encrypt) {
        const key = recalledKey();
        if (!key || !keyState.unlocked) {
          throw new Error("Unlock the encryption key first (see the Encryption key section).");
        }
        const plain = new Uint8Array(await file.arrayBuffer());
        const sealed = await encryptBundle(key, name.trim(), version.trim(), plain);
        form.set("format", "enc-v1");
        form.set("bundle", new Blob([sealed]), file.name + ".nseb");
      } else {
        form.set("bundle", file);
      }
      await apiUpload("/api/bundles", form);
      setName("");
      setVersion("");
      if (fileRef.current) fileRef.current.value = "";
      refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Box>
      <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 1 }}>
        <Typography variant="h4">Bundles</Typography>
        <Stack direction="row" spacing={1} alignItems="center">
          <RefreshButton refreshing={refreshing} onClick={refresh} />
          {!editor && canWriteConfig(me.role) && (
            <Button
              variant="contained"
              startIcon={<AddIcon />}
              onClick={() => setEditor({ bundle: null })}
            >
              New bundle
            </Button>
          )}
        </Stack>
      </Stack>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        A bundle is a zip (manifest + config patch + scripts) signed by your tenant key.
        Versions are immutable — to roll back, assign the older version to the group.
        Encrypted bundles are additionally sealed in your browser; the server never sees
        their contents or the key.
      </Typography>
      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {editor && (
        <BundleEditor
          key={editor.bundle?.id ?? "new"}
          editBundle={editor.bundle}
          keyState={keyState}
          onSaved={() => {
            setEditor(null);
            refresh();
          }}
          onCancel={() => setEditor(null)}
        />
      )}

      {bundles === null ? (
        <Typography>Loading…</Typography>
      ) : bundles.length === 0 ? (
        <Card>
          <CardContent>
            <Typography color="text.secondary">
              No bundles yet — create one with the editor, or upload a zip below.
            </Typography>
          </CardContent>
        </Card>
      ) : (
        <TableContainer component={Card}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Name</TableCell>
                <TableCell>Version</TableCell>
                <TableCell>Size</TableCell>
                <TableCell>Uploaded</TableCell>
                <TableCell>sha256</TableCell>
                <TableCell />
              </TableRow>
            </TableHead>
            <TableBody>
              {bundles.map((b) => (
                <TableRow key={b.id} hover>
                  <TableCell>
                    <Stack direction="row" spacing={1} alignItems="center">
                      <span>{b.name}</span>
                      {b.format === "enc-v1" && (
                        <Tooltip title={`Encrypted client-side (key ${b.key_fingerprint ?? "?"})`}>
                          <Chip
                            icon={<LockIcon />}
                            label="encrypted"
                            size="small"
                            variant="outlined"
                          />
                        </Tooltip>
                      )}
                    </Stack>
                  </TableCell>
                  <TableCell>{b.version}</TableCell>
                  <TableCell>{fmtBytes(b.size_bytes)}</TableCell>
                  <TableCell>{fmtTime(b.uploaded_at)}</TableCell>
                  <TableCell>
                    <Typography variant="caption" component="code">
                      {b.sha256.slice(0, 16)}…
                    </Typography>
                  </TableCell>
                  <TableCell align="right">
                    <Tooltip
                      title={
                        b.format === "enc-v1"
                          ? "Download the sealed bundle (ciphertext)"
                          : "Download the bundle zip"
                      }
                    >
                      <IconButton
                        size="small"
                        component="a"
                        href={`/api/bundles/${b.id}/download`}
                      >
                        <DownloadIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                    {canWriteConfig(me.role) &&
                      (b.format === "enc-v1" &&
                      !(keyState.unlocked && b.key_fingerprint === keyState.fingerprint) ? (
                        <Tooltip
                          title={
                            !keyState.unlocked
                              ? "Unlock the encryption key (below) to open this bundle in " +
                                "your browser — the server cannot read it."
                              : "This bundle is sealed with a different key than the one " +
                                "registered, so it cannot be opened here."
                          }
                        >
                          <span>
                            <Button size="small" startIcon={<EditIcon />} disabled>
                              Edit
                            </Button>
                          </span>
                        </Tooltip>
                      ) : (
                        <Button
                          size="small"
                          startIcon={<EditIcon />}
                          onClick={() => setEditor({ bundle: b })}
                        >
                          Edit
                        </Button>
                      ))}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      {canWriteConfig(me.role) && <EncryptionKeyCard keyState={keyState} onError={setError} />}

      {canWriteConfig(me.role) && (
      <Accordion sx={{ mt: 1 }} disableGutters>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography color="text.secondary">Upload a pre-built zip</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Stack direction="row" spacing={1} alignItems="center" useFlexGap flexWrap="wrap">
            <TextField
              size="small"
              label="name"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
            <TextField
              size="small"
              label="version"
              value={version}
              onChange={(e) => setVersion(e.target.value)}
            />
            <input type="file" ref={fileRef} accept=".zip" />
            <Tooltip
              title={
                encrypt && !keyState.unlocked
                  ? "Unlock the encryption key first"
                  : "Seal the zip in your browser before upload — for bundles carrying secrets"
              }
            >
              <FormControlLabel
                control={
                  <Checkbox
                    checked={encrypt}
                    onChange={(e) => setEncrypt(e.target.checked)}
                    size="small"
                  />
                }
                label="Encrypt"
              />
            </Tooltip>
            <Button
              variant="contained"
              onClick={upload}
              disabled={busy || !name.trim() || !version.trim() || (encrypt && !keyState.unlocked)}
            >
              {busy ? "Uploading…" : encrypt ? "Encrypt & upload" : "Upload bundle"}
            </Button>
          </Stack>
        </AccordionDetails>
      </Accordion>
      )}
    </Box>
  );
}
