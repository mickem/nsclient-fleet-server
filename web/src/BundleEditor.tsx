import { useEffect, useState } from "react";
import {
  Alert,
  Button,
  Card,
  CardContent,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import { apiGet, apiSend, BundleConfigView, BundleView } from "./api";
import { ConfigObject, iniToJson, jsonToIni, suggestNextVersion } from "./ini";

type Props = {
  /** When set, the editor loads this bundle's config and saves as a new version. */
  editBundleId: string | null;
  onSaved: (created: BundleView) => void;
  onCancel: () => void;
};

const NEW_BUNDLE_TEMPLATE = `; Bundle configuration (NSClient INI).
; Sections are configuration paths, e.g.:
;
; [/settings/system/windows]
; enable=true

`;

export function BundleEditor({ editBundleId, onSaved, onCancel }: Props) {
  const [base, setBase] = useState<BundleConfigView | null>(null);
  const [loading, setLoading] = useState(editBundleId !== null);
  const [name, setName] = useState("");
  const [version, setVersion] = useState("1.0.0");
  const [ini, setIni] = useState(NEW_BUNDLE_TEMPLATE);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (editBundleId === null) return;
    setLoading(true);
    apiGet<BundleConfigView>(`/api/bundles/${editBundleId}/config`).then(
      (cfg) => {
        setBase(cfg);
        setName(cfg.name);
        setVersion(suggestNextVersion(cfg.version));
        setIni(jsonToIni(cfg.config_json as ConfigObject));
        setLoading(false);
      },
      (e) => {
        setError(e instanceof Error ? e.message : String(e));
        setLoading(false);
      },
    );
  }, [editBundleId]);

  const save = async () => {
    setError(null);
    let config: ConfigObject;
    try {
      config = iniToJson(ini);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return;
    }
    setBusy(true);
    try {
      const created = await apiSend<BundleView>("POST", "/api/bundles/compose", {
        name: name.trim(),
        version: version.trim(),
        config_json: config,
        base_bundle_id: base?.id ?? null,
      });
      onSaved(created);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setError(
        msg.includes("already exists")
          ? `Version ${version.trim()} of ${name.trim()} already exists — pick another version.`
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
          {base ? `Edit ${base.name}@${base.version} → new version` : "New bundle"}
        </Typography>
        <Stack direction="row" spacing={2} sx={{ mb: 2 }} useFlexGap flexWrap="wrap">
          <TextField
            size="small"
            label="Name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            disabled={base !== null}
            placeholder="sql-monitoring"
          />
          <TextField
            size="small"
            label="Version"
            value={version}
            onChange={(e) => setVersion(e.target.value)}
            sx={{ width: "10rem" }}
          />
        </Stack>
        {base && base.scripts.length > 0 && (
          <Alert severity="info" sx={{ mb: 2 }}>
            {base.scripts.length} script file(s) will be carried over unchanged:{" "}
            <code>{base.scripts.join(", ")}</code> (script editing comes later).
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
            {busy ? "Saving…" : base ? "Save as new version" : "Create bundle"}
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
