import { useEffect, useState } from "react";
import {
  Alert,
  Autocomplete,
  Box,
  Button,
  Card,
  CardContent,
  Checkbox,
  FormControlLabel,
  MenuItem,
  Stack,
  Switch,
  TextField,
  Typography,
} from "@mui/material";
import {
  apiGet,
  apiSend,
  canWriteConfig,
  ExplainSettings,
  ExplainSettingsUpdate,
  fmtTime,
  Me,
} from "../api";

/** Tenant-wide settings. One section today; the page is where the next one goes. */
export function SettingsPage({ me }: { me: Me }) {
  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 2 }}>
        Settings
      </Typography>
      <ExplainSettingsCard canWrite={canWriteConfig(me.role)} />
    </Box>
  );
}

/**
 * Whether agents report failed checks with their snapshot, and which model explains errors
 * against that evidence.
 *
 * The API key is write-only: the form never shows one, only whether one is stored. Leaving the
 * field blank keeps it; "remove the stored key" sends an empty string, which clears it.
 */
function ExplainSettingsCard({ canWrite }: { canWrite: boolean }) {
  const [loaded, setLoaded] = useState<ExplainSettings | null>(null);
  const [form, setForm] = useState<ExplainSettingsUpdate | null>(null);
  const [apiKey, setApiKey] = useState("");
  const [clearKey, setClearKey] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [busy, setBusy] = useState(false);

  // Returns void, not the promise: `useEffect` below takes this directly.
  const load = () => {
    setApiKey("");
    setClearKey(false);
    void apiGet<ExplainSettings>("/api/settings/explain").then(
      (s) => {
        setLoaded(s);
        setForm({
          reports_enabled: s.reports_enabled,
          min_interval_secs: s.min_interval_secs,
          explain_enabled: s.explain_enabled,
          provider: s.provider || s.available_providers[0] || "",
          model: s.model,
          base_url: s.base_url,
          daily_call_budget: s.daily_call_budget,
        });
      },
      (e) => setError(e instanceof Error ? e.message : String(e)),
    );
  };
  useEffect(load, []);

  const set = <K extends keyof ExplainSettingsUpdate>(k: K, v: ExplainSettingsUpdate[K]) => {
    setSaved(false);
    setForm((f) => (f ? { ...f, [k]: v } : f));
  };

  const save = async () => {
    if (!form) return;
    setBusy(true);
    setError(null);
    setSaved(false);
    try {
      const body: ExplainSettingsUpdate = { ...form };
      if (clearKey) body.api_key = "";
      else if (apiKey.trim()) body.api_key = apiKey.trim();
      await apiSend("PUT", "/api/settings/explain", body);
      setSaved(true);
      load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const ro = !canWrite || busy;
  return (
    <Card variant="outlined" sx={{ maxWidth: "48rem" }}>
      <CardContent>
        <Typography variant="h5" gutterBottom>
          Failure context and explanations
        </Typography>
        <Typography variant="body2" sx={{ color: "text.secondary", mb: 2 }}>
          When a check fails, agents can report it together with the metrics they held at that
          moment. Those reports, with each host's inventory facts, are the evidence an error
          from your monitoring system is explained against on the host's Context tab, or with{" "}
          <code>check_nsclient fleet explain</code>.
        </Typography>
        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}
        {saved && (
          <Alert severity="success" sx={{ mb: 2 }} onClose={() => setSaved(false)}>
            Saved.
          </Alert>
        )}
        {!canWrite && (
          <Alert severity="info" sx={{ mb: 2 }}>
            Your role can view these settings but not change them.
          </Alert>
        )}
        {!form || !loaded ? (
          !error && <Typography>Loading…</Typography>
        ) : (
          <Stack spacing={2}>
            {loaded.inherits_server_default && (
              <Alert severity="info">
                These are the server's defaults. Saving stores settings for this tenant.
              </Alert>
            )}
            <FormControlLabel
              control={
                <Switch
                  checked={form.reports_enabled}
                  disabled={ro}
                  onChange={(e) => set("reports_enabled", e.target.checked)}
                />
              }
              label="Agents report failed checks with their metrics snapshot"
            />
            <TextField
              size="small"
              type="number"
              label="Minimum seconds between reports"
              helperText="Sent to agents as a lower limit. An agent set to a longer interval keeps it."
              value={form.min_interval_secs}
              disabled={ro || !form.reports_enabled}
              onChange={(e) => set("min_interval_secs", Number(e.target.value))}
            />
            <FormControlLabel
              control={
                <Switch
                  checked={form.explain_enabled}
                  disabled={ro}
                  onChange={(e) => set("explain_enabled", e.target.checked)}
                />
              }
              label="Explain errors with a model"
            />
            {form.explain_enabled && (
              <>
                <Alert severity="warning">
                  Each explanation sends the error, the host's latest metrics snapshot and its
                  inventory facts to the provider below. These include host, service, interface
                  and address names.
                </Alert>
                <TextField
                  select
                  size="small"
                  label="Provider"
                  value={form.provider}
                  disabled={ro}
                  onChange={(e) => {
                    const provider = e.target.value;
                    const models = loaded.suggested_models?.[provider] ?? [];
                    set("provider", provider);
                    // A model named for the previous provider cannot work with this one, so
                    // switching provider switches to its default.
                    if (models.length > 0 && !models.includes(form.model)) {
                      set("model", models[0]);
                    }
                  }}
                >
                  {loaded.available_providers.map((p) => (
                    <MenuItem key={p} value={p}>
                      {p}
                    </MenuItem>
                  ))}
                </TextField>
                {/* Free text with suggestions: the list is the provider's current models, the
                    default first, but any model the provider serves can be typed in. */}
                <Autocomplete
                  freeSolo
                  // freeSolo hides the arrow and opens only on typing; the list is the point
                  // of this field, so it gets an arrow and opens when the field is focused —
                  // unless there is no list (a server older than this console), when an arrow
                  // over an empty popup would read as broken.
                  forcePopupIcon={(loaded.suggested_models?.[form.provider]?.length ?? 0) > 0}
                  openOnFocus
                  disableClearable
                  options={loaded.suggested_models?.[form.provider] ?? []}
                  value={form.model}
                  inputValue={form.model}
                  disabled={ro}
                  onInputChange={(_, v) => set("model", v)}
                  // The whole list every time: it is a few names, and filtering it by the
                  // current value would hide the alternatives as soon as one is picked.
                  filterOptions={(options) => options}
                  renderOption={(props, option) => (
                    <li {...props} key={option}>
                      {option}
                      {option === loaded.suggested_models?.[form.provider]?.[0] && (
                        <Typography
                          component="span"
                          variant="caption"
                          sx={{ ml: 1, color: "text.secondary" }}
                        >
                          default
                        </Typography>
                      )}
                    </li>
                  )}
                  renderInput={(params) => (
                    <TextField
                      {...params}
                      size="small"
                      label="Model"
                      helperText="Pick a suggested model or type the name of another."
                    />
                  )}
                />
                <TextField
                  size="small"
                  label="Base URL (optional)"
                  value={form.base_url ?? ""}
                  disabled={ro}
                  onChange={(e) => set("base_url", e.target.value || null)}
                />
                <TextField
                  size="small"
                  type="password"
                  autoComplete="off"
                  label="API key"
                  placeholder={loaded.api_key_set ? "stored — leave blank to keep it" : "not set"}
                  value={apiKey}
                  disabled={ro || clearKey}
                  onChange={(e) => {
                    setSaved(false);
                    setApiKey(e.target.value);
                  }}
                />
                {loaded.api_key_set && (
                  <FormControlLabel
                    control={
                      <Checkbox
                        checked={clearKey}
                        disabled={ro}
                        onChange={(e) => setClearKey(e.target.checked)}
                      />
                    }
                    label="Remove the stored key"
                  />
                )}
                <TextField
                  size="small"
                  type="number"
                  label="Explanations per day"
                  helperText={`${loaded.calls_today} used today (UTC), ${loaded.failures_today} of them failed.`}
                  value={form.daily_call_budget}
                  disabled={ro}
                  onChange={(e) => set("daily_call_budget", Number(e.target.value))}
                />
              </>
            )}
            {canWrite && (
              <Stack direction="row" spacing={2} sx={{ alignItems: "center" }}>
                <Button variant="contained" onClick={save} disabled={busy}>
                  {busy ? "Saving…" : "Save"}
                </Button>
                {loaded.updated_at && (
                  <Typography variant="caption" sx={{ color: "text.secondary" }}>
                    Last changed {fmtTime(loaded.updated_at)}
                  </Typography>
                )}
              </Stack>
            )}
          </Stack>
        )}
      </CardContent>
    </Card>
  );
}
