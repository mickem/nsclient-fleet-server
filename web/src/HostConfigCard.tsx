import { useEffect, useMemo, useState } from "react";
import {
  Alert,
  Button,
  Card,
  CardContent,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogContentText,
  DialogTitle,
  InputAdornment,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TextField,
  Tooltip,
  Typography,
} from "@mui/material";
import EditIcon from "@mui/icons-material/Edit";
import SearchIcon from "@mui/icons-material/Search";
import {
  apiGet,
  apiGetBytes,
  apiSend,
  BundleConfigView,
  DesiredStateView,
  HostDetail,
  HostOverrideView,
} from "./api";
import { useBundleKey } from "./bundleKey";
import { readBundleZip } from "./bundlezip";
import { decryptBundle, recalledKey } from "./crypto";
import { ConfigEditor } from "./ConfigEditor";
import {
  configFromRows,
  Layer,
  layerConfigs,
  overrideDiff,
  Removal,
  removalFor,
  removalLabel,
  removalsOf,
  removedBy,
  sameRemoval,
  shapeOf,
} from "./hostConfig";
import { type ConfigObject, iniToJson, IniParseError, jsonToIni, setIniValue } from "./ini";
import { TemplatePicker } from "./TemplatePicker";
import { templateById } from "./templates";

type Props = {
  host: HostDetail;
  desired: DesiredStateView | null;
  /** Why the desired state could not be loaded, when it could not. */
  desiredError: string | null;
  canWrite: boolean;
  onChanged: () => void;
};

type BundleLayers = { layers: Layer[]; unreadable: { label: string; reason: string }[] };

/** Each bundle's config fragment, in the order the agent applies them (ascending priority,
 *  the server's order breaking ties). Encrypted ones are opened here when this browser
 *  holds the key; anything that cannot be read is listed rather than silently skipped,
 *  since the table would otherwise claim a value is in force that one of them overrides. */
async function loadBundleLayers(
  desired: DesiredStateView,
  keyUnlocked: boolean,
): Promise<BundleLayers> {
  const ordered = desired.bundles
    .map((b, i) => ({ b, i }))
    .sort((x, y) => x.b.priority - y.b.priority || x.i - y.i)
    .map(({ b }) => b);
  const out: BundleLayers = { layers: [], unreadable: [] };
  for (const b of ordered) {
    const label = `${b.name}@${b.version}`;
    try {
      let config: ConfigObject;
      if (b.format === "enc-v1") {
        const key = recalledKey();
        if (!key || !keyUnlocked) {
          out.unreadable.push({
            label,
            reason: "encrypted — unlock the key on the Bundles page to include its settings",
          });
          continue;
        }
        const sealed = await apiGetBytes(`/api/bundles/${b.id}/download`);
        const zip = await decryptBundle(key, b.name, b.version, sealed);
        config = readBundleZip(zip).configJson as ConfigObject;
      } else {
        const view = await apiGet<BundleConfigView>(`/api/bundles/${b.id}/config`);
        config = view.config_json as ConfigObject;
      }
      out.layers.push({ id: b.id, label, kind: "bundle", config });
    } catch (e) {
      out.unreadable.push({ label, reason: e instanceof Error ? e.message : String(e) });
    }
  }
  return out;
}

/** Shown in place of an override value that has not been revealed. */
const HIDDEN = "••••••";

const DRAFT_HEADER = `; This host's whole configuration: what its bundles give it, with the override applied.
; Change, add or delete settings here. Only what differs from the bundles is saved, as
; the host override; a setting deleted here is removed on this host.

`;

/** `ini` with every setting of `template`'s base document it does not have yet: picking a
 *  template adds its defaults without touching what the host already gets. */
function withTemplateDefaults(ini: string, templateIni: string): string {
  const have = layerConfigs([{ id: "draft", label: "", kind: "bundle", config: iniToJson(ini) }]);
  const seen = new Set(have.map((r) => `${r.section}\u0000${r.key}`));
  let out = ini;
  for (const r of layerConfigs([{ id: "t", label: "", kind: "bundle", config: iniToJson(templateIni) }])) {
    if (r.value !== null && !seen.has(`${r.section}\u0000${r.key}`)) {
      out = setIniValue(out, r.section, r.key, r.value);
    }
  }
  return out;
}

/** The host's configuration as the agent will write it — every setting with the bundle
 *  (or the override) it comes from and what it replaced — and the host override, edited
 *  as INI with a live preview in the same table.
 *
 *  The override usually holds credentials, so the page loads only its shape (which keys
 *  it sets or removes) and shows its values masked. They are fetched — an audited read —
 *  only when someone asks to see them or starts changing the override. */
export function HostConfigCard({ host, desired, desiredError, canWrite, onChanged }: Props) {
  const keyState = useBundleKey();
  const [bundles, setBundles] = useState<BundleLayers | null>(null);
  const [bundlesError, setBundlesError] = useState<string | null>(null);
  /** Which keys the override sets ("") or removes (null); no values. */
  const [shape, setShape] = useState<ConfigObject | null>(null);
  /** The override with its values, once someone has asked for them. */
  const [saved, setSaved] = useState<ConfigObject | null>(null);
  /** The template the saved override was written with (known once its values are). */
  const [savedTemplate, setSavedTemplate] = useState<string | null>(null);
  const [overrideError, setOverrideError] = useState<string | null>(null);

  const [editing, setEditing] = useState(false);
  /** Choosing a template, before (or while) editing. */
  const [picking, setPicking] = useState(false);
  /** The host's whole configuration as edited; the override is its difference from the
   *  bundles. */
  const [draftIni, setDraftIni] = useState("");
  const [draftTemplate, setDraftTemplate] = useState<string | null>(null);
  /** Removals the saved override makes, kept while nothing under them is set again. */
  const [keptRemovals, setKeptRemovals] = useState<Removal[]>([]);
  const [busy, setBusy] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [filter, setFilter] = useState("");

  const hasOverride = host.override_meta !== null;

  useEffect(() => {
    if (!desired) return;
    let live = true;
    loadBundleLayers(desired, keyState.unlocked).then(
      (b) => {
        if (!live) return;
        setBundles(b);
        setBundlesError(null);
      },
      (e) => live && setBundlesError(String(e)),
    );
    return () => {
      live = false;
    };
  }, [desired?.state_hash, keyState.unlocked]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    setSaved(null);
    if (!canWrite || !hasOverride) {
      setShape(null);
      return;
    }
    let live = true;
    apiGet<HostOverrideView>(`/api/hosts/${host.id}/override/shape`).then(
      (o) => {
        if (!live) return;
        setShape(o.patch as ConfigObject);
        setOverrideError(null);
      },
      (e) => live && setOverrideError(`Could not read the override: ${e.message ?? e}`),
    );
    return () => {
      live = false;
    };
  }, [host.id, hasOverride, canWrite]);

  /** The override with its values: fetched (and audited) the first time it is needed. */
  const reveal = async (): Promise<{ patch: ConfigObject; template: string | null }> => {
    if (saved) return { patch: saved, template: savedTemplate };
    if (!hasOverride) return { patch: {}, template: null };
    try {
      const o = await apiGet<HostOverrideView>(`/api/hosts/${host.id}/override`);
      setSaved(o.patch as ConfigObject);
      setSavedTemplate(o.template);
      setOverrideError(null);
      return { patch: o.patch as ConfigObject, template: o.template };
    } catch (e) {
      const msg = `Could not read the override: ${e instanceof Error ? e.message : String(e)}`;
      setOverrideError(msg);
      throw new Error(msg);
    }
  };

  /** What the bundles alone give this host: the override is the draft's difference from it. */
  const baseline = useMemo(
    () => (bundles ? configFromRows(layerConfigs(bundles.layers)) : null),
    [bundles],
  );

  // The override in the table: the draft while editing (when it parses), else what is saved.
  let parseError: string | null = null;
  let draftPatch: ConfigObject | null = null;
  if (editing && baseline) {
    try {
      draftPatch = overrideDiff(baseline, iniToJson(draftIni), keptRemovals);
    } catch (e) {
      parseError = e instanceof IniParseError ? e.message : String(e);
    }
  }
  const draftRemovals = draftPatch ? removalsOf(draftPatch) : [];
  const overridePatch = editing ? (draftPatch ?? saved) : (saved ?? shape);
  /** The table shows where the override wins, but not with what. */
  const valuesHidden = !editing && saved === null && shape !== null;
  const overrideLast = host.host_override_last !== false;

  const rows = useMemo(() => {
    if (!bundles) return null;
    const layers = [...bundles.layers];
    if (overridePatch && Object.keys(overridePatch).length > 0) {
      const ov: Layer = { id: "override", label: "host override", kind: "override", config: overridePatch };
      if (overrideLast) layers.push(ov);
      else layers.unshift(ov);
    }
    return layerConfigs(layers);
  }, [bundles, overridePatch, overrideLast]);

  // Override lines that change nothing: a value the bundles already give, or a removal of
  // something nothing sets. Worth saying — they are easy to leave behind.
  const noOps = useMemo(() => {
    if (!bundles || !overridePatch || valuesHidden) return [];
    const fromBundles = new Map(
      layerConfigs(bundles.layers).map((r) => [`${r.section}\u0000${r.key}`, r]),
    );
    const own = layerConfigs([
      { id: "override", label: "host override", kind: "override", config: overridePatch },
    ]);
    const out: string[] = [];
    for (const r of own) {
      const b = fromBundles.get(`${r.section}\u0000${r.key}`);
      if (r.value !== null && b && b.value === r.value) {
        out.push(`[${r.section}] ${r.key} is already ${r.value} from ${b.layer.label}`);
      }
    }
    for (const r of rows ?? []) {
      if (r.layer.kind === "override" && r.value === null && r.replaced.length === 0) {
        out.push(`removing ${removalLabel(removalFor(r.section, r.key))} removes nothing`);
      }
    }
    return out;
  }, [bundles, overridePatch, rows, valuesHidden]);

  /** Open the editor on the host's configuration as it stands, override included; a new
   *  override starts at the template picker, as a new bundle does. */
  const openEditor = async () => {
    if (!bundles || !baseline) return;
    let current: { patch: ConfigObject; template: string | null };
    try {
      current = await reveal();
    } catch {
      return;
    }
    const layers = [...bundles.layers];
    if (Object.keys(current.patch).length > 0) {
      layers.push({ id: "override", label: "host override", kind: "override", config: current.patch });
    }
    setDraftIni(DRAFT_HEADER + jsonToIni(configFromRows(layerConfigs(layers))));
    setDraftTemplate(current.template);
    setKeptRemovals(removalsOf(current.patch));
    setSaveError(null);
    setPicking(!hasOverride);
    setEditing(true);
  };

  /** Stop removing `r`: what it took away comes back with the bundles' values. */
  const restoreRemoval = (r: Removal) => {
    if (!baseline) return;
    let ini = draftIni;
    for (const b of removedBy(baseline, r)) ini = setIniValue(ini, b.section, b.key, b.value);
    setDraftIni(ini);
    setKeptRemovals(keptRemovals.filter((x) => !sameRemoval(x, r)));
  };

  const save = async () => {
    if (!draftPatch) return;
    setBusy(true);
    setSaveError(null);
    try {
      if (Object.keys(draftPatch).length === 0) {
        if (hasOverride) await apiSend("DELETE", `/api/hosts/${host.id}/override`);
      } else {
        await apiSend("PUT", `/api/hosts/${host.id}/override`, {
          patch: draftPatch,
          template: draftTemplate,
        });
      }
      const empty = Object.keys(draftPatch).length === 0;
      setSaved(empty ? null : draftPatch);
      setSavedTemplate(empty ? null : draftTemplate);
      setShape(empty ? null : shapeOf(draftPatch));
      setEditing(false);
      onChanged();
    } catch (e) {
      setSaveError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const remove = async () => {
    setBusy(true);
    try {
      await apiSend("DELETE", `/api/hosts/${host.id}/override`);
      setSaved(null);
      setShape(null);
      setEditing(false);
      setConfirmDelete(false);
      onChanged();
    } catch (e) {
      setSaveError(e instanceof Error ? e.message : String(e));
      setConfirmDelete(false);
    } finally {
      setBusy(false);
    }
  };

  const needle = filter.trim().toLowerCase();
  const shown = (rows ?? []).filter(
    (r) =>
      needle === "" ||
      `${r.section} ${r.key} ${r.value ?? ""} ${r.layer.label}`.toLowerCase().includes(needle),
  );
  const overrideInPlay = editing ? draftPatch !== null && Object.keys(draftPatch).length > 0 : hasOverride;

  return (
    <Card variant="outlined">
      <CardContent>
        <Stack direction="row" alignItems="center" spacing={2} sx={{ mb: 1 }} useFlexGap flexWrap="wrap">
          <Typography variant="h5" sx={{ flexGrow: 1 }}>
            Configuration
          </Typography>
          {hasOverride ? (
            <Chip label="host override set" color="secondary" size="small" />
          ) : (
            <Chip label="no host override" size="small" variant="outlined" />
          )}
          <TextField
            size="small"
            placeholder="Filter settings"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            slotProps={{
              input: {
                startAdornment: (
                  <InputAdornment position="start">
                    <SearchIcon fontSize="small" />
                  </InputAdornment>
                ),
              },
            }}
          />
        </Stack>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5 }}>
          What this host's agent writes to its fleet.ini: each setting with the bundle it comes
          from, lowest priority first, and the host override on top. The override is for this
          host alone and may hold secrets — it is encrypted at rest, its values stay hidden here
          until you ask for them, and each time they are shown that is recorded in the audit log.
        </Typography>

        {overrideInPlay && host.host_override_last === false && (
          <Alert severity="warning" sx={{ mb: 1.5 }}>
            This host's NSClient++ merges the override <strong>before</strong> its bundles, so a
            bundle that sets the same key wins. The table shows what is actually in force.
            Upgrade NSClient++ on this host to a build that applies the override last.
          </Alert>
        )}
        {overrideInPlay && host.host_override_last === null && (
          <Alert severity="info" sx={{ mb: 1.5 }}>
            This host has not yet reported whether it applies the override after its bundles.
            The table assumes it does; older NSClient++ builds let bundles win.
          </Alert>
        )}
        {!canWrite && hasOverride && (
          <Alert severity="info" sx={{ mb: 1.5 }}>
            This host has an override. Its contents are visible to admins only, so the table
            shows what the bundles give it.
          </Alert>
        )}
        {[desiredError && `Could not load this host's desired state: ${desiredError}`, bundlesError, overrideError]
          .filter((m): m is string => Boolean(m))
          .map((m) => (
            <Alert key={m} severity="error" sx={{ mb: 1.5 }}>
              {m}
            </Alert>
          ))}
        {bundles?.unreadable.map((u) => (
          <Alert key={u.label} severity="info" sx={{ mb: 1 }}>
            Not included: <strong>{u.label}</strong> — {u.reason}.
          </Alert>
        ))}

        {rows === null ? (
          !desiredError && <Typography color="text.secondary">Loading…</Typography>
        ) : rows.length === 0 ? (
          <Typography color="text.secondary" sx={{ mb: 2 }}>
            Nothing configured — no bundle applies to this host{hasOverride ? "" : " and it has no override"}.
          </Typography>
        ) : (
          <Table size="small" sx={{ mb: 2 }}>
            <TableHead>
              <TableRow>
                <TableCell>Section</TableCell>
                <TableCell>Key</TableCell>
                <TableCell>Value</TableCell>
                <TableCell>Set by</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {shown.map((r) => {
                const fromOverride = r.layer.kind === "override";
                const last = r.replaced[r.replaced.length - 1];
                return (
                  <TableRow key={`${r.section}\u0000${r.key}`} hover>
                    <TableCell sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{r.section}</TableCell>
                    <TableCell sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{r.key}</TableCell>
                    <TableCell sx={{ fontFamily: "monospace", fontSize: "0.8rem", wordBreak: "break-all" }}>
                      {r.value === null ? (
                        <Typography component="span" variant="body2" color="text.secondary">
                          {last ? <s>{last.value}</s> : null} removed on this host
                        </Typography>
                      ) : fromOverride && valuesHidden ? (
                        <Typography component="span" variant="body2" color="text.secondary">
                          {HIDDEN}
                        </Typography>
                      ) : (
                        r.value
                      )}
                      {r.value !== null && last && (
                        <Typography variant="caption" color="text.secondary" component="div">
                          replaces <s>{last.value}</s> from {last.layer.label}
                        </Typography>
                      )}
                    </TableCell>
                    <TableCell>
                      <Chip
                        size="small"
                        label={r.layer.label}
                        color={fromOverride ? "secondary" : "default"}
                        variant={fromOverride ? "filled" : "outlined"}
                      />
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        )}

        {canWrite && !editing && (
          <Stack direction="row" spacing={1}>
            <Button
              variant="outlined"
              size="small"
              startIcon={<EditIcon />}
              onClick={() => void openEditor()}
              disabled={baseline === null}
            >
              {hasOverride ? "Edit override" : "Add override"}
            </Button>
            {hasOverride &&
              (valuesHidden ? (
                <Tooltip title="Show the override's values here. Reading them is recorded in the audit log.">
                  <Button size="small" onClick={() => void reveal().catch(() => {})}>
                    Show values
                  </Button>
                </Tooltip>
              ) : (
                <Button size="small" onClick={() => setSaved(null)}>
                  Hide values
                </Button>
              ))}
            {hasOverride && (
              <Button size="small" color="error" onClick={() => setConfirmDelete(true)}>
                Delete override
              </Button>
            )}
          </Stack>
        )}

        {canWrite && editing && picking && (
          <Stack spacing={1.5}>
            <Typography variant="subtitle1">{hasOverride ? "Edit override" : "New override"}</Typography>
            <TemplatePicker
              intro={
                "Pick what to change on this host. A template adds its settings where the " +
                "host has none and opens its form; anything its bundles already set keeps " +
                "their value until you change it."
              }
              onPick={(t) => {
                if (t !== null) {
                  try {
                    setDraftIni(withTemplateDefaults(draftIni, t.ini));
                  } catch (e) {
                    setSaveError(e instanceof Error ? e.message : String(e));
                  }
                  setDraftTemplate(t.id);
                }
                setPicking(false);
              }}
              onCancel={() => {
                setPicking(false);
                if (!hasOverride && draftPatch !== null && Object.keys(draftPatch).length === 0) {
                  setEditing(false);
                }
              }}
            />
          </Stack>
        )}

        {canWrite && editing && !picking && (
          <Stack spacing={1.5}>
            <Stack direction="row" spacing={1} alignItems="center" useFlexGap flexWrap="wrap">
              <Typography variant="subtitle1" sx={{ flexGrow: 1 }}>
                Host override
              </Typography>
              {draftTemplate !== null ? (
                <Tooltip
                  title={
                    templateById(draftTemplate)?.description ??
                    "Written with a template this UI no longer knows. Remove to detach."
                  }
                >
                  <Chip
                    size="small"
                    variant="outlined"
                    label={`template: ${templateById(draftTemplate)?.title ?? draftTemplate}`}
                    onDelete={() => setDraftTemplate(null)}
                  />
                </Tooltip>
              ) : (
                <Button size="small" onClick={() => setPicking(true)}>
                  Use a template
                </Button>
              )}
            </Stack>
            <Typography variant="body2" color="text.secondary">
              This host's whole configuration — the table above previews the result. Only what
              you change is saved as the override; a setting you delete is removed on this host.
            </Typography>
            {bundles?.unreadable.length ? (
              <Alert severity="info">
                Settings from {bundles.unreadable.map((u) => u.label).join(", ")} are not shown
                here, so they cannot be removed; anything set here still wins over them.
              </Alert>
            ) : null}
            <ConfigEditor
              template={draftTemplate !== null ? templateById(draftTemplate) : undefined}
              ini={draftIni}
              onChange={setDraftIni}
              minRows={10}
            />
            {parseError && <Alert severity="error">{parseError}</Alert>}
            {draftRemovals.length > 0 && (
              <div>
                <Typography variant="body2" sx={{ mb: 0.5 }}>
                  Removed on this host
                </Typography>
                <Stack direction="row" spacing={1} useFlexGap flexWrap="wrap">
                  {draftRemovals.map((r) => (
                    <Tooltip key={r.join("/")} title="Keep it: back to what the bundles give">
                      <Chip
                        size="small"
                        label={removalLabel(r)}
                        sx={{ fontFamily: "monospace" }}
                        onDelete={() => restoreRemoval(r)}
                      />
                    </Tooltip>
                  ))}
                </Stack>
              </div>
            )}
            {noOps.length > 0 && (
              <Alert severity="info">
                These lines change nothing:
                <ul style={{ margin: "4px 0 0", paddingLeft: "1.2rem" }}>
                  {noOps.map((n) => (
                    <li key={n}>
                      <code>{n}</code>
                    </li>
                  ))}
                </ul>
              </Alert>
            )}
            {saveError && <Alert severity="error">{saveError}</Alert>}
            <Stack direction="row" spacing={1}>
              <Button
                variant="contained"
                onClick={save}
                disabled={busy || draftPatch === null || (!hasOverride && Object.keys(draftPatch).length === 0)}
              >
                {busy ? "Saving…" : "Save override"}
              </Button>
              <Button onClick={() => setEditing(false)} disabled={busy}>
                Cancel
              </Button>
            </Stack>
          </Stack>
        )}
      </CardContent>

      <Dialog open={confirmDelete} onClose={busy ? undefined : () => setConfirmDelete(false)}>
        <DialogTitle>Delete this host's override?</DialogTitle>
        <DialogContent>
          <DialogContentText>
            The host goes back to exactly what its bundles give it on its next poll. The
            override's settings are not kept anywhere else.
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setConfirmDelete(false)} disabled={busy}>
            Cancel
          </Button>
          <Button color="error" variant="contained" onClick={remove} disabled={busy}>
            Delete override
          </Button>
        </DialogActions>
      </Dialog>
    </Card>
  );
}
