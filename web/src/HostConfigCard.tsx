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
  IconButton,
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
import RemoveCircleOutlineIcon from "@mui/icons-material/RemoveCircleOutline";
import SearchIcon from "@mui/icons-material/Search";
import UndoIcon from "@mui/icons-material/Undo";
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
import {
  EffectiveRow,
  joinOverride,
  Layer,
  layerConfigs,
  Removal,
  removalFor,
  removalLabel,
  sameRemoval,
  splitOverride,
} from "./hostConfig";
import { type ConfigObject, IniParseError, removeIniKey, setIniValue } from "./ini";

type Props = {
  host: HostDetail;
  desired: DesiredStateView | null;
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

/** The host's configuration as the agent will write it — every setting with the bundle
 *  (or the override) it comes from and what it replaced — and the host override, edited
 *  as INI with a live preview in the same table. */
export function HostConfigCard({ host, desired, canWrite, onChanged }: Props) {
  const keyState = useBundleKey();
  const [bundles, setBundles] = useState<BundleLayers | null>(null);
  const [saved, setSaved] = useState<ConfigObject | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  const [editing, setEditing] = useState(false);
  const [draftIni, setDraftIni] = useState("");
  const [draftRemovals, setDraftRemovals] = useState<Removal[]>([]);
  const [busy, setBusy] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [filter, setFilter] = useState("");

  const hasOverride = host.override_meta !== null;

  useEffect(() => {
    if (!desired) return;
    let live = true;
    loadBundleLayers(desired, keyState.unlocked).then(
      (b) => live && setBundles(b),
      (e) => live && setLoadError(String(e)),
    );
    return () => {
      live = false;
    };
  }, [desired?.state_hash, keyState.unlocked]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!canWrite || !hasOverride) {
      setSaved(null);
      return;
    }
    let live = true;
    apiGet<HostOverrideView>(`/api/hosts/${host.id}/override`).then(
      (o) => live && setSaved(o.patch as ConfigObject),
      (e) => live && setLoadError(`Could not read the override: ${e.message ?? e}`),
    );
    return () => {
      live = false;
    };
  }, [host.id, hasOverride, canWrite]);

  // The override in the table: the draft while editing (when it parses), else what is saved.
  let parseError: string | null = null;
  let draftPatch: ConfigObject | null = null;
  if (editing) {
    try {
      draftPatch = joinOverride(draftIni, draftRemovals);
    } catch (e) {
      parseError = e instanceof IniParseError ? e.message : String(e);
    }
  }
  const overridePatch = editing ? (draftPatch ?? saved) : saved;
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
    if (!bundles || !overridePatch) return [];
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
  }, [bundles, overridePatch, rows]);

  const openEditor = () => {
    if (editing) return;
    const split = saved ? splitOverride(saved) : { ini: "", removals: [] };
    setDraftIni(split.ini);
    setDraftRemovals(split.removals);
    setSaveError(null);
    setEditing(true);
  };
  // Row actions edit the draft, opening the editor first when needed. The draft has to be
  // seeded synchronously, so these read the saved override directly when not yet editing.
  const draftBase = () =>
    editing
      ? { ini: draftIni, removals: draftRemovals }
      : saved
        ? splitOverride(saved)
        : { ini: "", removals: [] as Removal[] };
  const editDraft = (f: (d: { ini: string; removals: Removal[] }) => { ini: string; removals: Removal[] }) => {
    const next = f(draftBase());
    setDraftIni(next.ini);
    setDraftRemovals(next.removals);
    setSaveError(null);
    setEditing(true);
  };
  const overrideRow = (r: EffectiveRow) =>
    editDraft((d) => ({
      ini: setIniValue(d.ini, r.section, r.key, r.value ?? r.replaced[r.replaced.length - 1]?.value ?? ""),
      removals: d.removals.filter((x) => !sameRemoval(x, removalFor(r.section, r.key))),
    }));
  const removeRow = (r: EffectiveRow) =>
    editDraft((d) => ({
      ini: removeIniKey(d.ini, r.section, r.key),
      removals: [...d.removals.filter((x) => !sameRemoval(x, removalFor(r.section, r.key))), removalFor(r.section, r.key)],
    }));
  const revertRow = (r: EffectiveRow) =>
    editDraft((d) => ({
      ini: removeIniKey(d.ini, r.section, r.key),
      removals: d.removals.filter((x) => !sameRemoval(x, removalFor(r.section, r.key))),
    }));

  const save = async () => {
    if (!draftPatch) return;
    setBusy(true);
    setSaveError(null);
    try {
      if (Object.keys(draftPatch).length === 0) {
        if (hasOverride) await apiSend("DELETE", `/api/hosts/${host.id}/override`);
      } else {
        await apiSend("PUT", `/api/hosts/${host.id}/override`, { patch: draftPatch });
      }
      setSaved(Object.keys(draftPatch).length === 0 ? null : draftPatch);
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
          host alone and may hold secrets — it is encrypted at rest and never logged.
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
        {loadError && (
          <Alert severity="error" sx={{ mb: 1.5 }}>
            {loadError}
          </Alert>
        )}
        {bundles?.unreadable.map((u) => (
          <Alert key={u.label} severity="info" sx={{ mb: 1 }}>
            Not included: <strong>{u.label}</strong> — {u.reason}.
          </Alert>
        ))}

        {rows === null ? (
          <Typography color="text.secondary">Loading…</Typography>
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
                {canWrite && <TableCell />}
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
                    {canWrite && (
                      <TableCell align="right" sx={{ whiteSpace: "nowrap" }}>
                        {fromOverride ? (
                          <Tooltip title="Stop overriding: back to what the bundles give">
                            <IconButton size="small" onClick={() => revertRow(r)}>
                              <UndoIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                        ) : (
                          <>
                            <Tooltip title="Override this value on this host">
                              <IconButton size="small" onClick={() => overrideRow(r)}>
                                <EditIcon fontSize="small" />
                              </IconButton>
                            </Tooltip>
                            <Tooltip title="Remove this key on this host">
                              <IconButton size="small" onClick={() => removeRow(r)}>
                                <RemoveCircleOutlineIcon fontSize="small" />
                              </IconButton>
                            </Tooltip>
                          </>
                        )}
                      </TableCell>
                    )}
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        )}

        {canWrite && !editing && (
          <Stack direction="row" spacing={1}>
            <Button variant="outlined" size="small" startIcon={<EditIcon />} onClick={openEditor}>
              {hasOverride ? "Edit override" : "Add override"}
            </Button>
            {hasOverride && (
              <Button size="small" color="error" onClick={() => setConfirmDelete(true)}>
                Delete override
              </Button>
            )}
          </Stack>
        )}

        {canWrite && editing && (
          <Stack spacing={1.5}>
            <Typography variant="subtitle1">Host override</Typography>
            <Typography variant="body2" color="text.secondary">
              Settings for this host only, as INI — the table above previews the result. Use
              the row buttons to override or remove a bundle's setting.
            </Typography>
            <TextField
              multiline
              minRows={6}
              value={draftIni}
              onChange={(e) => setDraftIni(e.target.value)}
              placeholder={"[/settings/mysql]\npassword = …"}
              error={parseError !== null}
              helperText={parseError ?? " "}
              slotProps={{ input: { sx: { fontFamily: "monospace", fontSize: "0.85rem" } } }}
            />
            {draftRemovals.length > 0 && (
              <div>
                <Typography variant="body2" sx={{ mb: 0.5 }}>
                  Removed on this host
                </Typography>
                <Stack direction="row" spacing={1} useFlexGap flexWrap="wrap">
                  {draftRemovals.map((r) => (
                    <Chip
                      key={r.join("/")}
                      size="small"
                      label={removalLabel(r)}
                      sx={{ fontFamily: "monospace" }}
                      onDelete={() => setDraftRemovals(draftRemovals.filter((x) => !sameRemoval(x, r)))}
                    />
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
              <Button variant="contained" onClick={save} disabled={busy || parseError !== null}>
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
