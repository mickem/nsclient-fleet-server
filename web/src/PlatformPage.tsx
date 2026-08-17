import { useEffect, useState } from "react";
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Collapse,
  Dialog,
  DialogActions,
  DialogContent,
  DialogContentText,
  DialogTitle,
  Divider,
  FormControlLabel,
  IconButton,
  LinearProgress,
  MenuItem,
  Stack,
  Switch,
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
import BlockIcon from "@mui/icons-material/Block";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import DeleteIcon from "@mui/icons-material/Delete";
import EditIcon from "@mui/icons-material/Edit";
import KeyboardArrowDownIcon from "@mui/icons-material/KeyboardArrowDown";
import KeyboardArrowRightIcon from "@mui/icons-material/KeyboardArrowRight";
import {
  apiGet,
  apiSend,
  CreateTenantResponse,
  fmtLimit,
  fmtTime,
  Me,
  PlatformSettings,
  PlatformTenantView,
  PlatformUserView,
  ROLE_LABELS,
  TierLimits,
  TierOverrides,
} from "./api";
import { RefreshButton } from "./RefreshButton";

/** The four numeric fields a tenant may have overridden, and how to label them. Kept in one
 *  place because the edit form, the "what does this tier grant" hint and the summary chip on
 *  each row all iterate the same list. */
const OVERRIDE_FIELDS: { key: keyof TierOverrides; label: string; unit?: string }[] = [
  { key: "max_hosts", label: "Max hosts" },
  { key: "min_poll_interval_secs", label: "Min poll interval", unit: "s" },
  { key: "per_host_requests_per_minute", label: "Requests / host / min" },
  { key: "max_bundle_mb", label: "Max bundle size", unit: "MB" },
];

const EMPTY_OVERRIDES: TierOverrides = {
  max_hosts: null,
  min_poll_interval_secs: null,
  per_host_requests_per_minute: null,
  max_bundle_mb: null,
};

/** Unix seconds ↔ the `yyyy-mm-dd` an `<input type="date">` speaks. A trial set for a given
 *  day is taken to run to the end of it, which is what a customer told "your trial ends on
 *  the 30th" expects. */
const toDateInput = (ts: number | null) => {
  if (!ts) return "";
  const d = new Date(ts * 1000);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
};
const fromDateInput = (s: string) =>
  s ? Math.floor(new Date(`${s}T23:59:59`).getTime() / 1000) : null;

const errText = (e: unknown) => (e instanceof Error ? e.message : String(e));

/**
 * Cross-tenant administration, for whoever operates the service rather than uses it.
 *
 * The nav entry is hidden without `me.is_platform_admin` and every route behind this page
 * checks the flag server-side, so this file never has to reason about who is allowed here —
 * only about what the operator can see and change.
 */
export function PlatformPage({ me }: { me: Me }) {
  const [tenants, setTenants] = useState<PlatformTenantView[] | null>(null);
  const [tiers, setTiers] = useState<TierLimits[]>([]);
  const [settings, setSettings] = useState<PlatformSettings | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [editing, setEditing] = useState<PlatformTenantView | null>(null);
  const [creating, setCreating] = useState(false);

  const refresh = () => {
    setRefreshing(true);
    setError(null);
    void Promise.all([
      apiGet<PlatformTenantView[]>("/api/platform/tenants"),
      apiGet<TierLimits[]>("/api/platform/tiers"),
      apiGet<PlatformSettings>("/api/platform/settings"),
    ])
      .then(([t, ti, s]) => {
        setTenants(t);
        setTiers(ti);
        setSettings(s);
      }, (e) => setError(errText(e)))
      .finally(() => setRefreshing(false));
  };
  useEffect(refresh, []);

  return (
    <Box>
      <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 1 }}>
        <Typography variant="h4">Platform</Typography>
        <RefreshButton refreshing={refreshing} onClick={refresh} />
      </Stack>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Every tenant on this install, their subscriptions and their users. Changes here apply
        on the affected tenant's next request — nobody has to sign in again.
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}
      {notice && (
        <Alert severity="success" sx={{ mb: 2 }} onClose={() => setNotice(null)}>
          {notice}
        </Alert>
      )}

      <SignupCard settings={settings} onChanged={setSettings} onError={setError} />

      <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 1 }}>
        <Typography variant="h6">Tenants</Typography>
        <Button variant="contained" startIcon={<AddIcon />} onClick={() => setCreating(true)}>
          New tenant
        </Button>
      </Stack>

      {tenants === null ? (
        <Typography>Loading…</Typography>
      ) : (
        <TableContainer component={Card}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell sx={{ width: 40 }} />
                <TableCell>Tenant</TableCell>
                <TableCell>Subscription</TableCell>
                <TableCell>Hosts</TableCell>
                <TableCell>Users</TableCell>
                <TableCell>Trial</TableCell>
                <TableCell>Created</TableCell>
                <TableCell />
              </TableRow>
            </TableHead>
            <TableBody>
              {tenants.map((t) => (
                <TenantRow
                  key={t.id}
                  me={me}
                  tenant={t}
                  onEdit={() => setEditing(t)}
                  onChanged={refresh}
                  onError={setError}
                />
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      {editing && (
        <SubscriptionDialog
          tenant={editing}
          tiers={tiers}
          onClose={() => setEditing(null)}
          onSaved={(name) => {
            setEditing(null);
            setNotice(`${name}'s subscription updated.`);
            refresh();
          }}
        />
      )}
      {creating && (
        <CreateTenantDialog
          tiers={tiers}
          onClose={() => setCreating(false)}
          onCreated={(res) => {
            setCreating(false);
            setNotice(
              res.owner_invited
                ? `${res.tenant.name} created — a sign-in link is on its way to its owner.`
                : `${res.tenant.name} created. No sign-in link went out; invite an owner, or ` +
                  `check the SMTP configuration if you asked for one.`,
            );
            refresh();
          }}
        />
      )}
    </Box>
  );
}

/** The one switch that is not per-tenant: whether strangers can create tenants themselves. */
function SignupCard({
  settings,
  onChanged,
  onError,
}: {
  settings: PlatformSettings | null;
  onChanged: (s: PlatformSettings) => void;
  onError: (e: string) => void;
}) {
  const [busy, setBusy] = useState(false);

  const toggle = async (enabled: boolean) => {
    setBusy(true);
    try {
      onChanged(await apiSend<PlatformSettings>("PUT", "/api/platform/settings", {
        signups_enabled: enabled,
      }));
    } catch (e) {
      onError(errText(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card variant="outlined" sx={{ mb: 3 }}>
      <CardContent>
        <Typography variant="h6" gutterBottom>
          Signups
        </Typography>
        <FormControlLabel
          control={
            <Switch
              checked={settings?.signups_enabled ?? false}
              disabled={busy || settings === null || settings.on_prem}
              onChange={(e) => void toggle(e.target.checked)}
            />
          }
          label="Allow self-service signups"
        />
        <Typography variant="body2" color="text.secondary">
          {settings?.on_prem
            ? "This is an on-prem install: signup and magic links are disabled outright, and the switch has nothing to do."
            : settings?.signups_enabled
              ? "Anyone can start a trial from the sign-in page. Turning this off leaves existing tenants untouched — and invitations keep working, so tenants can still add their own colleagues."
              : "The signup form is hidden and the endpoint refuses. New tenants come from New tenant below, or from an invitation into an existing tenant."}
        </Typography>
      </CardContent>
    </Card>
  );
}

function TenantRow({
  me,
  tenant,
  onEdit,
  onChanged,
  onError,
}: {
  me: Me;
  tenant: PlatformTenantView;
  onEdit: () => void;
  onChanged: () => void;
  onError: (e: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const overridden = OVERRIDE_FIELDS.filter((f) => tenant.overrides?.[f.key] != null);

  return (
    <>
      <TableRow hover>
        <TableCell>
          <IconButton size="small" onClick={() => setOpen(!open)} aria-label="show users">
            {open ? <KeyboardArrowDownIcon /> : <KeyboardArrowRightIcon />}
          </IconButton>
        </TableCell>
        <TableCell>
          <Typography variant="body2">{tenant.name}</Typography>
          <Typography variant="caption" color="text.secondary" component="code">
            {tenant.slug}
          </Typography>
          {tenant.id === me.tenant_id && <Chip label="yours" size="small" sx={{ ml: 1 }} />}
        </TableCell>
        <TableCell>
          <Stack direction="row" spacing={0.5} alignItems="center" useFlexGap flexWrap="wrap">
            <Chip label={tenant.tier} size="small" color="primary" variant="outlined" />
            {overridden.length > 0 && (
              <Tooltip
                title={overridden
                  .map((f) => `${f.label}: ${tenant.overrides?.[f.key]}${f.unit ?? ""}`)
                  .join(" · ")}
              >
                <Chip label={`${overridden.length} override${overridden.length > 1 ? "s" : ""}`} size="small" />
              </Tooltip>
            )}
          </Stack>
        </TableCell>
        <TableCell>
          <Stack direction="row" spacing={0.5} alignItems="center" useFlexGap flexWrap="wrap">
            <span>
              {tenant.host_count} / {fmtLimit(tenant.effective.max_hosts)}
            </span>
            {/* Only when there is something to say. A tenant whose hosts are all fully
                fleet-managed — or whose agents predate the flag — shows a plain count. */}
            {tenant.local_config_host_count > 0 && (
              <Tooltip
                title={
                  `${tenant.local_config_host_count} of this tenant's hosts carry configuration of ` +
                  "their own, which outranks anything the fleet sends them. Open the tenant's own " +
                  "Hosts page to see which."
                }
              >
                <Chip
                  label={`${tenant.local_config_host_count} local config`}
                  size="small"
                  color="warning"
                  variant="outlined"
                />
              </Tooltip>
            )}
          </Stack>
        </TableCell>
        <TableCell>
          {tenant.user_count}
          {tenant.blocked_user_count > 0 && (
            <Chip
              label={`${tenant.blocked_user_count} blocked`}
              size="small"
              color="warning"
              sx={{ ml: 1 }}
            />
          )}
        </TableCell>
        <TableCell>
          {tenant.trial_expires_at === null ? (
            <Chip label="none" size="small" variant="outlined" />
          ) : tenant.trial_expired ? (
            <Tooltip title={`Expired ${fmtTime(tenant.trial_expires_at)}`}>
              <Chip label="expired" size="small" color="error" />
            </Tooltip>
          ) : (
            <Tooltip title={fmtTime(tenant.trial_expires_at)}>
              <Chip
                label={`${Math.max(
                  0,
                  Math.ceil((tenant.trial_expires_at - Date.now() / 1000) / 86400),
                )}d left`}
                size="small"
                color="info"
              />
            </Tooltip>
          )}
        </TableCell>
        <TableCell>{fmtTime(tenant.created_at)}</TableCell>
        <TableCell align="right">
          <Button size="small" startIcon={<EditIcon fontSize="small" />} onClick={onEdit}>
            Subscription
          </Button>
        </TableCell>
      </TableRow>
      <TableRow>
        <TableCell sx={{ py: 0, borderBottom: open ? undefined : "none" }} colSpan={8}>
          <Collapse in={open} unmountOnExit>
            <Box sx={{ my: 2 }}>
              <TenantUsers tenantId={tenant.id} onChanged={onChanged} onError={onError} />
            </Box>
          </Collapse>
        </TableCell>
      </TableRow>
    </>
  );
}

/**
 * A tenant's users, fetched when the row is expanded rather than with the tenant list —
 * the estate could be large, and most rows are never opened.
 */
function TenantUsers({
  tenantId,
  onChanged,
  onError,
}: {
  tenantId: number;
  onChanged: () => void;
  onError: (e: string) => void;
}) {
  const [users, setUsers] = useState<PlatformUserView[] | null>(null);
  const [busyId, setBusyId] = useState<number | null>(null);

  const load = () => {
    void apiGet<PlatformUserView[]>(`/api/platform/tenants/${tenantId}/users`).then(
      setUsers,
      (e) => onError(errText(e)),
    );
  };
  useEffect(load, [tenantId]);

  // Every action refreshes both this list and the tenant table above it, because blocking or
  // removing someone changes the counts shown on the parent row.
  const act = async (id: number, fn: () => Promise<unknown>) => {
    setBusyId(id);
    try {
      await fn();
      load();
      onChanged();
    } catch (e) {
      onError(errText(e));
    } finally {
      setBusyId(null);
    }
  };

  if (users === null) return <LinearProgress />;
  if (users.length === 0) {
    return (
      <Typography variant="body2" color="text.secondary">
        No users — nobody can sign into this tenant. Its owner has to be invited from inside
        it, or the tenant deleted directly in the database.
      </Typography>
    );
  }

  return (
    <Table size="small">
      <TableHead>
        <TableRow>
          <TableCell>Email</TableCell>
          <TableCell>Role</TableCell>
          <TableCell>Added</TableCell>
          <TableCell>Platform admin</TableCell>
          <TableCell />
        </TableRow>
      </TableHead>
      <TableBody>
        {users.map((u) => {
          const blocked = u.blocked_at !== null;
          return (
            <TableRow key={u.id}>
              <TableCell>
                {u.email}
                {u.is_self && <Chip label="you" size="small" sx={{ ml: 1 }} />}
                {blocked && (
                  <Tooltip title={`Blocked ${fmtTime(u.blocked_at)}`}>
                    <Chip label="blocked" size="small" color="warning" sx={{ ml: 1 }} />
                  </Tooltip>
                )}
              </TableCell>
              <TableCell>{ROLE_LABELS[u.role]}</TableCell>
              <TableCell>{fmtTime(u.created_at)}</TableCell>
              <TableCell>
                <Tooltip
                  title={
                    u.is_self
                      ? "You cannot drop your own platform-admin flag."
                      : "Grants access to this console for every tenant."
                  }
                >
                  <span>
                    <Switch
                      size="small"
                      checked={u.is_platform_admin}
                      disabled={u.is_self || busyId === u.id}
                      onChange={(e) =>
                        void act(u.id, () =>
                          apiSend("PATCH", `/api/platform/users/${u.id}`, {
                            platform_admin: e.target.checked,
                          }),
                        )
                      }
                    />
                  </span>
                </Tooltip>
              </TableCell>
              <TableCell align="right">
                <Stack direction="row" spacing={1} justifyContent="flex-end">
                  <Tooltip
                    title={
                      u.is_self
                        ? "You cannot block your own account."
                        : blocked
                          ? "Let them sign in again."
                          : "Signs them out immediately and stops their API keys, without deleting anything."
                    }
                  >
                    <span>
                      <Button
                        size="small"
                        color={blocked ? "success" : "warning"}
                        disabled={u.is_self || busyId === u.id}
                        startIcon={
                          blocked ? (
                            <CheckCircleIcon fontSize="small" />
                          ) : (
                            <BlockIcon fontSize="small" />
                          )
                        }
                        onClick={() =>
                          void act(u.id, () =>
                            apiSend("PATCH", `/api/platform/users/${u.id}`, { blocked: !blocked }),
                          )
                        }
                      >
                        {blocked ? "Unblock" : "Block"}
                      </Button>
                    </span>
                  </Tooltip>
                  <Tooltip
                    title={
                      u.is_self
                        ? "You cannot delete your own account."
                        : "Deletes the account and its API keys. Audit entries are kept, without attribution."
                    }
                  >
                    <span>
                      <Button
                        size="small"
                        color="error"
                        disabled={u.is_self || busyId === u.id}
                        startIcon={<DeleteIcon fontSize="small" />}
                        onClick={() => {
                          if (
                            !confirm(
                              `Remove ${u.email}? This cannot be undone — block them instead if it might need reversing.`,
                            )
                          )
                            return;
                          void act(u.id, () => apiSend("DELETE", `/api/platform/users/${u.id}`));
                        }}
                      >
                        Remove
                      </Button>
                    </span>
                  </Tooltip>
                </Stack>
              </TableCell>
            </TableRow>
          );
        })}
      </TableBody>
    </Table>
  );
}

/**
 * Edit a tenant's subscription: the named tier, the trial deadline, and numeric overrides
 * on top of the tier. The form is submitted whole — the API replaces all three, so what is
 * on screen when Save is pressed is exactly what the tenant ends up with.
 */
function SubscriptionDialog({
  tenant,
  tiers,
  onClose,
  onSaved,
}: {
  tenant: PlatformTenantView;
  tiers: TierLimits[];
  onClose: () => void;
  onSaved: (tenantName: string) => void;
}) {
  const [tier, setTier] = useState(tenant.tier);
  const [trial, setTrial] = useState(toDateInput(tenant.trial_expires_at));
  const [overrides, setOverrides] = useState<TierOverrides>(tenant.overrides ?? EMPTY_OVERRIDES);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const base = tiers.find((t) => t.name === tier);

  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      await apiSend("PUT", `/api/platform/tenants/${tenant.id}/subscription`, {
        tier,
        trial_expires_at: fromDateInput(trial),
        overrides,
      });
      onSaved(tenant.name);
    } catch (e) {
      setError(errText(e));
      setBusy(false);
    }
  };

  return (
    <Dialog open onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>{tenant.name} — subscription</DialogTitle>
      <DialogContent>
        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}
        <Stack spacing={3} sx={{ mt: 1 }}>
          <TextField
            select
            label="Tier"
            value={tier}
            onChange={(e) => setTier(e.target.value)}
            helperText={
              base
                ? `${fmtLimit(base.max_hosts)} hosts · poll every ${base.min_poll_interval_secs}s · ` +
                  `${base.per_host_requests_per_minute} req/host/min · ${base.max_bundle_mb} MB bundles`
                : "Tiers are defined in code and applied on the tenant's next request."
            }
            fullWidth
          >
            {tiers.map((t) => (
              <MenuItem key={t.name} value={t.name}>
                {t.name}
              </MenuItem>
            ))}
          </TextField>

          <TextField
            label="Trial ends"
            type="date"
            value={trial}
            onChange={(e) => setTrial(e.target.value)}
            slotProps={{ inputLabel: { shrink: true } }}
            helperText="Leave blank for a tenant that has paid. Past this date every API call from the tenant is refused with 402 until it is changed."
            fullWidth
          />

          <Divider />
          <Box>
            <Typography variant="subtitle2" gutterBottom>
              Limit overrides
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              Blank inherits the tier's value, shown as the placeholder. Use these for a
              one-off arrangement rather than to invent a new tier.
            </Typography>
            <Stack spacing={2}>
              {OVERRIDE_FIELDS.map((f) => (
                <TextField
                  key={f.key}
                  label={f.label}
                  type="number"
                  size="small"
                  value={overrides[f.key] ?? ""}
                  placeholder={base ? String(base[f.key]) : ""}
                  slotProps={{ inputLabel: { shrink: true }, htmlInput: { min: 0 } }}
                  onChange={(e) =>
                    setOverrides({
                      ...overrides,
                      [f.key]: e.target.value === "" ? null : Number(e.target.value),
                    })
                  }
                  helperText={f.unit ? `in ${f.unit}` : undefined}
                  fullWidth
                />
              ))}
            </Stack>
          </Box>
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={busy}>
          Cancel
        </Button>
        <Button variant="contained" onClick={save} disabled={busy}>
          {busy ? "Saving…" : "Save"}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

/** Create a tenant by hand — the way a tenant comes into being when self-service signup is
 *  closed, or when one is provisioned ahead of the customer arriving. */
function CreateTenantDialog({
  tiers,
  onClose,
  onCreated,
}: {
  tiers: TierLimits[];
  onClose: () => void;
  onCreated: (res: CreateTenantResponse) => void;
}) {
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [slugTouched, setSlugTouched] = useState(false);
  const [tier, setTier] = useState("free");
  const [trialDays, setTrialDays] = useState("14");
  const [ownerEmail, setOwnerEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Suggest a slug from the name until the operator types one themselves. Same rules the
  // server enforces, so the suggestion is never one it would refuse.
  const suggest = (v: string) =>
    v
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 63);

  const create = async () => {
    setBusy(true);
    setError(null);
    try {
      onCreated(
        await apiSend<CreateTenantResponse>("POST", "/api/platform/tenants", {
          slug: slug.trim(),
          name: name.trim(),
          tier,
          trial_days: trialDays.trim() === "" ? null : Number(trialDays),
          owner_email: ownerEmail.trim() || null,
        }),
      );
    } catch (e) {
      setError(errText(e));
      setBusy(false);
    }
  };

  return (
    <Dialog open onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>New tenant</DialogTitle>
      <DialogContent>
        <DialogContentText variant="body2" sx={{ mb: 2 }}>
          Creates the tenant along with its certificate authority and bundle-signing key. With
          an owner address it also emails that person a sign-in link — the only way anyone
          gets into a new tenant.
        </DialogContentText>
        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}
        <Stack spacing={3} sx={{ mt: 1 }}>
          <TextField
            label="Name"
            value={name}
            onChange={(e) => {
              setName(e.target.value);
              if (!slugTouched) setSlug(suggest(e.target.value));
            }}
            placeholder="Acme Corp"
            autoFocus
            required
            fullWidth
          />
          <TextField
            label="Slug"
            value={slug}
            onChange={(e) => {
              setSlugTouched(true);
              setSlug(e.target.value);
            }}
            placeholder="acme"
            required
            fullWidth
            helperText="a-z, 0-9 and dashes. Goes into the tenant's certificate authority and cannot be changed afterwards."
          />
          <TextField
            select
            label="Tier"
            value={tier}
            onChange={(e) => setTier(e.target.value)}
            fullWidth
          >
            {tiers.map((t) => (
              <MenuItem key={t.name} value={t.name}>
                {t.name} — {fmtLimit(t.max_hosts)} hosts
              </MenuItem>
            ))}
          </TextField>
          <TextField
            label="Trial days"
            type="number"
            value={trialDays}
            onChange={(e) => setTrialDays(e.target.value)}
            slotProps={{ htmlInput: { min: 0 } }}
            helperText="Blank for no trial deadline — the shape for a tenant that has already paid."
            fullWidth
          />
          <TextField
            label="Owner email"
            type="email"
            value={ownerEmail}
            onChange={(e) => setOwnerEmail(e.target.value)}
            placeholder="boss@acme.example"
            helperText="Optional. Without one the tenant exists but nobody can sign into it yet."
            fullWidth
          />
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={busy}>
          Cancel
        </Button>
        <Button
          variant="contained"
          onClick={create}
          disabled={busy || !name.trim() || !slug.trim()}
        >
          {busy ? "Creating…" : "Create tenant"}
        </Button>
      </DialogActions>
    </Dialog>
  );
}
