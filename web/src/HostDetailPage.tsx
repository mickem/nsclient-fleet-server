import { useEffect, useState } from "react";
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Grid,
  IconButton,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TextField,
  Typography,
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import DeleteIcon from "@mui/icons-material/Delete";
import { ConfirmDeleteHostDialog } from "./ConfirmDeleteHostDialog";
import { HostStatusChip, LocalConfigChip } from "./HostStatusChip";
import { RefreshButton } from "./RefreshButton";
import {
  apiGet,
  apiSend,
  canWriteConfig,
  DesiredStateView,
  fmtAgo,
  fmtTime,
  HostDetail,
  Me,
} from "./api";

type Props = { me: Me; hostId: string; onBack: () => void };

/** The enrolment clause of the summary line — what happened, or what still needs to.
 *  The live states all share it: the chip beside the hostname carries what they add. */
function enrollmentSummary(host: HostDetail): string {
  switch (host.status) {
    case "in_sync":
    case "out_of_sync":
    case "offline":
    case "lost":
      return `enrolled ${fmtTime(host.enrolled_at)}`;
    case "awaiting_enrollment":
      return `install command not run yet — token expires ${fmtTime(host.bootstrap_expires_at)}`;
    case "never_enrolled":
      return host.bootstrap_expires_at
        ? `never enrolled — token expired ${fmtTime(host.bootstrap_expires_at)}`
        : "never enrolled";
  }
}

export function HostDetailPage({ me, hostId, onBack }: Props) {
  const [host, setHost] = useState<HostDetail | null>(null);
  const [desired, setDesired] = useState<DesiredStateView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);

  // Returns void, not the promise: `useEffect` below takes this directly, and a returned
  // promise would be mistaken for a cleanup function.
  const refresh = () => {
    setRefreshing(true);
    void Promise.all([
      apiGet<HostDetail>(`/api/hosts/${hostId}`).then(
        (h) => {
          setHost(h);
          setError(null);
        },
        (e) => setError(e.message),
      ),
      apiGet<DesiredStateView>(`/api/hosts/${hostId}/desired`).then(setDesired, () => {}),
    ]).finally(() => setRefreshing(false));
  };
  useEffect(refresh, [hostId]);

  // Only the initial load takes over the page. Once a host is on screen a failed refresh
  // reports itself inline instead of discarding what the operator was looking at.
  if (error && !host) {
    return (
      <Box>
        <Button startIcon={<ArrowBackIcon />} onClick={onBack}>
          Back
        </Button>
        <Alert severity="error" sx={{ mt: 2 }}>
          {error}
        </Alert>
      </Box>
    );
  }
  if (!host) {
    return (
      <Box>
        <Button startIcon={<ArrowBackIcon />} onClick={onBack}>
          Back
        </Button>
        <Typography sx={{ mt: 2 }}>Loading…</Typography>
      </Box>
    );
  }

  return (
    <Box>
      <Stack direction="row" alignItems="center" spacing={2} sx={{ mb: 1 }}>
        <Button startIcon={<ArrowBackIcon />} onClick={onBack}>
          Hosts
        </Button>
        <Stack direction="row" alignItems="center" spacing={1} sx={{ flexGrow: 1 }}>
          <Typography variant="h4">{host.hostname ?? host.id}</Typography>
          <HostStatusChip host={host} />
        </Stack>
        <RefreshButton refreshing={refreshing} onClick={refresh} />
        {canWriteConfig(me.role) && (
          <Button
            color="error"
            variant="outlined"
            startIcon={<DeleteIcon />}
            onClick={() => setConfirmDelete(true)}
          >
            Delete host
          </Button>
        )}
      </Stack>
      <ConfirmDeleteHostDialog
        host={confirmDelete ? { id: host.id, hostname: host.hostname } : null}
        onClose={() => setConfirmDelete(false)}
        onDeleted={onBack}
      />
      {error && (
        <Alert severity="warning" sx={{ mb: 2 }} onClose={() => setError(null)}>
          Refresh failed — showing the last loaded state. {error}
        </Alert>
      )}
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        <code>{host.id}</code> · {host.os ?? "unknown os"} · {enrollmentSummary(host)} · last seen{" "}
        {fmtAgo(host.last_seen_at)}
      </Typography>

      <Grid container spacing={2}>
        <Grid size={{ xs: 12, md: 6 }}>
          <DesiredCard host={host} desired={desired} />
        </Grid>
        <Grid size={{ xs: 12, md: 6 }}>
          <TagsCard host={host} canWrite={canWriteConfig(me.role)} onChanged={refresh} />
        </Grid>
        <Grid size={{ xs: 12, md: 6 }}>
          <OverrideCard host={host} canWrite={canWriteConfig(me.role)} onChanged={refresh} />
        </Grid>
      </Grid>
    </Box>
  );
}

/**
 * What the fleet wants this host to run, and whether it is running it.
 *
 * The local-configuration line sits here rather than anywhere else because it is the caveat
 * to "In sync": that chip only says the host applied the state we sent, and a host with local
 * configuration applies it and then overrides part of it. Unlike the hosts list this
 * distinguishes "reported none" from "never reported" — silence is not a denial, and an
 * operator asking why a change had no effect deserves to be told which one they are seeing.
 */
function DesiredCard({ host, desired }: { host: HostDetail; desired: DesiredStateView | null }) {
  const localConfig =
    host.local_config_present === true ? (
      <Stack direction="row" spacing={1} alignItems="center" sx={{ mt: 1 }}>
        <LocalConfigChip host={host} />
        <Typography variant="caption" color="text.secondary">
          Local settings on the host take precedence over what is shown here.
        </Typography>
      </Stack>
    ) : (
      <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 1 }}>
        {host.local_config_present === false
          ? "No local configuration — this host is entirely fleet-managed."
          : "Local configuration: not reported by this agent."}
      </Typography>
    );

  return (
    <Card variant="outlined" sx={{ height: "100%" }}>
      <CardContent>
        <Typography variant="h5" gutterBottom>
          Configuration state
        </Typography>
        {!desired ? (
          <Typography>Loading…</Typography>
        ) : (
          <>
            <Stack direction="row" spacing={1} alignItems="center">
              {desired.in_sync ? (
                <Chip label="In sync" color="success" size="small" />
              ) : (
                <Chip label="Out of sync" color="warning" size="small" />
              )}
              <Typography variant="caption" color="text.secondary">
                desired hash <code>{desired.state_hash.slice(0, 12)}…</code>
              </Typography>
            </Stack>
            <Box sx={{ mb: 2 }}>{localConfig}</Box>
            {desired.bundles.length === 0 ? (
              <Typography variant="body2" color="text.secondary">
                No bundles apply to this host — it matches no group with assignments.
              </Typography>
            ) : (
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Bundle</TableCell>
                    <TableCell>Version</TableCell>
                    <TableCell>Priority</TableCell>
                    <TableCell>sha256</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {desired.bundles.map((b) => (
                    <TableRow key={b.id}>
                      <TableCell>{b.name}</TableCell>
                      <TableCell>{b.version}</TableCell>
                      <TableCell>{b.priority}</TableCell>
                      <TableCell>
                        <Typography variant="caption" component="code">
                          {b.sha256.slice(0, 12)}…
                        </Typography>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </>
        )}
      </CardContent>
    </Card>
  );
}

function TagsCard({
  host,
  canWrite,
  onChanged,
}: {
  host: HostDetail;
  canWrite: boolean;
  onChanged: () => void;
}) {
  const [key, setKey] = useState("");
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | null>(null);

  const save = async () => {
    if (!key.trim()) return;
    setError(null);
    try {
      await apiSend("PUT", `/api/hosts/${host.id}/tags/${encodeURIComponent(key.trim())}`, {
        value: value.trim(),
      });
      setKey("");
      setValue("");
      onChanged();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const remove = async (k: string) => {
    setError(null);
    try {
      await apiSend("DELETE", `/api/hosts/${host.id}/tags/${encodeURIComponent(k)}`);
      onChanged();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <Card variant="outlined" sx={{ height: "100%" }}>
      <CardContent>
        <Typography variant="h5" gutterBottom>
          Tags
        </Typography>
        {error && (
          <Alert severity="error" sx={{ mb: 1 }}>
            {error}
          </Alert>
        )}
        <Stack direction="row" spacing={1} useFlexGap sx={{ flexWrap: "wrap", mb: 2 }}>
          {host.tags.length === 0 && (
            <Typography variant="body2" color="text.secondary">
              No tags.
            </Typography>
          )}
          {host.tags.map((t) =>
            t.source === "agent" ? (
              <Chip
                key={`a:${t.key}`}
                label={`${t.key}=${t.value}`}
                size="small"
                color="info"
                variant="outlined"
                title="reported by the agent"
              />
            ) : (
              <Chip
                key={`m:${t.key}`}
                label={`${t.key}=${t.value}`}
                size="small"
                color="primary"
                onDelete={canWrite ? () => remove(t.key) : undefined}
              />
            ),
          )}
        </Stack>
        {canWrite && (
        <Stack direction="row" spacing={1}>
          <TextField
            size="small"
            label="key"
            value={key}
            onChange={(e) => setKey(e.target.value)}
            placeholder="role"
          />
          <TextField
            size="small"
            label="value"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder="sql_server"
          />
          <Button variant="contained" onClick={save} disabled={!key.trim()}>
            Set
          </Button>
        </Stack>
        )}
        <Typography variant="caption" color="text.secondary">
          Outlined chips are agent-reported (read-only); solid chips are manual.
        </Typography>
      </CardContent>
    </Card>
  );
}

function OverrideCard({
  host,
  canWrite,
  onChanged,
}: {
  host: HostDetail;
  canWrite: boolean;
  onChanged: () => void;
}) {
  const [editing, setEditing] = useState(false);
  const [patch, setPatch] = useState("{}");
  const [priority, setPriority] = useState("1000");
  const [error, setError] = useState<string | null>(null);

  const save = async () => {
    setError(null);
    let parsed: unknown;
    try {
      parsed = JSON.parse(patch);
    } catch {
      setError("Patch is not valid JSON");
      return;
    }
    try {
      await apiSend("PUT", `/api/hosts/${host.id}/override`, {
        patch: parsed,
        priority: parseInt(priority, 10) || 1000,
      });
      setEditing(false);
      onChanged();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const remove = async () => {
    setError(null);
    try {
      await apiSend("DELETE", `/api/hosts/${host.id}/override`);
      onChanged();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <Card variant="outlined" sx={{ height: "100%" }}>
      <CardContent>
        <Typography variant="h5" gutterBottom>
          Host override
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
          A JSON Merge Patch applied only to this host, above all group bundles. May contain
          secrets — encrypted at rest, never logged, write-only from here.
        </Typography>
        {error && (
          <Alert severity="error" sx={{ mb: 1 }}>
            {error}
          </Alert>
        )}
        {host.override_meta && !editing && (
          <Stack direction="row" spacing={1} alignItems="center">
            <Chip
              label={`Override set (priority ${host.override_meta.priority})`}
              color="secondary"
              size="small"
            />
            {canWrite && (
              <>
                <Button size="small" onClick={() => setEditing(true)}>
                  Replace
                </Button>
                <IconButton size="small" onClick={remove} title="Delete override">
                  <DeleteIcon fontSize="small" />
                </IconButton>
              </>
            )}
          </Stack>
        )}
        {!host.override_meta && !editing && canWrite && (
          <Button variant="outlined" size="small" onClick={() => setEditing(true)}>
            Add override
          </Button>
        )}
        {!host.override_meta && !editing && !canWrite && (
          <Typography variant="body2" color="text.secondary">
            No override set.
          </Typography>
        )}
        {editing && (
          <Stack spacing={1}>
            <TextField
              multiline
              minRows={5}
              value={patch}
              onChange={(e) => setPatch(e.target.value)}
              slotProps={{ input: { sx: { fontFamily: "monospace", fontSize: "0.85rem" } } }}
            />
            <Stack direction="row" spacing={1} alignItems="center">
              <TextField
                size="small"
                label="Priority"
                value={priority}
                onChange={(e) => setPriority(e.target.value)}
                sx={{ width: "8rem" }}
              />
              <Button variant="contained" onClick={save}>
                Save override
              </Button>
              <Button onClick={() => setEditing(false)}>Cancel</Button>
            </Stack>
          </Stack>
        )}
      </CardContent>
    </Card>
  );
}
