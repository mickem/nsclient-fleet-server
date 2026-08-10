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
import { apiGet, apiSend, DesiredStateView, fmtAgo, fmtTime, HostDetail } from "./api";

type Props = { hostId: string; onBack: () => void };

export function HostDetailPage({ hostId, onBack }: Props) {
  const [host, setHost] = useState<HostDetail | null>(null);
  const [desired, setDesired] = useState<DesiredStateView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);

  const refresh = () => {
    apiGet<HostDetail>(`/api/hosts/${hostId}`).then(setHost, (e) => setError(e.message));
    apiGet<DesiredStateView>(`/api/hosts/${hostId}/desired`).then(setDesired, () => {});
  };
  useEffect(refresh, [hostId]);

  if (error) {
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
        <Typography variant="h4" sx={{ flexGrow: 1 }}>
          {host.hostname ?? host.id}
        </Typography>
        <Button
          color="error"
          variant="outlined"
          startIcon={<DeleteIcon />}
          onClick={() => setConfirmDelete(true)}
        >
          Delete host
        </Button>
      </Stack>
      <ConfirmDeleteHostDialog
        host={confirmDelete ? { id: host.id, hostname: host.hostname } : null}
        onClose={() => setConfirmDelete(false)}
        onDeleted={onBack}
      />
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        <code>{host.id}</code> · {host.os ?? "unknown os"} ·{" "}
        {host.enrolled_at ? `enrolled ${fmtTime(host.enrolled_at)}` : "pending enrollment"} · last
        seen {fmtAgo(host.last_seen_at)}
      </Typography>

      <Grid container spacing={2}>
        <Grid size={{ xs: 12, md: 6 }}>
          <DesiredCard desired={desired} />
        </Grid>
        <Grid size={{ xs: 12, md: 6 }}>
          <TagsCard host={host} onChanged={refresh} />
        </Grid>
        <Grid size={{ xs: 12, md: 6 }}>
          <OverrideCard host={host} onChanged={refresh} />
        </Grid>
      </Grid>
    </Box>
  );
}

function DesiredCard({ desired }: { desired: DesiredStateView | null }) {
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
            <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1 }}>
              {desired.in_sync ? (
                <Chip label="In sync" color="success" size="small" />
              ) : (
                <Chip label="Out of sync" color="warning" size="small" />
              )}
              <Typography variant="caption" color="text.secondary">
                desired hash <code>{desired.state_hash.slice(0, 12)}…</code>
              </Typography>
            </Stack>
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

function TagsCard({ host, onChanged }: { host: HostDetail; onChanged: () => void }) {
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
                onDelete={() => remove(t.key)}
              />
            ),
          )}
        </Stack>
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
        <Typography variant="caption" color="text.secondary">
          Outlined chips are agent-reported (read-only); solid chips are manual.
        </Typography>
      </CardContent>
    </Card>
  );
}

function OverrideCard({ host, onChanged }: { host: HostDetail; onChanged: () => void }) {
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
            <Button size="small" onClick={() => setEditing(true)}>
              Replace
            </Button>
            <IconButton size="small" onClick={remove} title="Delete override">
              <DeleteIcon fontSize="small" />
            </IconButton>
          </Stack>
        )}
        {!host.override_meta && !editing && (
          <Button variant="outlined" size="small" onClick={() => setEditing(true)}>
            Add override
          </Button>
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
