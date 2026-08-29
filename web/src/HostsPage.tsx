import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Alert,
  Autocomplete,
  Box,
  Button,
  Card,
  CardContent,
  Checkbox,
  Chip,
  IconButton,
  MenuItem,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Typography,
} from "@mui/material";
import AddIcon from "@mui/icons-material/Add";
import CloseIcon from "@mui/icons-material/Close";
import DeleteIcon from "@mui/icons-material/Delete";
import LabelIcon from "@mui/icons-material/Label";
import LabelOffIcon from "@mui/icons-material/LabelOff";
import {
  apiGet,
  apiSend,
  canAddHosts,
  canWriteConfig,
  CreateHostResponse,
  fmtAgo,
  HostStatus,
  HostView,
  Me,
} from "./api";
import { BulkAddTagDialog, BulkDeleteDialog, BulkRemoveTagDialog } from "./BulkHostDialogs";
import { ConfirmDeleteHostDialog } from "./ConfirmDeleteHostDialog";
import { HostStatusChip, LocalConfigChip } from "./HostStatusChip";
import { RefreshButton } from "./RefreshButton";

type Props = { me: Me };

/** The concrete statuses plus the two composites an operator actually sweeps by: "everything
 *  that ever became an agent" and "everything we are not hearing from". */
type StatusFilter = "all" | "enrolled" | "silent" | HostStatus;

const STATUS_FILTERS: { value: StatusFilter; label: string }[] = [
  { value: "all", label: "All statuses" },
  { value: "awaiting_enrollment", label: "Awaiting enrollment" },
  { value: "never_enrolled", label: "Never enrolled" },
  { value: "enrolled", label: "Enrolled (any)" },
  { value: "in_sync", label: "In sync" },
  { value: "out_of_sync", label: "Out of sync" },
  { value: "offline", label: "Offline" },
  { value: "lost", label: "Lost" },
  { value: "silent", label: "Offline or lost" },
];

const matchesStatus = (h: HostView, f: StatusFilter): boolean => {
  switch (f) {
    case "all":
      return true;
    case "enrolled":
      return h.status === "in_sync" || h.status === "out_of_sync" || h.status === "offline" || h.status === "lost";
    case "silent":
      return h.status === "offline" || h.status === "lost";
    default:
      return h.status === f;
  }
};

type BulkDialog = "delete" | "add-tag" | "remove-tag" | null;

export function HostsPage({ me }: Props) {
  const navigate = useNavigate();
  const [hosts, setHosts] = useState<HostView[] | null>(null);
  const [issued, setIssued] = useState<CreateHostResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [toDelete, setToDelete] = useState<HostView | null>(null);

  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [tagKey, setTagKey] = useState<string | null>(null);
  const [tagValue, setTagValue] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [bulkDialog, setBulkDialog] = useState<BulkDialog>(null);

  const canWrite = canWriteConfig(me.role);

  // Returns void, not the promise: `useEffect` below takes this directly, and a returned
  // promise would be mistaken for a cleanup function. `hosts` is left in place while the
  // fetch is in flight, so the table stays on screen rather than flashing back to "Loading…".
  const refresh = () => {
    setRefreshing(true);
    setError(null);
    void apiGet<HostView[]>("/api/hosts")
      .then(setHosts, (e) => setError(String(e.message)))
      .finally(() => setRefreshing(false));
  };
  useEffect(refresh, []);

  const addHost = async () => {
    setBusy(true);
    setError(null);
    try {
      setIssued(await apiSend<CreateHostResponse>("POST", "/api/hosts", {}));
      refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const tagKeys = useMemo(
    () => [...new Set((hosts ?? []).flatMap((h) => h.tags.map((t) => t.key)))].sort(),
    [hosts],
  );
  const tagValues = useMemo(
    () =>
      tagKey === null
        ? []
        : [
            ...new Set(
              (hosts ?? []).flatMap((h) =>
                h.tags.filter((t) => t.key === tagKey).map((t) => t.value),
              ),
            ),
          ].sort(),
    [hosts, tagKey],
  );

  const filtered = useMemo(
    () =>
      (hosts ?? []).filter(
        (h) =>
          matchesStatus(h, statusFilter) &&
          (tagKey === null ||
            h.tags.some((t) => t.key === tagKey && (tagValue === null || t.value === tagValue))),
      ),
    [hosts, statusFilter, tagKey, tagValue],
  );

  // The selection is always a subset of the visible rows. Anything a filter change or a
  // refresh hides is dropped, so a bulk action can never touch a host the operator cannot
  // currently see.
  const filteredIds = useMemo(() => new Set(filtered.map((h) => h.id)), [filtered]);
  useEffect(() => {
    setSelected((prev) => {
      const next = new Set([...prev].filter((id) => filteredIds.has(id)));
      return next.size === prev.size ? prev : next;
    });
  }, [filteredIds]);

  const toggle = (id: string) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (!next.delete(id)) next.add(id);
      return next;
    });
  const toggleAll = () =>
    setSelected((prev) => (prev.size === filtered.length ? new Set() : new Set(filteredIds)));

  const selectedIds = useMemo(() => [...selected], [selected]);
  const removableKeys = useMemo(
    () =>
      [
        ...new Set(
          (hosts ?? [])
            .filter((h) => selected.has(h.id))
            .flatMap((h) => h.tags.filter((t) => t.source === "manual").map((t) => t.key)),
        ),
      ].sort(),
    [hosts, selected],
  );

  const onBulkDone = (result: { updated: number; not_found: string[] }) => {
    setBulkDialog(null);
    setSelected(new Set());
    if (result.not_found.length > 0) {
      setError(
        `${result.not_found.length} of the selected hosts no longer exist — ` +
          "they may have been deleted elsewhere. The rest were processed.",
      );
    }
    refresh();
  };

  const filtering = statusFilter !== "all" || tagKey !== null;

  return (
    <Box>
      <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 2 }}>
        <Typography variant="h4">Hosts</Typography>
        <Stack direction="row" spacing={1} alignItems="center">
          <RefreshButton refreshing={refreshing} onClick={refresh} />
          {canAddHosts(me.role) && (
            <Button variant="contained" startIcon={<AddIcon />} onClick={addHost} disabled={busy}>
              {busy ? "Issuing token…" : "Add host"}
            </Button>
          )}
        </Stack>
      </Stack>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {issued && (
        <Card sx={{ mb: 2 }}>
          <CardContent>
            <Stack direction="row" justifyContent="space-between" alignItems="flex-start">
              <Typography variant="h5" gutterBottom>
                Install command
              </Typography>
              <IconButton size="small" onClick={() => setIssued(null)}>
                <CloseIcon fontSize="small" />
              </IconButton>
            </Stack>
            <Typography variant="body2" color="text.secondary">
              Run this on the host — the token expires in 1 hour and can be used once.
            </Typography>
            <Box
              component="pre"
              sx={{
                overflowX: "auto",
                p: 1.5,
                mt: 1,
                bgcolor: "#0D1117",
                borderRadius: 1,
                fontSize: "0.85rem",
              }}
            >
              {issued.install_command}
            </Box>
            <Typography variant="caption" color="text.secondary">
              host_id: <code>{issued.host_id}</code>
            </Typography>
          </CardContent>
        </Card>
      )}

      {hosts !== null && hosts.length > 0 && (
        <Stack direction="row" spacing={1} alignItems="center" useFlexGap flexWrap="wrap" sx={{ mb: 2 }}>
          <TextField
            select
            size="small"
            label="Status"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value as StatusFilter)}
            sx={{ minWidth: 190 }}
          >
            {STATUS_FILTERS.map((f) => (
              <MenuItem key={f.value} value={f.value}>
                {f.label}
              </MenuItem>
            ))}
          </TextField>
          <Autocomplete
            size="small"
            options={tagKeys}
            value={tagKey}
            onChange={(_, v) => {
              setTagKey(v);
              setTagValue(null);
            }}
            renderInput={(params) => <TextField {...params} label="Tag" />}
            sx={{ minWidth: 180 }}
          />
          <Autocomplete
            size="small"
            options={tagValues}
            value={tagValue}
            onChange={(_, v) => setTagValue(v)}
            disabled={tagKey === null}
            renderInput={(params) => <TextField {...params} label="Value (any)" />}
            sx={{ minWidth: 180 }}
          />
          {filtering && (
            <Typography variant="body2" color="text.secondary">
              {filtered.length} of {hosts.length} hosts
            </Typography>
          )}
        </Stack>
      )}

      {selected.size > 0 && (
        <Stack direction="row" spacing={1} alignItems="center" useFlexGap flexWrap="wrap" sx={{ mb: 2 }}>
          <Typography variant="body2" sx={{ fontWeight: 500 }}>
            {selected.size} selected
          </Typography>
          <Button size="small" startIcon={<LabelIcon />} onClick={() => setBulkDialog("add-tag")}>
            Add tag
          </Button>
          <Button
            size="small"
            startIcon={<LabelOffIcon />}
            onClick={() => setBulkDialog("remove-tag")}
          >
            Remove tag
          </Button>
          <Button
            size="small"
            color="error"
            startIcon={<DeleteIcon />}
            onClick={() => setBulkDialog("delete")}
          >
            Delete
          </Button>
          <Button size="small" color="inherit" onClick={() => setSelected(new Set())}>
            Clear
          </Button>
        </Stack>
      )}

      {hosts === null ? (
        <Typography>Loading…</Typography>
      ) : hosts.length === 0 ? (
        <Card>
          <CardContent>
            <Typography color="text.secondary">
              No hosts yet. Click "Add host" to get a one-line install command.
            </Typography>
          </CardContent>
        </Card>
      ) : filtered.length === 0 ? (
        <Card>
          <CardContent>
            <Typography color="text.secondary">No hosts match the current filters.</Typography>
          </CardContent>
        </Card>
      ) : (
        <TableContainer component={Card}>
          <Table size="small">
            <TableHead>
              <TableRow>
                {canWrite && (
                  <TableCell padding="checkbox">
                    <Checkbox
                      size="small"
                      checked={selected.size === filtered.length && filtered.length > 0}
                      indeterminate={selected.size > 0 && selected.size < filtered.length}
                      onChange={toggleAll}
                    />
                  </TableCell>
                )}
                <TableCell>Hostname</TableCell>
                <TableCell>OS</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Tags</TableCell>
                <TableCell>Last seen</TableCell>
                <TableCell>Host ID</TableCell>
                <TableCell />
              </TableRow>
            </TableHead>
            <TableBody>
              {filtered.map((h) => (
                <TableRow
                  key={h.id}
                  hover
                  onClick={() => navigate(`/hosts/${h.id}`)}
                  selected={selected.has(h.id)}
                  sx={{ cursor: "pointer" }}
                >
                  {canWrite && (
                    <TableCell padding="checkbox">
                      <Checkbox
                        size="small"
                        checked={selected.has(h.id)}
                        onClick={(e) => e.stopPropagation()}
                        onChange={() => toggle(h.id)}
                      />
                    </TableCell>
                  )}
                  <TableCell>{h.hostname ?? <em>(not reported)</em>}</TableCell>
                  <TableCell>{h.os ?? "—"}</TableCell>
                  <TableCell>
                    <Stack direction="row" spacing={0.5} alignItems="center" useFlexGap flexWrap="wrap">
                      <HostStatusChip host={h} />
                      <LocalConfigChip host={h} />
                    </Stack>
                  </TableCell>
                  <TableCell>
                    <Stack direction="row" spacing={0.5} useFlexGap flexWrap="wrap">
                      {h.tags.map((t) => (
                        <Chip
                          key={`${t.source}:${t.key}`}
                          label={`${t.key}=${t.value}`}
                          size="small"
                          variant={t.source === "manual" ? "filled" : "outlined"}
                          title={
                            (t.source === "manual"
                              ? "Set by an operator."
                              : "Reported by the agent.") + " Click to filter by this tag."
                          }
                          onClick={(e) => {
                            e.stopPropagation();
                            setTagKey(t.key);
                            setTagValue(t.value);
                          }}
                        />
                      ))}
                    </Stack>
                  </TableCell>
                  <TableCell>{fmtAgo(h.last_seen_at)}</TableCell>
                  <TableCell>
                    <Typography variant="caption" component="code">
                      {h.id}
                    </Typography>
                  </TableCell>
                  <TableCell align="right">
                    {canWrite && (
                      <IconButton
                        size="small"
                        title="Delete host"
                        onClick={(e) => {
                          e.stopPropagation();
                          setToDelete(h);
                        }}
                      >
                        <DeleteIcon fontSize="small" />
                      </IconButton>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      <ConfirmDeleteHostDialog
        host={toDelete}
        onClose={() => setToDelete(null)}
        onDeleted={() => {
          setToDelete(null);
          refresh();
        }}
      />
      <BulkDeleteDialog
        hostIds={selectedIds}
        open={bulkDialog === "delete"}
        onClose={() => setBulkDialog(null)}
        onDone={onBulkDone}
      />
      <BulkAddTagDialog
        hostIds={selectedIds}
        open={bulkDialog === "add-tag"}
        onClose={() => setBulkDialog(null)}
        onDone={onBulkDone}
      />
      <BulkRemoveTagDialog
        hostIds={selectedIds}
        open={bulkDialog === "remove-tag"}
        onClose={() => setBulkDialog(null)}
        onDone={onBulkDone}
        keyOptions={removableKeys}
      />
    </Box>
  );
}
