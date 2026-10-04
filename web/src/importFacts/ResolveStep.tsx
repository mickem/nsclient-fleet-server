import { useMemo, useState } from "react";
import {
  Alert,
  Autocomplete,
  Box,
  Button,
  Checkbox,
  Chip,
  FormControlLabel,
  Link,
  Stack,
  Tab,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TablePagination,
  TableRow,
  Tabs,
  TextField,
  Typography,
} from "@mui/material";
import { alpha } from "@mui/material/styles";
import { Link as RouterLink } from "react-router-dom";
import type { HostView, ImportResolveResponse, ImportRowResult, ImportRowStatus } from "../api";
import { isBlocking } from "./model";

type Filter = "attention" | "all" | ImportRowStatus;

const STATUS_COLOR: Record<ImportRowStatus, "success" | "warning" | "error" | "default"> = {
  matched: "success",
  ambiguous: "warning",
  unmatched: "error",
  duplicate: "default",
  skipped: "default",
};

const PAGE_SIZES = [25, 100, 250];

const hostLabel = (h: HostView) => h.hostname ?? h.id;

export function ResolveStep({
  res,
  keyLabels,
  rowKeys,
  hosts,
  overrides,
  onOverride,
  skip,
  onSkip,
  prune,
  onPrune,
  busy,
  error,
  stale,
  onResolve,
  highlight,
}: {
  res: ImportResolveResponse | null;
  /** What each key column is matched against, for the header. */
  keyLabels: string[];
  /** Each row's key cells, as sent. */
  rowKeys: string[][];
  hosts: HostView[];
  overrides: Record<number, string>;
  onOverride: (index: number, hostId: string | null) => void;
  skip: ReadonlySet<number>;
  onSkip: (indices: number[], skipped: boolean) => void;
  prune: boolean;
  onPrune: (p: boolean) => void;
  busy: boolean;
  error: string | null;
  /** The mapping or host choices changed since `res` was computed. */
  stale: boolean;
  onResolve: () => void;
  /** Rows a refused commit named. */
  highlight: ReadonlySet<number>;
}) {
  const [filter, setFilter] = useState<Filter>("attention");
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(PAGE_SIZES[0]);
  const [showAbsent, setShowAbsent] = useState(false);
  const hostsById = useMemo(() => new Map(hosts.map((h) => [h.id, h])), [hosts]);

  const needsAttention = (r: ImportRowResult) => isBlocking(r) || highlight.has(r.index);

  const rows = (res?.rows ?? []).filter((r) =>
    filter === "all" ? true : filter === "attention" ? needsAttention(r) : r.status === filter,
  );

  if (!res) {
    return (
      <Stack spacing={2}>
        {error && <Alert severity="error">{error}</Alert>}
        <Typography>{busy ? "Resolving rows to hosts…" : "Not resolved yet."}</Typography>
        {!busy && (
          <Box>
            <Button variant="contained" onClick={onResolve}>
              Resolve
            </Button>
          </Box>
        )}
      </Stack>
    );
  }

  const attention = res.rows.filter(needsAttention).length;
  const shown = rows.slice(page * pageSize, (page + 1) * pageSize);
  const unmatchedOpen = res.rows.filter((r) => r.status === "unmatched" && !skip.has(r.index)).map((r) => r.index);
  const duplicatesOpen = res.rows.filter((r) => r.status === "duplicate" && !skip.has(r.index)).map((r) => r.index);
  const anyHolding = res.absent.some((a) => a.has_source) || res.absent_total > res.absent.length;
  const tab = (value: Filter, label: string, n: number) => (
    <Tab value={value} label={`${label} (${n.toLocaleString()})`} />
  );

  const hostCell = (r: ImportRowResult) => {
    switch (r.status) {
      case "matched":
        return (
          <Link component={RouterLink} to={`/hosts/${r.host_id}`} target="_blank">
            {r.hostname ?? r.host_id}
          </Link>
        );
      case "ambiguous":
        return (
          <Typography variant="body2" color="text.secondary">
            {r.host_ids.length} hosts:{" "}
            {r.host_ids
              .slice(0, 5)
              .map((id) => hostsById.get(id)?.hostname ?? id)
              .join(", ")}
            {r.host_ids.length > 5 && ", …"}
          </Typography>
        );
      case "duplicate":
        return (
          <Typography variant="body2" color="text.secondary">
            {hostsById.get(r.host_id)?.hostname ?? r.host_id} — same host as row {r.of + 1}
          </Typography>
        );
      case "unmatched":
        return (
          <Typography variant="body2" color="text.secondary">
            No host
          </Typography>
        );
      case "skipped":
        return (
          <Typography variant="body2" color="text.secondary">
            Not imported
          </Typography>
        );
    }
  };

  return (
    <Stack spacing={2}>
      {error && <Alert severity="error">{error}</Alert>}
      {stale && (
        <Alert
          severity="info"
          action={
            <Button color="inherit" size="small" onClick={onResolve} disabled={busy}>
              Resolve again
            </Button>
          }
        >
          The mapping, host choices or skips changed since these rows were resolved; resolve
          again to see what the server makes of them.
        </Alert>
      )}

      <Stack direction="row" spacing={1} alignItems="center" useFlexGap flexWrap="wrap">
        {(Object.keys(STATUS_COLOR) as ImportRowStatus[]).map((s) => (
          <Chip
            key={s}
            label={`${(res.stats[s] ?? 0).toLocaleString()} ${s}`}
            color={STATUS_COLOR[s]}
            variant={(res.stats[s] ?? 0) > 0 ? "filled" : "outlined"}
            size="small"
          />
        ))}
        <Box sx={{ flexGrow: 1 }} />
        <Button size="small" onClick={onResolve} disabled={busy}>
          {busy ? "Resolving…" : "Resolve again"}
        </Button>
      </Stack>

      <Tabs
        value={filter}
        onChange={(_, v: Filter) => {
          setFilter(v);
          setPage(0);
        }}
        variant="scrollable"
      >
        {tab("attention", "Needs attention", attention)}
        {tab("matched", "Matched", res.stats.matched)}
        {tab("unmatched", "Unmatched", res.stats.unmatched)}
        {tab("ambiguous", "Ambiguous", res.stats.ambiguous)}
        {tab("duplicate", "Duplicate", res.stats.duplicate)}
        {tab("skipped", "Skipped", res.stats.skipped ?? 0)}
        {tab("all", "All", res.rows.length)}
      </Tabs>

      <Stack direction="row" spacing={1} useFlexGap flexWrap="wrap">
        <Button size="small" disabled={unmatchedOpen.length === 0} onClick={() => onSkip(unmatchedOpen, true)}>
          Skip all unmatched ({unmatchedOpen.length})
        </Button>
        <Button size="small" disabled={duplicatesOpen.length === 0} onClick={() => onSkip(duplicatesOpen, true)}>
          Skip all duplicates ({duplicatesOpen.length})
        </Button>
        <Button size="small" color="inherit" disabled={skip.size === 0} onClick={() => onSkip([...skip], false)}>
          Clear skips ({skip.size})
        </Button>
      </Stack>

      {rows.length === 0 ? (
        <Typography color="text.secondary">
          {filter === "attention" ? "Every row is matched or skipped." : "No rows."}
        </Typography>
      ) : (
        <Box sx={{ border: 1, borderColor: "divider", borderRadius: 1 }}>
          <Box sx={{ overflowX: "auto" }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Row</TableCell>
                  <TableCell>{keyLabels.join(" · ")}</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>Host</TableCell>
                  <TableCell sx={{ minWidth: 260 }}>Assign host</TableCell>
                  <TableCell padding="checkbox">Skip</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {shown.map((r) => {
                  const override = overrides[r.index];
                  const pickable = (r.status !== "matched" && r.status !== "skipped") || override !== undefined;
                  const candidates = r.status === "ambiguous" ? new Set(r.host_ids) : null;
                  const value = override ? (hostsById.get(override) ?? null) : null;
                  return (
                    <TableRow
                      key={r.index}
                      sx={{
                        opacity: skip.has(r.index) ? 0.5 : 1,
                        bgcolor: highlight.has(r.index) ? (t) => alpha(t.palette.warning.main, 0.15) : undefined,
                      }}
                    >
                      <TableCell>{r.index + 1}</TableCell>
                      <TableCell sx={{ fontFamily: "monospace", wordBreak: "break-all" }}>
                        {(rowKeys[r.index] ?? []).map((k) => k || "∅").join(" · ")}
                      </TableCell>
                      <TableCell>
                        <Chip label={r.status} color={STATUS_COLOR[r.status]} size="small" variant="outlined" />
                        {override !== undefined && (
                          <Typography variant="caption" color="text.secondary" display="block">
                            assigned
                          </Typography>
                        )}
                      </TableCell>
                      <TableCell>{hostCell(r)}</TableCell>
                      <TableCell>
                        {pickable && (
                          <Autocomplete
                            size="small"
                            options={
                              candidates
                                ? [...hosts].sort(
                                    (a, b) => Number(candidates.has(b.id)) - Number(candidates.has(a.id)),
                                  )
                                : hosts
                            }
                            groupBy={candidates ? (h) => (candidates.has(h.id) ? "Candidates" : "Other hosts") : undefined}
                            value={value}
                            disabled={skip.has(r.index)}
                            onChange={(_, h) => onOverride(r.index, h?.id ?? null)}
                            getOptionLabel={hostLabel}
                            isOptionEqualToValue={(a, b) => a.id === b.id}
                            renderOption={(props, h) => {
                              const { key, ...rest } = props;
                              return (
                                <li key={key} {...rest}>
                                  <Stack>
                                    <Typography variant="body2">{hostLabel(h)}</Typography>
                                    <Typography variant="caption" color="text.secondary" sx={{ fontFamily: "monospace" }}>
                                      {h.id}
                                    </Typography>
                                  </Stack>
                                </li>
                              );
                            }}
                            renderInput={(params) => <TextField {...params} placeholder="Choose a host" />}
                          />
                        )}
                      </TableCell>
                      <TableCell padding="checkbox">
                        <Checkbox
                          size="small"
                          checked={skip.has(r.index)}
                          onChange={(e) => onSkip([r.index], e.target.checked)}
                        />
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </Box>
          <TablePagination
            component="div"
            count={rows.length}
            page={page}
            rowsPerPage={pageSize}
            rowsPerPageOptions={PAGE_SIZES}
            onPageChange={(_, p) => setPage(p)}
            onRowsPerPageChange={(e) => {
              setPageSize(Number(e.target.value));
              setPage(0);
            }}
          />
        </Box>
      )}

      <Box>
        <Typography variant="h6">Hosts not in this file</Typography>
        {res.absent_total === 0 ? (
          <Typography variant="body2" color="text.secondary">
            Every host in the fleet has a row.
          </Typography>
        ) : (
          <>
            <Typography variant="body2" color="text.secondary">
              {res.absent_total.toLocaleString()} host{res.absent_total === 1 ? "" : "s"} have no
              row in this file; they keep any {res.source} document they hold unless you remove it.{" "}
              <Button size="small" onClick={() => setShowAbsent((v) => !v)}>
                {showAbsent ? "Hide" : "Show"}
              </Button>
            </Typography>
            {showAbsent && (
              <Stack direction="row" spacing={0.5} useFlexGap flexWrap="wrap" sx={{ my: 1 }}>
                {res.absent.map((a) => (
                  <Chip
                    key={a.id}
                    size="small"
                    label={a.hostname ?? a.id}
                    variant={a.has_source ? "filled" : "outlined"}
                    title={a.has_source ? `Holds ${res.source}` : `Has no ${res.source} document`}
                    component={RouterLink}
                    to={`/hosts/${a.id}`}
                    target="_blank"
                    clickable
                  />
                ))}
                {res.absent_total > res.absent.length && (
                  <Typography variant="caption" color="text.secondary">
                    …and {(res.absent_total - res.absent.length).toLocaleString()} more
                  </Typography>
                )}
              </Stack>
            )}
            <FormControlLabel
              control={
                <Checkbox checked={prune} disabled={!anyHolding} onChange={(e) => onPrune(e.target.checked)} />
              }
              label={`Remove ${res.source} from the ${res.absent_total.toLocaleString()} host${
                res.absent_total === 1 ? "" : "s"
              } not in this file`}
            />
            {!anyHolding && (
              <Typography variant="caption" color="text.secondary" display="block">
                None of them holds {res.source}, so there is nothing to remove.
              </Typography>
            )}
          </>
        )}
      </Box>
    </Stack>
  );
}
