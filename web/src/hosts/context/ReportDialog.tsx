import { useEffect, useMemo, useState } from "react";
import {
  Alert,
  Box,
  Button,
  Collapse,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TextField,
  Typography,
} from "@mui/material";
import {
  apiGet,
  ContextDetail,
  DiagnosticsCell,
  DiagnosticsColumn,
  DiagnosticsSection,
  fmtAgo,
  fmtBytes,
  FailureReport,
  SnapshotMeta,
} from "../../api";
import {
  CONTEXT_STATE_TEXT,
  ContextStateChip,
  DIAGNOSTICS_STATE_TEXT,
  DiagnosticsStateChip,
  ReportStatusChip,
} from "./ContextChips";

type Props = {
  hostId: string;
  /** The report to show; null keeps the dialog closed. */
  reportId: string | null;
  onClose: () => void;
};

/** One stored report: what the check said, and the diagnostics tables and the metrics
 *  snapshot that came with it. */
export function ReportDialog({ hostId, reportId, onClose }: Props) {
  const [detail, setDetail] = useState<ContextDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setDetail(null);
    setError(null);
    if (!reportId) return;
    apiGet<ContextDetail>(`/api/hosts/${hostId}/contexts/${reportId}`).then(setDetail, (e) =>
      setError(e instanceof Error ? e.message : String(e)),
    );
  }, [hostId, reportId]);

  return (
    <Dialog open={reportId !== null} onClose={onClose} maxWidth="lg" fullWidth>
      <DialogTitle>
        {detail ? (
          <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
            <code>{detail.command}</code>
            {detail.alias && detail.alias !== detail.command && (
              <Typography component="span" sx={{ color: "text.secondary" }}>
                {detail.alias}
              </Typography>
            )}
            <ReportStatusChip r={detail} />
            <Typography variant="body2" sx={{ color: "text.secondary" }}>
              reported {fmtAgo(detail.reported_at)}
            </Typography>
          </Stack>
        ) : (
          "Report"
        )}
      </DialogTitle>
      <DialogContent dividers>
        {error && <Alert severity="error">{error}</Alert>}
        {!detail && !error && <Typography>Loading…</Typography>}
        {detail && (
          <Stack spacing={3}>
            <CheckResult detail={detail} report={detail.report ?? {}} />
            <Diagnostics detail={detail} report={detail.report ?? {}} />
            <Snapshot detail={detail} report={detail.report ?? {}} />
            <RawReport report={detail.report} bytes={detail.payload_bytes} />
          </Stack>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Close</Button>
      </DialogActions>
    </Dialog>
  );
}

/** What the check said, with its perfdata. */
function CheckResult({ detail, report }: { detail: ContextDetail; report: FailureReport }) {
  const lines = report.failure?.lines ?? [];
  const perf = lines.flatMap((l) => Object.entries(l.perf ?? {}));
  const args = report.failure?.arguments;
  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        Check result
      </Typography>
      <Box
        component="pre"
        sx={{ m: 0, mb: 1, whiteSpace: "pre-wrap", wordBreak: "break-word", fontSize: "0.85rem" }}
      >
        {lines.length > 0 ? lines.map((l) => l.message ?? "").join("\n") : detail.message}
      </Box>
      {/* Absent means the agent does not record arguments — not that there were none. */}
      {args !== undefined && (
        <Typography variant="body2" sx={{ mb: 1 }}>
          Arguments: <code>{args.length ? args.join(" ") : "(none)"}</code>
        </Typography>
      )}
      {detail.subject && (
        <Typography variant="body2" sx={{ mb: 1, color: "text.secondary" }}>
          Run by {detail.subject}
        </Typography>
      )}
      {perf.length > 0 && (
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Perfdata</TableCell>
              <TableCell>Value</TableCell>
              <TableCell>Warning</TableCell>
              <TableCell>Critical</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {perf.map(([k, p], i) => (
              <TableRow key={`${i}:${k}`}>
                <TableCell>{k}</TableCell>
                <TableCell>
                  {String(p.value ?? "—")}
                  {p.unit ? ` ${p.unit}` : ""}
                </TableCell>
                <TableCell>{p.warning != null ? String(p.warning) : "—"}</TableCell>
                <TableCell>{p.critical != null ? String(p.critical) : "—"}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </Box>
  );
}

/** Byte-valued metrics read better scaled; everything else is shown as sent. */
function fmtMetric(v: unknown, meta: SnapshotMeta | undefined): string {
  if (typeof v === "number" && meta?.unit === "bytes") return `${fmtBytes(v)} (${v})`;
  const text = typeof v === "string" ? v : JSON.stringify(v);
  return meta?.unit ? `${text} ${meta.unit}` : text;
}

/** A table's name sorts it, except that the failures leading up to this one come first:
 *  the order the agent's own console shows them in. */
function sectionOrder([a]: [string, unknown], [b]: [string, unknown]): number {
  const first = "failures.recent";
  if (a === first || b === first) return a === b ? 0 : a === first ? -1 : 1;
  return a.localeCompare(b);
}

/** A cell the way its column says to read it. A missing value is a dash. */
function fmtCell(v: DiagnosticsCell | undefined, col: DiagnosticsColumn): string {
  if (v === null || v === undefined) return "—";
  if (typeof v === "number") {
    if (col.unit === "bytes") return fmtBytes(v);
    if (col.unit === "percent") return `${v}%`;
    return String(v);
  }
  if (typeof v === "string" && col.type === "timestamp") {
    const t = new Date(v);
    return Number.isNaN(t.getTime()) ? v : t.toLocaleString();
  }
  return String(v);
}

/** The exact value behind a cell that was scaled or localised for reading. */
function cellTitle(v: DiagnosticsCell | undefined, col: DiagnosticsColumn): string | undefined {
  if (typeof v === "number" && col.unit === "bytes") return `${v} bytes`;
  if (typeof v === "string" && col.type === "timestamp") return v;
  return undefined;
}

/** The diagnostics tables the agent held when the check failed: what was running and what
 *  went wrong, by name. */
function Diagnostics({ detail, report }: { detail: ContextDetail; report: FailureReport }) {
  const d = report.diagnostics;
  const sections = useMemo(() => Object.entries(d?.sections ?? {}).sort(sectionOrder), [d]);
  return (
    <Box>
      <Stack direction="row" spacing={1} sx={{ alignItems: "center", mb: 1 }}>
        <Typography variant="h6" sx={{ flexGrow: 1 }}>
          Diagnostics at the time
        </Typography>
        <DiagnosticsStateChip r={detail} />
      </Stack>
      {detail.diagnostics_state !== "captured" || sections.length === 0 ? (
        <Alert severity="info">
          {detail.diagnostics_state === "captured"
            ? "The agent captured diagnostics, but no table was switched on."
            : (DIAGNOSTICS_STATE_TEXT[detail.diagnostics_state] ??
              `No tables (${detail.diagnostics_state}).`)}
        </Alert>
      ) : (
        <>
          <Typography variant="body2" sx={{ color: "text.secondary", mb: 1 }}>
            {d?.snapshot_id != null && <>Snapshot #{d.snapshot_id} · </>}
            captured {d?.captured_at ? new Date(d.captured_at).toLocaleString() : "—"}
            {d?.age_seconds != null && <>, {d.age_seconds}s before the check failed</>}
          </Typography>
          <Stack spacing={2}>
            {sections.map(([name, section]) => (
              <DiagnosticsTable key={name} name={name} section={section} />
            ))}
          </Stack>
        </>
      )}
    </Box>
  );
}

function DiagnosticsTable({ name, section }: { name: string; section: DiagnosticsSection }) {
  const columns = section.columns ?? [];
  const rows = section.rows ?? [];
  return (
    <Box>
      <Typography variant="subtitle2">
        <code>{name}</code>
        {section.description && <> · {section.description}</>}
      </Typography>
      <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 0.5 }}>
        {/* A top list is always cut, so "10 rows" has to read as "at least 10". */}
        {section.truncated ? `first ${rows.length} rows` : `${rows.length} rows`}
        {section.source && <> · from {section.source}</>}
        {section.captured_at && <> · as of {new Date(section.captured_at).toLocaleString()}</>}
      </Typography>
      {/* Beside the rows, not instead of them: a table read from two logs carries one log's
          rows and the other's error. */}
      {section.error && (
        <Alert severity="warning" sx={{ mb: 0.5 }}>
          The agent could not collect all of this table: {section.error}
        </Alert>
      )}
      {rows.length === 0 ? (
        !section.error && (
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            No rows.
          </Typography>
        )
      ) : (
        <Box sx={{ overflowX: "auto" }}>
          <Table size="small">
            <TableHead>
              <TableRow>
                {columns.map((c) => (
                  <TableCell key={c.name} title={c.description}>
                    {c.name}
                  </TableCell>
                ))}
              </TableRow>
            </TableHead>
            <TableBody>
              {rows.map((row, i) => (
                <TableRow key={i} sx={{ verticalAlign: "top" }}>
                  {columns.map((c) => (
                    <TableCell
                      key={c.name}
                      title={cellTitle(row[c.name], c)}
                      sx={{
                        wordBreak: "break-word",
                        whiteSpace: typeof row[c.name] === "string" ? "pre-wrap" : "nowrap",
                      }}
                    >
                      {fmtCell(row[c.name], c)}
                    </TableCell>
                  ))}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Box>
      )}
    </Box>
  );
}

const PAGE = 100;

/** The metrics the agent held when the check failed. */
function Snapshot({ detail, report }: { detail: ContextDetail; report: FailureReport }) {
  const [filter, setFilter] = useState("");
  const [showAll, setShowAll] = useState(false);
  const ctx = report.context;
  const rows = useMemo(
    () => Object.entries(ctx?.metrics ?? {}).sort(([a], [b]) => a.localeCompare(b)),
    [ctx],
  );
  const needle = filter.trim().toLowerCase();
  const matching = needle
    ? rows.filter(
        ([k, v]) => k.toLowerCase().includes(needle) || String(v).toLowerCase().includes(needle),
      )
    : rows;
  const shown = showAll || needle ? matching : matching.slice(0, PAGE);

  return (
    <Box>
      <Stack direction="row" spacing={1} sx={{ alignItems: "center", mb: 1 }}>
        <Typography variant="h6" sx={{ flexGrow: 1 }}>
          Metrics snapshot
        </Typography>
        <ContextStateChip r={detail} />
      </Stack>
      {detail.context_state !== "captured" || !ctx?.metrics ? (
        <Alert severity="info">
          {CONTEXT_STATE_TEXT[detail.context_state] ?? `No snapshot (${detail.context_state}).`}
        </Alert>
      ) : (
        <>
          <Typography variant="body2" sx={{ color: "text.secondary", mb: 1 }}>
            {ctx.snapshot_id != null && <>Snapshot #{ctx.snapshot_id} · </>}
            captured {ctx.captured_at ? new Date(ctx.captured_at).toLocaleString() : "—"}
            {ctx.age_seconds != null && <>, {ctx.age_seconds}s before the check failed</>}
          </Typography>
          <TextField
            size="small"
            placeholder={`Filter ${rows.length} metrics`}
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            sx={{ mb: 1, minWidth: "20rem" }}
          />
          <Box sx={{ overflowX: "auto" }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Metric</TableCell>
                  <TableCell>Value</TableCell>
                  <TableCell>Type</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {shown.map(([k, v]) => {
                  const meta = ctx.metadata?.[k];
                  return (
                    <TableRow key={k}>
                      <TableCell sx={{ fontFamily: "monospace", wordBreak: "break-all" }}>
                        {k}
                      </TableCell>
                      <TableCell sx={{ wordBreak: "break-word" }}>{fmtMetric(v, meta)}</TableCell>
                      <TableCell sx={{ color: "text.secondary" }}>{meta?.type ?? ""}</TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </Box>
          {matching.length > shown.length && (
            <Button size="small" onClick={() => setShowAll(true)} sx={{ mt: 0.5 }}>
              Show all {matching.length}
            </Button>
          )}
          {needle && matching.length === 0 && (
            <Typography variant="body2" sx={{ color: "text.secondary", mt: 1 }}>
              No metric matches.
            </Typography>
          )}
        </>
      )}
    </Box>
  );
}

function RawReport({ report, bytes }: { report: FailureReport | null; bytes: number }) {
  const [open, setOpen] = useState(false);
  return (
    <Box>
      <Button size="small" onClick={() => setOpen(!open)}>
        {open ? "Hide" : "Show"} the report as sent ({fmtBytes(bytes)})
      </Button>
      <Collapse in={open} unmountOnExit>
        <Box
          component="pre"
          sx={{
            mt: 1,
            p: 1,
            bgcolor: "action.hover",
            overflow: "auto",
            maxHeight: "32rem",
            fontSize: "0.8rem",
          }}
        >
          {JSON.stringify(report, null, 2)}
        </Box>
      </Collapse>
    </Box>
  );
}
