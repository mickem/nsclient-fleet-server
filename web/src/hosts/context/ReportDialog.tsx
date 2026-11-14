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
import { apiGet, ContextDetail, fmtAgo, fmtBytes, FailureReport, SnapshotMeta } from "../../api";
import { CONTEXT_STATE_TEXT, ContextStateChip, ReportStatusChip } from "./ContextChips";

type Props = {
  hostId: string;
  /** The report to show; null keeps the dialog closed. */
  reportId: string | null;
  onClose: () => void;
};

/** One stored report: what the check said, and the metrics snapshot that came with it. */
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
