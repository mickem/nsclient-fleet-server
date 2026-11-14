import { useState } from "react";
import { Link as RouterLink } from "react-router-dom";
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  IconButton,
  Link,
  MenuItem,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TextField,
  Typography,
} from "@mui/material";
import DeleteIcon from "@mui/icons-material/Delete";
import {
  ApiError,
  apiSend,
  ContextSummary,
  EvidenceRef,
  ExplainRequest,
  ExplainResponse,
  fmtAgo,
  fmtTime,
  HostDetail,
} from "../../api";
import { ContextStateChip, ReportStatusChip } from "./ContextChips";
import { ReportDialog } from "./ReportDialog";

/** The check selector's value for "work it out from the error text". */
const AUTO = "";

type Props = {
  host: HostDetail;
  reports: ContextSummary[] | null;
  reportsError: string | null;
  canWrite: boolean;
  onChanged: () => void;
};

/**
 * Context for errors on this host: paste an error from the monitoring system and have it
 * explained against the host's latest snapshot and facts, and see the reports the agent sent.
 *
 * Not an alert list. The monitoring system owns the alert; this tab only holds the evidence.
 */
export function ContextTab({ host, reports, reportsError, canWrite, onChanged }: Props) {
  const [openReport, setOpenReport] = useState<string | null>(null);
  return (
    <Stack spacing={2}>
      <ExplainCard host={host} reports={reports ?? []} onOpenReport={setOpenReport} />
      <ReportsCard
        host={host}
        reports={reports}
        error={reportsError}
        canWrite={canWrite}
        onOpen={setOpenReport}
        onChanged={onChanged}
      />
      <ReportDialog hostId={host.id} reportId={openReport} onClose={() => setOpenReport(null)} />
    </Stack>
  );
}

function ExplainCard({
  host,
  reports,
  onOpenReport,
}: {
  host: HostDetail;
  reports: ContextSummary[];
  onOpenReport: (id: string) => void;
}) {
  const [error, setError] = useState("");
  const [check, setCheck] = useState(AUTO);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<ExplainResponse | null>(null);
  const [failure, setFailure] = useState<{ status: number; message: string } | null>(null);

  const explain = async () => {
    setBusy(true);
    setFailure(null);
    try {
      const body: ExplainRequest = { host: host.id, error, check: check || undefined };
      setResult(await apiSend<ExplainResponse>("POST", "/api/explain", body));
    } catch (e) {
      setResult(null);
      setFailure({
        status: e instanceof ApiError ? e.status : 0,
        message: e instanceof Error ? e.message : String(e),
      });
    } finally {
      setBusy(false);
    }
  };

  // One entry per alias, which is what names a check instance; a command run under several
  // aliases appears once per alias.
  const checks = reports.map((r) => r.alias || r.command);

  return (
    <Card variant="outlined">
      <CardContent>
        <Typography variant="h5" gutterBottom>
          Explain an error
        </Typography>
        <Typography variant="body2" sx={{ color: "text.secondary", mb: 2 }}>
          Paste an error your monitoring system raised for this host. It is explained using the
          host's latest metrics snapshot, its inventory facts and, when the error names a check
          the agent has reported, that check's latest result.
        </Typography>
        <TextField
          multiline
          minRows={3}
          fullWidth
          placeholder="PROBLEM: web01/disk_c is CRITICAL: C:\ used 95.2% > 90%"
          value={error}
          onChange={(e) => setError(e.target.value)}
          sx={{ mb: 2 }}
        />
        <Stack direction="row" spacing={2} sx={{ alignItems: "center" }}>
          <TextField
            select
            size="small"
            label="Check"
            value={check}
            onChange={(e) => setCheck(e.target.value)}
            sx={{ minWidth: "14rem" }}
          >
            <MenuItem value={AUTO}>Find it in the error</MenuItem>
            {[...new Set(checks)].map((c) => (
              <MenuItem key={c} value={c}>
                {c}
              </MenuItem>
            ))}
          </TextField>
          <Button
            variant="contained"
            onClick={explain}
            disabled={busy || !error.trim()}
            startIcon={busy ? <CircularProgress size={16} color="inherit" /> : undefined}
          >
            {busy ? "Explaining…" : "Explain"}
          </Button>
        </Stack>

        {failure && (
          <Alert severity={failure.status === 409 || failure.status === 429 ? "info" : "error"} sx={{ mt: 2 }}>
            {failure.message}
            {failure.status === 409 && (
              <>
                {" "}
                <Link component={RouterLink} to="/settings">
                  Open settings
                </Link>
              </>
            )}
          </Alert>
        )}
        {result && <ExplanationView result={result} onOpenReport={onOpenReport} />}
      </CardContent>
    </Card>
  );
}

function ExplanationView({
  result,
  onOpenReport,
}: {
  result: ExplainResponse;
  onOpenReport: (id: string) => void;
}) {
  const x = result.explanation;
  return (
    <Box sx={{ mt: 3 }}>
      <Stack direction="row" spacing={1} sx={{ alignItems: "center", mb: 1 }}>
        <Typography variant="h6" sx={{ flexGrow: 1 }}>
          Explanation
        </Typography>
        <Chip
          size="small"
          label={`confidence: ${x.confidence}`}
          color={x.confidence === "low" ? "warning" : "default"}
          title="How well the evidence supports the explanation"
        />
      </Stack>
      <Typography sx={{ mb: 2 }}>{x.summary}</Typography>
      <BulletList title="Relevant evidence" items={x.relevant_evidence} />
      <BulletList title="Likely causes" items={x.likely_causes} />
      <BulletList title="Suggested checks" items={x.suggested_checks} />

      <Typography variant="subtitle2" sx={{ mt: 2 }}>
        Based on
      </Typography>
      <Box component="ul" sx={{ mt: 0.5, mb: 1, pl: 3 }}>
        <li>
          <Typography variant="body2">
            {result.check ? (
              <>
                The agent's latest report of <EvidenceLink r={result.check} onOpen={onOpenReport} />
              </>
            ) : (
              "No reported check matched the error."
            )}
          </Typography>
        </li>
        <li>
          <Typography variant="body2">
            {result.snapshot ? (
              <>
                The latest metrics snapshot ({result.snapshot.metrics_count} metrics), which came
                with <EvidenceLink r={result.snapshot} onOpen={onOpenReport} />
              </>
            ) : (
              "No metrics snapshot — this host has not reported one."
            )}
          </Typography>
        </li>
        <li>
          <Typography variant="body2">
            {result.facts_sources.length > 0
              ? `Facts from ${result.facts_sources.join(", ")}`
              : "No inventory facts — this host has none on file."}
          </Typography>
        </li>
      </Box>
      <Typography variant="caption" sx={{ color: "text.secondary" }}>
        Written by {result.provider}/{result.model}
        {result.input_tokens != null &&
          ` · ${result.input_tokens} in / ${result.output_tokens ?? 0} out tokens`}
        . Model-written: check it against the evidence before acting on it.
      </Typography>
    </Box>
  );
}

function EvidenceLink({ r, onOpen }: { r: EvidenceRef; onOpen: (id: string) => void }) {
  return (
    <>
      <Link component="button" variant="body2" onClick={() => onOpen(r.id)}>
        {r.alias && r.alias !== r.command ? `${r.command} (${r.alias})` : r.command}
      </Link>
      , reported {fmtAgo(r.reported_at)}
    </>
  );
}

function BulletList({ title, items }: { title: string; items: string[] }) {
  if (items.length === 0) return null;
  return (
    <Box sx={{ mb: 1 }}>
      <Typography variant="subtitle2">{title}</Typography>
      <Box component="ul" sx={{ mt: 0.5, mb: 0, pl: 3 }}>
        {items.map((s, i) => (
          <li key={i}>
            <Typography variant="body2">{s}</Typography>
          </li>
        ))}
      </Box>
    </Box>
  );
}

/** The latest report per check the agent sent: the evidence explanations draw on. */
function ReportsCard({
  host,
  reports,
  error,
  canWrite,
  onOpen,
  onChanged,
}: {
  host: HostDetail;
  reports: ContextSummary[] | null;
  error: string | null;
  canWrite: boolean;
  onOpen: (id: string) => void;
  onChanged: () => void;
}) {
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const remove = async (id: string) => {
    setDeleteError(null);
    try {
      await apiSend("DELETE", `/api/hosts/${host.id}/contexts/${id}`);
      onChanged();
    } catch (e) {
      setDeleteError(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <Card variant="outlined">
      <CardContent>
        <Typography variant="h5" gutterBottom>
          Reports from the agent
        </Typography>
        <Typography variant="body2" sx={{ color: "text.secondary", mb: 2 }}>
          The latest report the agent sent for each check that failed, with the metrics snapshot
          it held at the time. A newer report for the same check replaces the older one.
        </Typography>
        {(error || deleteError) && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error ?? deleteError}
          </Alert>
        )}
        {reports === null ? (
          !error && <Typography>Loading…</Typography>
        ) : reports.length === 0 ? (
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            This host's agent has not reported a failed check. Agents report only after the
            server has told them it accepts reports, which is on unless it was switched off
            under Settings.
          </Typography>
        ) : (
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Check</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Message</TableCell>
                <TableCell>Reported</TableCell>
                <TableCell>Snapshot</TableCell>
                {canWrite && <TableCell />}
              </TableRow>
            </TableHead>
            <TableBody>
              {reports.map((r) => (
                <TableRow
                  key={r.id}
                  hover
                  sx={{ cursor: "pointer", verticalAlign: "top" }}
                  onClick={() => onOpen(r.id)}
                >
                  <TableCell>
                    <code>{r.command}</code>
                    {r.alias && r.alias !== r.command && (
                      <Typography
                        variant="caption"
                        sx={{ display: "block", color: "text.secondary" }}
                      >
                        {r.alias}
                      </Typography>
                    )}
                  </TableCell>
                  <TableCell>
                    <ReportStatusChip r={r} />
                  </TableCell>
                  <TableCell sx={{ wordBreak: "break-word" }}>{r.message}</TableCell>
                  <TableCell sx={{ whiteSpace: "nowrap" }} title={fmtTime(r.reported_at)}>
                    {fmtAgo(r.reported_at)}
                  </TableCell>
                  <TableCell>
                    <ContextStateChip r={r} />
                  </TableCell>
                  {canWrite && (
                    <TableCell>
                      <IconButton
                        size="small"
                        aria-label="Delete report"
                        title="Delete this report and its snapshot"
                        onClick={(e) => {
                          e.stopPropagation();
                          void remove(r.id);
                        }}
                      >
                        <DeleteIcon fontSize="small" />
                      </IconButton>
                    </TableCell>
                  )}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}
