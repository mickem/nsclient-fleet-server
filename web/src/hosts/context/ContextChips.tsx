import { Chip } from "@mui/material";
import { ContextSummary } from "../../api";

/** The check's own verdict when it last reported, coloured the way every Nagios console
 *  colours it. */
export function ReportStatusChip({ r }: { r: Pick<ContextSummary, "status" | "status_word"> }) {
  const color = r.status === 2 ? "error" : r.status === 1 ? "warning" : "default";
  return <Chip label={r.status_word || `status ${r.status}`} color={color} size="small" />;
}

/** Why a report has no snapshot, in words an operator can act on. */
export const CONTEXT_STATE_TEXT: Record<string, string> = {
  captured: "The agent sent the metrics it held when the check failed.",
  evicted:
    "The agent had a snapshot, but it was replaced by a newer one before the report went out.",
  too_large: "The snapshot was over the agent's size limit, so the agent did not send it.",
  disabled:
    "This agent does not capture metrics. Set `capture metrics = true` under " +
    "[/settings/core/failed checks] to send them.",
  none: "The agent had no snapshot yet when the check failed (for example, just after it started).",
};

/** Why a report has no diagnostics tables, in words an operator can act on. */
export const DIAGNOSTICS_STATE_TEXT: Record<string, string> = {
  captured:
    "The agent sent the diagnostics tables it held when the check failed: what was running " +
    "and what went wrong, by name.",
  evicted: "The agent had the tables, but released them before the report went out.",
  too_large: "The tables were over the agent's size limit, so the agent did not send them.",
  disabled:
    "This agent does not capture diagnostics. Set `capture diagnostics = true` under " +
    "[/settings/core/failed checks], and switch on the tables you want in the modules that " +
    "produce them.",
  none: "The agent had no tables yet when the check failed (for example, just after it started).",
  not_sent:
    "This report has no diagnostics in it: the agent that sent it predates them, or the " +
    "report was stored before this server kept them.",
};

/** Whether the diagnostics tables came with the report: the evidence that names a culprit. */
export function DiagnosticsStateChip({
  r,
}: {
  r: Pick<ContextSummary, "diagnostics_state" | "diagnostics_tables">;
}) {
  const captured = r.diagnostics_state === "captured" && r.diagnostics_tables > 0;
  const state = r.diagnostics_state.replace("_", " ");
  return (
    <Chip
      label={
        captured
          ? `${r.diagnostics_tables} ${r.diagnostics_tables === 1 ? "table" : "tables"}`
          : `no tables (${state})`
      }
      size="small"
      variant="outlined"
      color={captured ? "success" : "default"}
      title={DIAGNOSTICS_STATE_TEXT[r.diagnostics_state] ?? r.diagnostics_state}
    />
  );
}

/** Whether the snapshot came with the report: the thing that makes an error explainable. */
export function ContextStateChip({
  r,
}: {
  r: Pick<ContextSummary, "context_state" | "metrics_count">;
}) {
  const captured = r.context_state === "captured";
  return (
    <Chip
      label={captured ? `${r.metrics_count} metrics` : `no snapshot (${r.context_state})`}
      size="small"
      variant="outlined"
      color={captured ? "success" : "default"}
      title={CONTEXT_STATE_TEXT[r.context_state] ?? r.context_state}
    />
  );
}
