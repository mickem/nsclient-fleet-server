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
