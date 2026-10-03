import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableRow,
  Typography,
} from "@mui/material";
import type { ReactNode } from "react";
import { Link as RouterLink } from "react-router-dom";
import type { ImportCommitResponse } from "../api";

export type CommitSummary = {
  source: string;
  /** Rows that will be written (matched, not skipped). */
  toStore: number;
  skipped: number;
  /** Rows that still block a commit. */
  blocking: number;
  prune: boolean;
  absentTotal: number;
  collectedAt: string | undefined;
};

function Row({ label, value }: { label: string; value: ReactNode }) {
  return (
    <TableRow>
      <TableCell sx={{ width: "16rem", color: "text.secondary" }}>{label}</TableCell>
      <TableCell>{value}</TableCell>
    </TableRow>
  );
}

export function CommitStep({
  summary,
  nameIssue,
  stale,
  busy,
  error,
  result,
  onCommit,
  onReset,
}: {
  summary: CommitSummary;
  /** Why the import name cannot be used, if it cannot. */
  nameIssue: string | null;
  stale: boolean;
  busy: boolean;
  error: string | null;
  result: ImportCommitResponse | null;
  onCommit: () => void;
  onReset: () => void;
}) {
  if (result) {
    return (
      <Stack spacing={2}>
        <Alert severity={(result.failed ?? 0) > 0 ? "warning" : "success"}>
          Imported into {result.source}.
          {(result.failed ?? 0) > 0 &&
            ` ${result.failed} row${result.failed === 1 ? "" : "s"} could not be stored because the host was deleted while the import ran.`}
        </Alert>
        <Card variant="outlined">
          <CardContent>
            <Table size="small">
              <TableBody>
                <Row label="Stored" value={result.stored.toLocaleString()} />
                <Row label="Unchanged" value={result.unchanged.toLocaleString()} />
                <Row label="Skipped" value={result.skipped.toLocaleString()} />
                <Row label="Removed from hosts not in the file" value={result.pruned.toLocaleString()} />
                {(result.failed ?? 0) > 0 && (
                  <Row
                    label="Failed (host deleted during the import)"
                    value={(result.failed ?? 0).toLocaleString()}
                  />
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
        <Stack direction="row" spacing={1}>
          <Button variant="contained" component={RouterLink} to="/hosts">
            Back to hosts
          </Button>
          <Button onClick={onReset}>Import another file</Button>
        </Stack>
      </Stack>
    );
  }

  const blocked = summary.blocking > 0 || stale || nameIssue !== null || summary.toStore + (summary.prune ? 1 : 0) === 0;
  return (
    <Stack spacing={2}>
      <Card variant="outlined">
        <CardContent>
          <Table size="small">
            <TableBody>
              <Row label="Facts source" value={<code>{summary.source}</code>} />
              <Row label="Documents to store" value={summary.toStore.toLocaleString()} />
              <Row label="Rows skipped" value={summary.skipped.toLocaleString()} />
              <Row
                label="Hosts not in the file"
                value={
                  summary.prune
                    ? `${summary.absentTotal.toLocaleString()} — ${summary.source} is removed from them`
                    : `${summary.absentTotal.toLocaleString()} — they keep what they have`
                }
              />
              {summary.collectedAt && (
                <Row label="Collected at" value={new Date(summary.collectedAt).toLocaleString()} />
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
      <Typography variant="body2" color="text.secondary">
        Each matched host&apos;s {summary.source} document is replaced by its row. The server
        resolves the rows again when committing and refuses if any no longer match one host.
      </Typography>
      {nameIssue && <Alert severity="warning">Import name: {nameIssue}</Alert>}
      {stale && <Alert severity="warning">The rows changed since they were resolved; go back and resolve again.</Alert>}
      {summary.blocking > 0 && (
        <Alert severity="warning">
          {summary.blocking} row{summary.blocking === 1 ? "" : "s"} are unmatched, ambiguous or
          duplicate. Assign a host or skip them in the previous step.
        </Alert>
      )}
      {error && <Alert severity="error">{error}</Alert>}
      <Box>
        <Button variant="contained" disabled={blocked || busy} onClick={onCommit}>
          {busy ? "Importing…" : `Import ${summary.toStore.toLocaleString()} document${summary.toStore === 1 ? "" : "s"}`}
        </Button>
      </Box>
    </Stack>
  );
}
