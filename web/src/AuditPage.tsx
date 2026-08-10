import { useEffect, useState } from "react";
import {
  Alert,
  Box,
  Card,
  MenuItem,
  Select,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
} from "@mui/material";
import { apiGet, fmtTime } from "./api";

type AuditEntry = {
  id: number;
  action: string;
  target_type: string;
  target_id: string;
  user_id: number | null;
  ts: number;
  metadata: unknown | null;
};

export function AuditPage() {
  const [entries, setEntries] = useState<AuditEntry[] | null>(null);
  const [filter, setFilter] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const qs = filter ? `?action=${encodeURIComponent(filter)}` : "";
    apiGet<AuditEntry[]>(`/api/audit${qs}`).then(setEntries, (e) => setError(e.message));
  }, [filter]);

  return (
    <Box>
      <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 2 }}>
        <Typography variant="h4">Audit log</Typography>
        <Select size="small" value={filter} onChange={(e) => setFilter(e.target.value)} displayEmpty>
          <MenuItem value="">all actions</MenuItem>
          <MenuItem value="host.">host.*</MenuItem>
          <MenuItem value="group.">group.*</MenuItem>
          <MenuItem value="bundle.">bundle.*</MenuItem>
        </Select>
      </Stack>
      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}
      {entries === null ? (
        <Typography>Loading…</Typography>
      ) : entries.length === 0 ? (
        <Typography color="text.secondary">No audit entries.</Typography>
      ) : (
        <TableContainer component={Card}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Time</TableCell>
                <TableCell>Action</TableCell>
                <TableCell>Target</TableCell>
                <TableCell>User</TableCell>
                <TableCell>Details</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {entries.map((e) => (
                <TableRow key={e.id} hover sx={{ verticalAlign: "top" }}>
                  <TableCell sx={{ whiteSpace: "nowrap" }}>{fmtTime(e.ts)}</TableCell>
                  <TableCell>
                    <code>{e.action}</code>
                  </TableCell>
                  <TableCell>
                    {e.target_type}{" "}
                    <Typography variant="caption" component="code">
                      {e.target_id}
                    </Typography>
                  </TableCell>
                  <TableCell>{e.user_id ?? "agent"}</TableCell>
                  <TableCell>
                    {e.metadata ? (
                      <Typography variant="caption" component="code">
                        {JSON.stringify(e.metadata)}
                      </Typography>
                    ) : (
                      "—"
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}
    </Box>
  );
}
