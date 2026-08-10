import { useEffect, useState } from "react";
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  IconButton,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
} from "@mui/material";
import AddIcon from "@mui/icons-material/Add";
import CloseIcon from "@mui/icons-material/Close";
import DeleteIcon from "@mui/icons-material/Delete";
import { apiGet, apiSend, CreateHostResponse, fmtAgo, HostView } from "./api";
import { ConfirmDeleteHostDialog } from "./ConfirmDeleteHostDialog";
import { RefreshButton } from "./RefreshButton";

type Props = { onOpen: (hostId: string) => void };

export function HostsPage({ onOpen }: Props) {
  const [hosts, setHosts] = useState<HostView[] | null>(null);
  const [issued, setIssued] = useState<CreateHostResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [toDelete, setToDelete] = useState<HostView | null>(null);

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

  return (
    <Box>
      <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 2 }}>
        <Typography variant="h4">Hosts</Typography>
        <Stack direction="row" spacing={1} alignItems="center">
          <RefreshButton refreshing={refreshing} onClick={refresh} />
          <Button variant="contained" startIcon={<AddIcon />} onClick={addHost} disabled={busy}>
            {busy ? "Issuing token…" : "Add host"}
          </Button>
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
      ) : (
        <TableContainer component={Card}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Hostname</TableCell>
                <TableCell>OS</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Last seen</TableCell>
                <TableCell>Host ID</TableCell>
                <TableCell />
              </TableRow>
            </TableHead>
            <TableBody>
              {hosts.map((h) => (
                <TableRow
                  key={h.id}
                  hover
                  onClick={() => onOpen(h.id)}
                  sx={{ cursor: "pointer" }}
                >
                  <TableCell>{h.hostname ?? <em>(not reported)</em>}</TableCell>
                  <TableCell>{h.os ?? "—"}</TableCell>
                  <TableCell>
                    {h.enrolled_at ? (
                      <Chip label="enrolled" color="success" size="small" />
                    ) : (
                      <Chip label="pending" color="warning" size="small" variant="outlined" />
                    )}
                  </TableCell>
                  <TableCell>{fmtAgo(h.last_seen_at)}</TableCell>
                  <TableCell>
                    <Typography variant="caption" component="code">
                      {h.id}
                    </Typography>
                  </TableCell>
                  <TableCell align="right">
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
    </Box>
  );
}
