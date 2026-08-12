import { useEffect, useState } from "react";
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  IconButton,
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
import {
  apiGet,
  apiSend,
  ApiKeyView,
  canAddHosts,
  CreatedApiKey,
  fmtAgo,
  fmtTime,
  Me,
  ROLE_LABELS,
} from "./api";
import { RefreshButton } from "./RefreshButton";

export function ApiKeysPage({ me }: { me: Me }) {
  const [keys, setKeys] = useState<ApiKeyView[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [issued, setIssued] = useState<CreatedApiKey | null>(null);

  // Returns void, not the promise: `useEffect` below takes this directly, and a returned
  // promise would be mistaken for a cleanup function.
  const refresh = () => {
    setRefreshing(true);
    setError(null);
    void apiGet<ApiKeyView[]>("/api/keys")
      .then(setKeys, (e) => setError(e.message))
      .finally(() => setRefreshing(false));
  };
  useEffect(refresh, []);

  const create = async () => {
    if (!name.trim()) return;
    setBusy(true);
    setError(null);
    try {
      setIssued(await apiSend<CreatedApiKey>("POST", "/api/keys", { name: name.trim() }));
      setName("");
      refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const revoke = async (k: ApiKeyView) => {
    if (!confirm(`Revoke "${k.name}"? Anything using it stops working immediately.`)) return;
    setError(null);
    try {
      await apiSend("DELETE", `/api/keys/${k.id}`);
      refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <Box>
      <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 1 }}>
        <Typography variant="h4">API keys</Typography>
        <RefreshButton refreshing={refreshing} onClick={refresh} />
      </Stack>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Your own keys, for scripting this API. A key acts as you — it can do exactly what your
        role ({ROLE_LABELS[me.role]}) allows, no more, and it stops working the moment your
        role changes or your account is removed. Nobody else can see or revoke your keys.
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {issued && <IssuedKeyCard issued={issued} me={me} onDismiss={() => setIssued(null)} />}

      <Card variant="outlined" sx={{ mb: 2 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Create a key
          </Typography>
          <Stack direction="row" spacing={1} alignItems="center">
            <TextField
              size="small"
              label="Name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="ci-provisioning"
              sx={{ minWidth: "18rem" }}
            />
            <Button
              variant="contained"
              startIcon={<AddIcon />}
              onClick={create}
              disabled={busy || !name.trim()}
            >
              {busy ? "Creating…" : "Create key"}
            </Button>
          </Stack>
          <Typography variant="caption" color="text.secondary">
            The token is shown once, here, and never again — only its hash is stored.
          </Typography>
        </CardContent>
      </Card>

      {keys === null ? (
        <Typography>Loading…</Typography>
      ) : keys.length === 0 ? (
        <Card>
          <CardContent>
            <Typography color="text.secondary">No API keys yet.</Typography>
          </CardContent>
        </Card>
      ) : (
        <TableContainer component={Card}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Name</TableCell>
                <TableCell>Key</TableCell>
                <TableCell>Created</TableCell>
                <TableCell>Last used</TableCell>
                <TableCell />
              </TableRow>
            </TableHead>
            <TableBody>
              {keys.map((k) => (
                <TableRow key={k.id} hover>
                  <TableCell>{k.name}</TableCell>
                  <TableCell>
                    <Typography variant="caption" component="code">
                      {k.token_prefix}…
                    </Typography>
                  </TableCell>
                  <TableCell>{fmtTime(k.created_at)}</TableCell>
                  <TableCell>{k.last_used_at ? fmtAgo(k.last_used_at) : "never"}</TableCell>
                  <TableCell align="right">
                    <Button
                      size="small"
                      color="error"
                      startIcon={<DeleteIcon fontSize="small" />}
                      onClick={() => revoke(k)}
                    >
                      Revoke
                    </Button>
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

/**
 * The one and only sighting of the token. Shown with the command it exists for, so the
 * common case — provisioning an installer from a script — can be copied straight out.
 */
function IssuedKeyCard({
  issued,
  me,
  onDismiss,
}: {
  issued: CreatedApiKey;
  me: Me;
  onDismiss: () => void;
}) {
  const origin = window.location.origin;
  const provision = [
    `curl -sS -X POST ${origin}/api/hosts \\`,
    `  -H "Authorization: Bearer ${issued.token}"`,
  ].join("\n");

  return (
    <Card sx={{ mb: 2 }}>
      <CardContent>
        <Stack direction="row" justifyContent="space-between" alignItems="flex-start">
          <Typography variant="h5" gutterBottom>
            Key created — copy it now
          </Typography>
          <IconButton size="small" onClick={onDismiss}>
            <CloseIcon fontSize="small" />
          </IconButton>
        </Stack>
        <Typography variant="body2" color="text.secondary">
          This is the only time the token is shown. Store it somewhere your scripts can read
          it; if you lose it, revoke the key and create another.
        </Typography>
        <Box component="pre" sx={preSx}>
          {issued.token}
        </Box>
        {canAddHosts(me.role) ? (
          <>
            <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
              Provision an installer token with it — the response carries{" "}
              <code>install_command</code> to run on the new host:
            </Typography>
            <Box component="pre" sx={preSx}>
              {provision}
            </Box>
          </>
        ) : (
          <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
            Your role is read-only, so this key can read the API but cannot provision
            installers or change anything.
          </Typography>
        )}
      </CardContent>
    </Card>
  );
}

const preSx = {
  overflowX: "auto",
  p: 1.5,
  mt: 1,
  bgcolor: "#0D1117",
  borderRadius: 1,
  fontSize: "0.85rem",
} as const;
