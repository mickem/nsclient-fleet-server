import { useEffect, useState } from "react";
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  MenuItem,
  Select,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Tooltip,
  Typography,
} from "@mui/material";
import DeleteIcon from "@mui/icons-material/Delete";
import PersonAddIcon from "@mui/icons-material/PersonAdd";
import {
  apiGet,
  apiSend,
  ASSIGNABLE_ROLES,
  fmtTime,
  Me,
  Role,
  ROLE_DESCRIPTIONS,
  ROLE_LABELS,
  UserView,
} from "./api";
import { RefreshButton } from "./RefreshButton";

export function UsersPage({ me }: { me: Me }) {
  const [users, setUsers] = useState<UserView[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  // Returns void, not the promise: `useEffect` below takes this directly, and a returned
  // promise would be mistaken for a cleanup function.
  const refresh = () => {
    setRefreshing(true);
    setError(null);
    void apiGet<UserView[]>("/api/users")
      .then(setUsers, (e) => setError(e.message))
      .finally(() => setRefreshing(false));
  };
  useEffect(refresh, []);

  return (
    <Box>
      <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 1 }}>
        <Typography variant="h4">Users</Typography>
        <RefreshButton refreshing={refreshing} onClick={refresh} />
      </Stack>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Everyone here signs in with a magic link sent to their address. An invitation creates
        the account and emails that link — it is not shown here, so the invitee is the only
        one who can use it.
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {me.on_prem ? (
        <Alert severity="info" sx={{ mb: 2 }}>
          On-prem installs authenticate a single administrator from{" "}
          <code>ON_PREM_ADMIN_EMAIL</code> / <code>ON_PREM_ADMIN_PASSWORD</code>, and magic
          links are disabled — so invitations are unavailable here.
        </Alert>
      ) : (
        <InviteCard onInvited={refresh} />
      )}

      {users === null ? (
        <Typography>Loading…</Typography>
      ) : (
        <TableContainer component={Card}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Email</TableCell>
                <TableCell>Role</TableCell>
                <TableCell>Added</TableCell>
                <TableCell />
              </TableRow>
            </TableHead>
            <TableBody>
              {users.map((u) => (
                <UserRow key={u.id} user={u} onChanged={refresh} onError={setError} />
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}
    </Box>
  );
}

/// The owner row and your own row are read-only: the server rejects both, and offering
/// controls that always fail is worse than not offering them.
function UserRow({
  user,
  onChanged,
  onError,
}: {
  user: UserView;
  onChanged: () => void;
  onError: (e: string) => void;
}) {
  const [busy, setBusy] = useState(false);
  const locked = user.is_self || user.role === "owner";
  const lockReason = user.is_self
    ? "You cannot change or remove your own account."
    : "The owner cannot be changed or removed.";

  const act = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    try {
      await fn();
      onChanged();
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <TableRow hover>
      <TableCell>
        {user.email}
        {user.is_self && <Chip label="you" size="small" sx={{ ml: 1 }} />}
        {user.blocked && (
          <Tooltip title="Blocked by the service operator — they cannot sign in, and their API keys are inert. Only the operator can lift it.">
            <Chip label="blocked" size="small" color="warning" sx={{ ml: 1 }} />
          </Tooltip>
        )}
      </TableCell>
      <TableCell>
        {locked ? (
          <Tooltip title={lockReason}>
            <span>{ROLE_LABELS[user.role]}</span>
          </Tooltip>
        ) : (
          <Select
            size="small"
            value={user.role}
            disabled={busy}
            onChange={(e) =>
              act(() => apiSend("PATCH", `/api/users/${user.id}`, { role: e.target.value }))
            }
          >
            {ASSIGNABLE_ROLES.map((r) => (
              <MenuItem key={r} value={r}>
                {ROLE_LABELS[r]}
              </MenuItem>
            ))}
          </Select>
        )}
      </TableCell>
      <TableCell>{fmtTime(user.created_at)}</TableCell>
      <TableCell align="right">
        {!locked && (
          <Button
            size="small"
            color="error"
            startIcon={<DeleteIcon fontSize="small" />}
            disabled={busy}
            onClick={() => {
              if (!confirm(`Remove ${user.email}? They are signed out immediately.`)) return;
              void act(() => apiSend("DELETE", `/api/users/${user.id}`));
            }}
          >
            Remove
          </Button>
        )}
      </TableCell>
    </TableRow>
  );
}

function InviteCard({ onInvited }: { onInvited: () => void }) {
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<Role>("view_only");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sentTo, setSentTo] = useState<string | null>(null);

  const invite = async () => {
    setBusy(true);
    setError(null);
    setSentTo(null);
    try {
      await apiSend("POST", "/api/users", { email: email.trim(), role });
      setSentTo(email.trim());
      setEmail("");
      onInvited();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card variant="outlined" sx={{ mb: 2 }}>
      <CardContent>
        <Typography variant="h6" gutterBottom>
          Invite a user
        </Typography>
        {error && (
          <Alert severity="error" sx={{ mb: 1 }} onClose={() => setError(null)}>
            {error}
          </Alert>
        )}
        {sentTo && (
          <Alert severity="success" sx={{ mb: 1 }} onClose={() => setSentTo(null)}>
            Invitation sent to {sentTo}. They'll receive an email with a sign-in link.
          </Alert>
        )}
        <Stack direction="row" spacing={1} alignItems="center" useFlexGap sx={{ flexWrap: "wrap" }}>
          <TextField
            size="small"
            label="Email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="colleague@example.com"
            sx={{ minWidth: "18rem" }}
          />
          <Select size="small" value={role} onChange={(e) => setRole(e.target.value as Role)}>
            {ASSIGNABLE_ROLES.map((r) => (
              <MenuItem key={r} value={r}>
                {ROLE_LABELS[r]}
              </MenuItem>
            ))}
          </Select>
          <Button
            variant="contained"
            startIcon={<PersonAddIcon />}
            onClick={invite}
            disabled={busy || !email.trim()}
          >
            {busy ? "Sending…" : "Send invitation"}
          </Button>
        </Stack>
        <Typography variant="caption" color="text.secondary">
          {ROLE_DESCRIPTIONS[role]}
        </Typography>
      </CardContent>
    </Card>
  );
}
