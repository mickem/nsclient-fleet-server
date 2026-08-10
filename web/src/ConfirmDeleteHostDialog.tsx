import { useState } from "react";
import {
  Alert,
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogContentText,
  DialogTitle,
} from "@mui/material";
import { apiSend } from "./api";

type Props = {
  /** Host to delete; null keeps the dialog closed. */
  host: { id: string; hostname: string | null } | null;
  onClose: () => void;
  onDeleted: () => void;
};

export function ConfirmDeleteHostDialog({ host, onClose, onDeleted }: Props) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const confirm = async () => {
    if (!host) return;
    setBusy(true);
    setError(null);
    try {
      await apiSend("DELETE", `/api/hosts/${host.id}`);
      onDeleted();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={host !== null} onClose={busy ? undefined : onClose}>
      <DialogTitle>Delete host?</DialogTitle>
      <DialogContent>
        <DialogContentText>
          <strong>{host?.hostname ?? host?.id}</strong> will be removed along with its tags,
          override, and certificates. A running agent is cut off immediately (its certificate
          stops being accepted) and cannot re-join without a new install command. This cannot be
          undone.
        </DialogContentText>
        {error && (
          <Alert severity="error" sx={{ mt: 1 }}>
            {error}
          </Alert>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={busy}>
          Cancel
        </Button>
        <Button color="error" variant="contained" onClick={confirm} disabled={busy}>
          {busy ? "Deleting…" : "Delete host"}
        </Button>
      </DialogActions>
    </Dialog>
  );
}
