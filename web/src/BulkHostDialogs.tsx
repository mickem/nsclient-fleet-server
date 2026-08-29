import { useState } from "react";
import {
  Alert,
  Autocomplete,
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogContentText,
  DialogTitle,
  Stack,
  TextField,
} from "@mui/material";
import { apiSend, BulkResult } from "./api";

type BulkDialogProps = {
  /** Hosts the action applies to; the dialog is closed while empty. */
  hostIds: string[];
  open: boolean;
  onClose: () => void;
  /** Called after the server accepted the request — the page refreshes and clears the
   *  selection here, and surfaces `not_found` if anything vanished under us. */
  onDone: (result: BulkResult) => void;
};

/** Shared submit plumbing: every dialog is a form over one POST with busy/error handling. */
function useBulkSubmit(onDone: (r: BulkResult) => void) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = async (path: string, body: unknown) => {
    setBusy(true);
    setError(null);
    try {
      onDone(await apiSend<BulkResult>("POST", path, body));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };
  return { busy, error, setError, submit };
}

export function BulkDeleteDialog({ hostIds, open, onClose, onDone }: BulkDialogProps) {
  const { busy, error, setError, submit } = useBulkSubmit(onDone);
  const close = () => {
    setError(null);
    onClose();
  };
  return (
    <Dialog open={open} onClose={busy ? undefined : close}>
      <DialogTitle>Delete {hostIds.length} hosts?</DialogTitle>
      <DialogContent>
        <DialogContentText>
          The {hostIds.length} selected hosts will be removed along with their tags, overrides,
          and certificates. Running agents are cut off immediately (their certificates stop
          being accepted) and cannot re-join without a new install command. This cannot be
          undone.
        </DialogContentText>
        {error && (
          <Alert severity="error" sx={{ mt: 1 }}>
            {error}
          </Alert>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={close} disabled={busy}>
          Cancel
        </Button>
        <Button
          color="error"
          variant="contained"
          disabled={busy}
          onClick={() => void submit("/api/hosts/bulk-delete", { host_ids: hostIds })}
        >
          {busy ? "Deleting…" : `Delete ${hostIds.length} hosts`}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

export function BulkAddTagDialog({ hostIds, open, onClose, onDone }: BulkDialogProps) {
  const { busy, error, setError, submit } = useBulkSubmit(onDone);
  const [key, setKey] = useState("");
  const [value, setValue] = useState("");
  const close = () => {
    setError(null);
    setKey("");
    setValue("");
    onClose();
  };
  const valid = key.trim().length > 0 && key.length <= 128;
  return (
    <Dialog open={open} onClose={busy ? undefined : close} fullWidth maxWidth="xs">
      <DialogTitle>Tag {hostIds.length} hosts</DialogTitle>
      <DialogContent>
        <DialogContentText sx={{ mb: 2 }}>
          Sets a manual tag on every selected host. A host that already carries the key gets
          the new value.
        </DialogContentText>
        <Stack spacing={2}>
          <TextField
            label="Key"
            size="small"
            autoFocus
            value={key}
            onChange={(e) => setKey(e.target.value)}
          />
          <TextField
            label="Value"
            size="small"
            value={value}
            onChange={(e) => setValue(e.target.value)}
          />
        </Stack>
        {error && (
          <Alert severity="error" sx={{ mt: 1 }}>
            {error}
          </Alert>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={close} disabled={busy}>
          Cancel
        </Button>
        <Button
          variant="contained"
          disabled={busy || !valid}
          onClick={() =>
            void submit("/api/hosts/bulk-tags", {
              host_ids: hostIds,
              set: [{ key: key.trim(), value }],
            })
          }
        >
          {busy ? "Tagging…" : "Set tag"}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

export function BulkRemoveTagDialog({
  hostIds,
  open,
  onClose,
  onDone,
  keyOptions,
}: BulkDialogProps & {
  /** Manual tag keys present on the selected hosts — offered as suggestions. Free text is
   *  allowed too, for removing a key from hosts that scrolled out of the selection. */
  keyOptions: string[];
}) {
  const { busy, error, setError, submit } = useBulkSubmit(onDone);
  const [key, setKey] = useState("");
  const close = () => {
    setError(null);
    setKey("");
    onClose();
  };
  const valid = key.trim().length > 0 && key.length <= 128;
  return (
    <Dialog open={open} onClose={busy ? undefined : close} fullWidth maxWidth="xs">
      <DialogTitle>Remove tag from {hostIds.length} hosts</DialogTitle>
      <DialogContent>
        <DialogContentText sx={{ mb: 2 }}>
          Removes a manual tag from every selected host. Agent-reported tags cannot be removed
          here — the agent would simply report them again.
        </DialogContentText>
        <Autocomplete
          freeSolo
          options={keyOptions}
          inputValue={key}
          onInputChange={(_, v) => setKey(v)}
          renderInput={(params) => <TextField {...params} label="Key" size="small" autoFocus />}
        />
        {error && (
          <Alert severity="error" sx={{ mt: 1 }}>
            {error}
          </Alert>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={close} disabled={busy}>
          Cancel
        </Button>
        <Button
          color="error"
          variant="contained"
          disabled={busy || !valid}
          onClick={() =>
            void submit("/api/hosts/bulk-tags", {
              host_ids: hostIds,
              remove: [key.trim()],
            })
          }
        >
          {busy ? "Removing…" : "Remove tag"}
        </Button>
      </DialogActions>
    </Dialog>
  );
}
