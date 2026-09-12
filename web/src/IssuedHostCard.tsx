import { ReactNode, useState } from "react";
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  IconButton,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import CloseIcon from "@mui/icons-material/Close";
import { CreateHostResponse } from "./api";
import { unlockWithPastedKey, useBundleKey } from "./bundleKey";
import { CopyButton } from "./CopyButton";
import { recalledKey } from "./crypto";
import { enrollCommand, msiCommand } from "./installCommands";

const preSx = {
  overflowX: "auto",
  p: 1.5,
  m: 0,
  bgcolor: "#0D1117",
  borderRadius: 1,
  fontSize: "0.85rem",
  flex: 1,
  minWidth: 0,
} as const;

/** A copyable block: the text in a dark box with its copy button beside it, so each of
 *  the three things an operator might paste (token, CLI, MSI) has its own button. */
function CopyBlock({ title, help, text, label }: { title: string; help: ReactNode; text: string; label: string }) {
  return (
    <Box sx={{ mt: 2 }}>
      <Typography variant="subtitle2">{title}</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 0.5 }}>
        {help}
      </Typography>
      <Stack direction="row" spacing={0.5} alignItems="flex-start">
        <Box component="pre" sx={preSx}>
          {text}
        </Box>
        <CopyButton text={text} label={label} />
      </Stack>
    </Box>
  );
}

/** The tenant has a key but this browser does not hold it: the commands below would
 *  enroll an agent that cannot open encrypted bundles. Offer the unlock right here —
 *  navigating to the bundles page would lose the freshly issued token. */
function KeyNotice({
  fingerprint,
  onUnlocked,
}: {
  fingerprint: string;
  onUnlocked: () => void;
}) {
  const [pasted, setPasted] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState(false);
  const unlock = async () => {
    const problem = await unlockWithPastedKey(pasted, fingerprint);
    if (problem) {
      setError(problem);
      return;
    }
    setPasted("");
    setError(null);
    onUnlocked();
  };
  return (
    <Alert severity="warning" sx={{ mt: 2 }}>
      This tenant seals bundles with an encryption key (fingerprint <code>{fingerprint}</code>)
      that is not unlocked in this browser, so the commands below leave it out. The agent would
      enroll fine but could not open encrypted bundles.{" "}
      {!open ? (
        <Button size="small" onClick={() => setOpen(true)}>
          Paste the key
        </Button>
      ) : (
        <Stack direction="row" spacing={1} sx={{ mt: 1 }} alignItems="flex-start">
          <TextField
            size="small"
            label="Bundle encryption key"
            value={pasted}
            onChange={(e) => setPasted(e.target.value)}
            error={error !== null}
            helperText={error ?? "base64, as shown once when it was created"}
            slotProps={{ input: { sx: { fontFamily: "monospace" } } }}
            sx={{ minWidth: "24rem" }}
          />
          <Button variant="contained" size="small" disabled={!pasted.trim()} onClick={() => void unlock()}>
            Unlock
          </Button>
        </Stack>
      )}
    </Alert>
  );
}

/** What "Add host" hands back: the one-time token, and the two ways to spend it. Both
 *  commands are assembled here so they can carry the bundle key this browser holds —
 *  the server never sees that key and so cannot write it into anything. */
export function IssuedHostCard({ issued, onClose }: { issued: CreateHostResponse; onClose: () => void }) {
  const keyState = useBundleKey();
  const bundleKey = keyState.unlocked ? recalledKey() : null;
  const inputs = { serverUrl: issued.server_url, token: issued.bootstrap_token, bundleKey };
  const keyMissing = keyState.loaded && keyState.fingerprint !== null && !keyState.unlocked;

  return (
    <Card sx={{ mb: 2 }}>
      <CardContent>
        <Stack direction="row" justifyContent="space-between" alignItems="flex-start">
          <Typography variant="h5" gutterBottom>
            Enroll the new host
          </Typography>
          <IconButton size="small" onClick={onClose} aria-label="dismiss">
            <CloseIcon fontSize="small" />
          </IconButton>
        </Stack>
        <Typography variant="body2" color="text.secondary">
          The token expires in 1 hour and can be used once. Run either command on the host, or
          paste the token into whatever provisions it.
          {bundleKey && " Both commands include this tenant's bundle encryption key."}
        </Typography>

        {keyMissing && keyState.fingerprint && (
          <KeyNotice fingerprint={keyState.fingerprint} onUnlocked={() => keyState.setUnlocked(true)} />
        )}

        <CopyBlock
          title="Bootstrap token"
          help="For the agent's enroll command, the MSI property, or your own tooling."
          text={issued.bootstrap_token}
          label="Copy token"
        />
        <CopyBlock
          title="Installed agent (command line)"
          help="On a host that already has NSClient++ — Windows or Linux."
          text={enrollCommand(inputs)}
          label="Copy enroll command"
        />
        <CopyBlock
          title="Windows installer (MSI)"
          help={
            <>
              Installs and enrolls in one step; replace the MSI file name. For a self-signed
              server certificate add <code>FLEET_CA=C:\path\to\fleet-ca.pem</code>, or on a
              trusted network <code>FLEET_VERIFY_MODE=none FLEET_INSECURE=1</code>.
            </>
          }
          text={msiCommand(inputs)}
          label="Copy MSI command"
        />

        <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 2 }}>
          host_id: <code>{issued.host_id}</code>
        </Typography>
      </CardContent>
    </Card>
  );
}
