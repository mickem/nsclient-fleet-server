import { FormEvent, useState } from "react";
import {
  Alert,
  Button,
  InputAdornment,
  Link,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import EmailIcon from "@mui/icons-material/Email";
import LockIcon from "@mui/icons-material/Lock";
import { AuthShell } from "./AuthShell";

type Props = {
  onDone: () => void;
  onSwitchToSignup: () => void;
  /** False when a platform admin has closed self-service signup, or on-prem — in either case
   *  the form would only lead to a 403, so the invitation is not offered at all. */
  signupsEnabled: boolean;
  /** On-prem has no mail and no magic links: the single administrator signs in with the
   *  password from the server's environment instead. */
  onPrem: boolean;
};

export function Login({ onDone, onSwitchToSignup, signupsEnabled, onPrem }: Props) {
  return onPrem ? (
    <PasswordLogin onDone={onDone} />
  ) : (
    <MagicLinkLogin onSwitchToSignup={onSwitchToSignup} signupsEnabled={signupsEnabled} />
  );
}

const emailAdornment = {
  input: {
    startAdornment: (
      <InputAdornment position="start">
        <EmailIcon />
      </InputAdornment>
    ),
  },
};

function PasswordLogin({ onDone }: { onDone: () => void }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ email, password }),
      });
      // Success is a 303 to "/", which fetch follows to the app shell's 200. The session
      // cookie is set either way; re-fetching /api/me swaps in the signed-in routes.
      if (res.ok) {
        onDone();
        return;
      }
      setError(
        res.status === 401 ? "Wrong email or password." : (await res.text()) || "Sign-in failed.",
      );
    } catch {
      setError("Could not reach the server.");
    }
    setSubmitting(false);
  };

  return (
    <AuthShell title="Sign in">
      <form onSubmit={submit}>
        <Stack direction="column" spacing={3}>
          {error && <Alert severity="error">{error}</Alert>}
          <TextField
            label="Email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            autoFocus
            fullWidth
            autoComplete="username"
            slotProps={emailAdornment}
          />
          <TextField
            label="Password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            fullWidth
            autoComplete="current-password"
            slotProps={{
              input: {
                startAdornment: (
                  <InputAdornment position="start">
                    <LockIcon />
                  </InputAdornment>
                ),
              },
            }}
          />
          <Button
            type="submit"
            variant="contained"
            size="large"
            fullWidth
            disabled={submitting || !email || !password}
          >
            {submitting ? "Signing in…" : "Sign in"}
          </Button>
        </Stack>
      </form>
    </AuthShell>
  );
}

function MagicLinkLogin({
  onSwitchToSignup,
  signupsEnabled,
}: {
  onSwitchToSignup: () => void;
  signupsEnabled: boolean;
}) {
  const [email, setEmail] = useState("");
  const [sent, setSent] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    await fetch("/api/auth/send-link", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email }),
    });
    setSubmitting(false);
    setSent(true);
  };

  if (sent) {
    return (
      <AuthShell title="Check your email">
        <Typography gutterBottom>
          If an account exists for <strong>{email}</strong>, a sign-in link is on its way.
        </Typography>
        <Typography variant="body2" color="text.secondary">
          The link expires in 15 minutes and can be used once.
        </Typography>
      </AuthShell>
    );
  }

  return (
    <AuthShell title="Sign in">
      <form onSubmit={submit}>
        <Stack direction="column" spacing={3}>
          <TextField
            label="Email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            autoFocus
            fullWidth
            slotProps={emailAdornment}
          />
          <Button
            type="submit"
            variant="contained"
            size="large"
            fullWidth
            disabled={submitting || !email}
          >
            {submitting ? "Sending…" : "Send magic link"}
          </Button>
          {signupsEnabled && (
            <Typography variant="body2">
              No account?{" "}
              <Link
                href="#"
                onClick={(e) => {
                  e.preventDefault();
                  onSwitchToSignup();
                }}
              >
                Start a trial
              </Link>
            </Typography>
          )}
        </Stack>
      </form>
    </AuthShell>
  );
}
