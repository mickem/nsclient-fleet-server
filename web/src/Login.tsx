import { FormEvent, useState } from "react";
import { Button, InputAdornment, Link, Stack, TextField, Typography } from "@mui/material";
import EmailIcon from "@mui/icons-material/Email";
import { AuthShell } from "./AuthShell";

type Props = {
  onDone: () => void;
  onSwitchToSignup: () => void;
};

export function Login({ onSwitchToSignup }: Props) {
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
            slotProps={{
              input: {
                startAdornment: (
                  <InputAdornment position="start">
                    <EmailIcon />
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
            disabled={submitting || !email}
          >
            {submitting ? "Sending…" : "Send magic link"}
          </Button>
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
        </Stack>
      </form>
    </AuthShell>
  );
}
