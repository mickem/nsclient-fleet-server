import { FormEvent, useState } from "react";
import { Alert, Button, Link, Stack, TextField, Typography } from "@mui/material";
import { AuthShell } from "./AuthShell";

type Props = {
  onDone: () => void;
  onSwitchToLogin: () => void;
};

export function Signup({ onSwitchToLogin }: Props) {
  const [email, setEmail] = useState("");
  const [tenantSlug, setTenantSlug] = useState("");
  const [tenantName, setTenantName] = useState("");
  const [submitted, setSubmitted] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    const res = await fetch("/api/auth/signup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email,
        tenant_slug: tenantSlug,
        tenant_name: tenantName,
        turnstile_token: "",
      }),
    });
    setSubmitting(false);
    if (res.ok) {
      setSubmitted(true);
    } else {
      setError(await res.text());
    }
  };

  if (submitted) {
    return (
      <AuthShell title="Trial started">
        <Typography>Check your email for the sign-in link.</Typography>
      </AuthShell>
    );
  }

  return (
    <AuthShell title="Start a 14-day trial">
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
          />
          <TextField
            label="Tenant slug"
            value={tenantSlug}
            onChange={(e) => setTenantSlug(e.target.value)}
            placeholder="acme"
            required
            fullWidth
            slotProps={{ htmlInput: { pattern: "[a-z0-9-]+" } }}
          />
          <TextField
            label="Tenant name"
            value={tenantName}
            onChange={(e) => setTenantName(e.target.value)}
            placeholder="Acme Corp"
            required
            fullWidth
          />
          <Button type="submit" variant="contained" size="large" fullWidth disabled={submitting}>
            {submitting ? "Creating…" : "Start trial"}
          </Button>
          <Typography variant="body2">
            Already have an account?{" "}
            <Link
              href="#"
              onClick={(e) => {
                e.preventDefault();
                onSwitchToLogin();
              }}
            >
              Sign in
            </Link>
          </Typography>
        </Stack>
      </form>
    </AuthShell>
  );
}
