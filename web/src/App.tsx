import { useEffect, useState } from "react";
import { CssBaseline } from "@mui/material";
import { ThemeProvider } from "@mui/material/styles";
import { theme } from "./theme";
import { Me, PublicConfig } from "./api";
import { Login } from "./Login";
import { Signup } from "./Signup";
import { Dashboard } from "./Dashboard";

type View = "loading" | "login" | "signup" | "dashboard";

export default function App() {
  const [me, setMe] = useState<Me | null>(null);
  const [view, setView] = useState<View>("loading");
  // Whether self-service signup is open. Null until the answer arrives; treated as closed
  // until then, so a slow response cannot flash a form that the server would refuse.
  const [publicConfig, setPublicConfig] = useState<PublicConfig | null>(null);
  const signupsEnabled = publicConfig?.signups_enabled ?? false;

  const refresh = async () => {
    try {
      const r = await fetch("/api/me", { credentials: "include" });
      if (r.ok) {
        setMe(await r.json());
        setView("dashboard");
      } else {
        setMe(null);
        setView((v) => (v === "signup" ? "signup" : "login"));
      }
    } catch {
      setMe(null);
      setView("login");
    }
  };

  useEffect(() => {
    refresh();
    fetch("/api/public-config")
      .then((r) => (r.ok ? r.json() : null))
      .then(setPublicConfig)
      .catch(() => setPublicConfig(null));
  }, []);

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      {view === "loading" && null}
      {view === "dashboard" && me && <Dashboard me={me} onLogout={refresh} />}
      {view === "signup" && signupsEnabled && (
        <Signup onDone={refresh} onSwitchToLogin={() => setView("login")} />
      )}
      {(view === "login" || (view === "signup" && !signupsEnabled)) && (
        <Login
          onDone={refresh}
          onSwitchToSignup={() => setView("signup")}
          signupsEnabled={signupsEnabled}
        />
      )}
    </ThemeProvider>
  );
}
