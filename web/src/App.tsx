import { useEffect, useState } from "react";
import { CssBaseline } from "@mui/material";
import { ThemeProvider } from "@mui/material/styles";
import { theme } from "./theme";
import { Me } from "./api";
import { Login } from "./Login";
import { Signup } from "./Signup";
import { Dashboard } from "./Dashboard";

type View = "loading" | "login" | "signup" | "dashboard";

export default function App() {
  const [me, setMe] = useState<Me | null>(null);
  const [view, setView] = useState<View>("loading");

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
  }, []);

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      {view === "loading" && null}
      {view === "dashboard" && me && <Dashboard me={me} onLogout={refresh} />}
      {view === "signup" && (
        <Signup onDone={refresh} onSwitchToLogin={() => setView("login")} />
      )}
      {view === "login" && (
        <Login onDone={refresh} onSwitchToSignup={() => setView("signup")} />
      )}
    </ThemeProvider>
  );
}
