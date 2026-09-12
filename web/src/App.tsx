import { useEffect, useState } from "react";
import { CssBaseline } from "@mui/material";
import { ThemeProvider } from "@mui/material/styles";
import { BrowserRouter, Navigate, Route, Routes, useNavigate } from "react-router-dom";
import { theme } from "./theme";
import { canManageUsers, Me, PublicConfig } from "./api";
import { Login } from "./Login";
import { Signup } from "./Signup";
import { Dashboard } from "./Dashboard";
import { HostsPage } from "./HostsPage";
import { HostDetailPage } from "./HostDetailPage";
import { GroupsPage } from "./GroupsPage";
import { BundlesPage } from "./BundlesPage";
import { AuditPage } from "./AuditPage";
import { UsersPage } from "./UsersPage";
import { ApiKeysPage } from "./ApiKeysPage";
import { PlatformPage } from "./PlatformPage";

/** Routes for a signed-in session. Role-gated pages are not registered at all for roles
 *  that cannot use them, so a deep link to one lands on the fallback instead of a page
 *  whose every request would be refused. */
function AuthedRoutes({ me, onLogout }: { me: Me; onLogout: () => void }) {
  return (
    <Routes>
      <Route element={<Dashboard me={me} onLogout={onLogout} />}>
        <Route path="hosts" element={<HostsPage me={me} />} />
        <Route path="hosts/:hostId" element={<HostDetailPage me={me} />} />
        <Route path="groups" element={<GroupsPage me={me} />} />
        <Route path="bundles" element={<BundlesPage me={me} />} />
        <Route path="audit" element={<AuditPage />} />
        <Route path="keys" element={<ApiKeysPage me={me} />} />
        {canManageUsers(me.role) && <Route path="users" element={<UsersPage me={me} />} />}
        {me.is_platform_admin && <Route path="platform" element={<PlatformPage me={me} />} />}
        {/* "/" and anything unknown (or not permitted) start at the fleet. */}
        <Route path="*" element={<Navigate to="/hosts" replace />} />
      </Route>
    </Routes>
  );
}

/** Routes before sign-in. Everything except /signup renders the login form *at the
 *  requested URL* — so a deep link survives the detour: signing in re-renders the same
 *  location as the real page, with no redirect dance. */
function AnonRoutes({
  onDone,
  signupsEnabled,
}: {
  onDone: () => void;
  signupsEnabled: boolean;
}) {
  const navigate = useNavigate();
  const login = (
  onPrem,
    <Login
      onDone={onDone}
      onSwitchToSignup={() => navigate("/signup")}
  onPrem: boolean;
      signupsEnabled={signupsEnabled}
    />
  );
  return (
    <Routes>
      <Route
        path="/signup"
      onPrem={onPrem}
        element={
          signupsEnabled ? (
            <Signup onDone={onDone} onSwitchToLogin={() => navigate("/login")} />
          ) : (
            <Navigate to="/login" replace />
          )
        }
      />
      <Route path="*" element={login} />
    </Routes>
  );
}

export default function App() {
  const [me, setMe] = useState<Me | null>(null);
  // Nothing renders until /api/me has answered: routing on an unknown session would flash
  // the login form over a page the user is entitled to (or the reverse).
  const [ready, setReady] = useState(false);
  // Whether self-service signup is open. Null until the answer arrives; treated as closed
  // until then, so a slow response cannot flash a form that the server would refuse.
  const [publicConfig, setPublicConfig] = useState<PublicConfig | null>(null);
  const signupsEnabled = publicConfig?.signups_enabled ?? false;

  const refresh = async () => {
    try {
      const r = await fetch("/api/me", { credentials: "include" });
      setMe(r.ok ? await r.json() : null);
    } catch {
  // Until the answer arrives the magic-link form shows; on-prem swaps in the password
  // form as soon as the server says so.
  const onPrem = publicConfig?.on_prem ?? false;
      setMe(null);
    } finally {
      setReady(true);
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
      <BrowserRouter>
        {!ready ? null : me ? (
          <AuthedRoutes me={me} onLogout={refresh} />
        ) : (
          <AnonRoutes onDone={refresh} signupsEnabled={signupsEnabled} onPrem={onPrem} />
        )}
      </BrowserRouter>
    </ThemeProvider>
  );
}
