import { useEffect, useState } from "react";
import { Alert, AlertTitle, Box, Button, CircularProgress, Typography } from "@mui/material";
import SyncIcon from "@mui/icons-material/Sync";
import {
  ApiError,
  apiGet,
  apiSend,
  canWriteConfig,
  ConfigSourceView,
  fmtTime,
  Me,
  ReloadReport,
  ReloadStatus,
} from "../api";

/** One line saying what a reload changed. */
function describeReport(r: ReloadReport): string {
  if (!r.changed) return "Nothing changed — the server already matched the files.";
  const parts: string[] = [];
  const count = (n: number, what: string) => n > 0 && parts.push(`${n} ${what}`);
  count(r.bundles_added.length, "bundle version(s) added");
  count(r.bundles_replaced.length, "replaced");
  count(r.bundles_removed.length, "removed");
  count(r.groups_added.length, "group(s) added");
  count(r.groups_updated.length, "updated");
  count(r.groups_removed.length, "removed");
  if (r.assignments_changed) parts.push("assignments changed");
  return parts.join(", ") + ".";
}

/**
 * Shown on the groups and bundles pages when the server reads them from a directory
 * (CONFIG_SOURCE_DIR) — say where, how the last load went, and offer a reload. Renders
 * nothing otherwise.
 */
export function ManagedConfigBanner({ me, onReloaded }: { me: Me; onReloaded: () => void }) {
  const [source, setSource] = useState<ConfigSourceView | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = () => {
    if (!me.config_managed) return;
    apiGet<ConfigSourceView>("/api/config-source").then(setSource, (e) => setError(e.message));
  };
  useEffect(load, [me.config_managed]);

  if (!me.config_managed) return null;

  const reload = async () => {
    setBusy(true);
    setError(null);
    try {
      await apiSend<ReloadReport>("POST", "/api/config-source/reload", {});
      onReloaded();
    } catch (e) {
      // A 422 carries the problems as JSON; the last-status fetch below shows them.
      if (!(e instanceof ApiError && e.status === 422)) {
        setError(e instanceof Error ? e.message : String(e));
      }
    } finally {
      setBusy(false);
      load();
    }
  };

  const last: ReloadStatus | null = source?.last ?? null;
  return (
    <Alert
      severity={last && !last.ok ? "warning" : "info"}
      sx={{ mb: 2 }}
      action={
        canWriteConfig(me.role) && (
          <Button
            color="inherit"
            size="small"
            onClick={reload}
            disabled={busy}
            startIcon={busy ? <CircularProgress size={14} color="inherit" /> : <SyncIcon />}
          >
            Reload
          </Button>
        )
      }
    >
      <AlertTitle>Managed in files</AlertTitle>
      Groups and bundles are read from{" "}
      <Box component="code" sx={{ fontFamily: "monospace" }}>
        {source?.dir ?? "the configuration directory"}
      </Box>{" "}
      on the server. Change them there (for instance by committing and pulling), then reload.
      {last && (
        <Typography variant="body2" sx={{ mt: 1 }}>
          Last reload {fmtTime(last.at)}:{" "}
          {last.ok && last.report
            ? describeReport(last.report)
            : "failed — the server is still serving the last configuration that loaded."}
        </Typography>
      )}
      {last && !last.ok && (
        <Box component="ul" sx={{ my: 0.5, pl: 3 }}>
          {last.errors.map((e) => (
            <li key={e}>
              <Typography variant="body2" component="span" sx={{ fontFamily: "monospace" }}>
                {e}
              </Typography>
            </li>
          ))}
        </Box>
      )}
      {error && (
        <Typography variant="body2" sx={{ mt: 1 }}>
          {error}
        </Typography>
      )}
    </Alert>
  );
}
