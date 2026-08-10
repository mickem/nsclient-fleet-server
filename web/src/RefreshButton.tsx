import { Button, CircularProgress } from "@mui/material";
import RefreshIcon from "@mui/icons-material/Refresh";

/**
 * Re-fetch affordance for a page's own data.
 *
 * Disabled while the fetch is in flight, because most refreshes change nothing on screen —
 * the spinner is the only feedback a click gets, so it has to be visible for as long as the
 * request takes.
 */
export function RefreshButton({
  refreshing,
  onClick,
}: {
  refreshing: boolean;
  onClick: () => void;
}) {
  return (
    <Button
      startIcon={refreshing ? <CircularProgress size={16} color="inherit" /> : <RefreshIcon />}
      onClick={onClick}
      disabled={refreshing}
    >
      Refresh
    </Button>
  );
}
