import { Chip } from "@mui/material";
import { fmtTime, HostView } from "./api";

/**
 * Shown when the agent reports that the host has configuration of its own.
 *
 * That configuration wins: NSClient resolves a key from the local store first and only falls
 * back to the fleet-managed include, so an in-sync host can still be running something other
 * than what this UI shows. Nothing is rendered for a host that reports none, or for one that
 * has never reported — the chip is a warning, and there is nothing to warn about in either
 * case. The host detail page distinguishes those two; a list row does not have the space to.
 */
export function LocalConfigChip({ host }: { host: HostView }) {
  if (host.local_config_present !== true) return null;
  return (
    <Chip
      label="local config"
      color="warning"
      size="small"
      variant="outlined"
      title={
        "This host has configuration of its own, which takes precedence over anything the " +
        "fleet sends it. The agent reports only that this is the case — never what is " +
        "configured locally."
      }
    />
  );
}

/**
 * The host lifecycle, in one chip.
 *
 * `never_enrolled` is deliberately the loudest of the three: it is terminal. The bootstrap
 * token expired without the install command being run, and there is no way to re-issue one
 * for an existing row — the host has to be deleted and added again.
 */
export function HostStatusChip({ host }: { host: HostView }) {
  switch (host.status) {
    case "enrolled":
      return (
        <Chip
          label="enrolled"
          color="success"
          size="small"
          title={`Enrolled ${fmtTime(host.enrolled_at)}`}
        />
      );
    case "awaiting_enrollment":
      return (
        <Chip
          label="awaiting enrollment"
          color="warning"
          size="small"
          variant="outlined"
          title={`Added, but the install command has not been run yet. The token is valid until ${fmtTime(
            host.bootstrap_expires_at,
          )}.`}
        />
      );
    case "never_enrolled":
      return (
        <Chip
          label="never enrolled"
          color="error"
          size="small"
          variant="outlined"
          title={
            "The install command was never run and the bootstrap token has expired, so this " +
            "host can no longer enroll. Delete it and add it again to get a fresh command."
          }
        />
      );
  }
}
