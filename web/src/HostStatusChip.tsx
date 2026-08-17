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
 * What the host is doing, in one chip — the whole answer, so a list can be scanned without
 * opening rows.
 *
 * Filled chips are hosts we are in contact with; outlined ones never became running agents.
 * `never_enrolled` is deliberately the loudest of those two: it is terminal. The bootstrap
 * token expired without the install command being run, and there is no way to re-issue one
 * for an existing row — the host has to be deleted and added again.
 */
export function HostStatusChip({ host }: { host: HostView }) {
  switch (host.status) {
    case "in_sync":
      return (
        <Chip
          label="in sync"
          color="success"
          size="small"
          title={`Running the configuration we want, as of ${fmtTime(host.last_seen_at)}.`}
        />
      );
    // Informational rather than amber on purpose: every configuration change puts the whole
    // fleet here for a poll interval, and a rollout in progress is not a fault.
    case "out_of_sync":
      return (
        <Chip
          label="out of sync"
          color="info"
          size="small"
          title={
            host.current_state_hash
              ? "The configuration this host reports having applied is not the one we would " +
                "send it now. Normal for a poll interval after a change; if it persists, check " +
                "the host page for the errors it is reporting."
              : "This host has enrolled and is calling home, but has not yet reported applying " +
                "any configuration."
          }
        />
      );
    case "offline":
      return (
        <Chip
          label="offline"
          color="warning"
          size="small"
          title={
            `Nothing heard from this host since ${fmtTime(host.last_seen_at ?? host.enrolled_at)}` +
            " — several poll intervals ago. It may be rebooting or briefly off the network, but" +
            " it is not picking up changes in the meantime."
          }
        />
      );
    case "lost":
      return (
        <Chip
          label="lost"
          color="error"
          size="small"
          title={
            `Nothing heard from this host since ${fmtTime(host.last_seen_at ?? host.enrolled_at)}` +
            " — long enough that a blip does not explain it. Past the point of waiting it out:" +
            " check whether the service is stopped, the agent was removed, a firewall changed," +
            " or the machine is gone."
          }
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
