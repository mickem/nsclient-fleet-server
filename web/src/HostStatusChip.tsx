import { Chip } from "@mui/material";
import { fmtTime, HostView } from "./api";

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
