import { Alert, Box, Typography } from "@mui/material";
import { fmtTime, Me } from "./api";

/** What an expired tenant sees in place of every page: the server refuses their API calls
 *  with 402, so rather than each page surfacing that as a raw error, this says why once. */
export function TrialExpiredPage({ me }: { me: Me }) {
  return (
    <Box sx={{ maxWidth: 640 }}>
      <Typography variant="h4" gutterBottom>
        Trial expired
      </Typography>
      <Alert severity="warning" sx={{ mb: 2 }}>
        The trial for <strong>{me.tenant_name}</strong> ended
        {me.trial_expires_at ? ` on ${fmtTime(me.trial_expires_at)}` : ""}.
      </Alert>
      <Typography paragraph>
        Hosts, groups, bundles and the rest of the console are unavailable until the
        subscription is extended. Your configuration is kept, and enrolled agents keep running
        with the configuration they already have.
      </Typography>
      <Typography paragraph color="text.secondary">
        To continue, contact us to upgrade the <code>{me.tenant_slug}</code> tenant. Once that
        is done, reload this page.
      </Typography>
    </Box>
  );
}
