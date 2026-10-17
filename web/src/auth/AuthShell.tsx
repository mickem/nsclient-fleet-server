import { ReactNode } from "react";
import AppBar from "@mui/material/AppBar";
import { Box, Card, CardContent, Grid, Toolbar } from "@mui/material";
import Typography from "@mui/material/Typography";

// Shared frame for the unauthenticated pages — mirrors the NSClient++ web UI's Login
// layout: plain AppBar, centered card.
export function AuthShell({ title, children }: { title: string; children: ReactNode }) {
  return (
    <Box sx={{ width: "100vw", height: "100vh" }}>
      <AppBar position="static">
        <Toolbar>
          <Typography variant="h6">NSClient · Fleet</Typography>
        </Toolbar>
      </AppBar>
      <Box sx={{ p: 3 }}>
        <Toolbar />
        <Grid container sx={{ justifyContent: "center" }}>
          <Grid>
            <Card sx={{ width: 380, p: 2 }}>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  {title}
                </Typography>
                {children}
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </Box>
    </Box>
  );
}
