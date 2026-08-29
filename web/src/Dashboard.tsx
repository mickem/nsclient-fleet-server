import { useState } from "react";
import { Box, Toolbar } from "@mui/material";
import { Outlet } from "react-router-dom";
import { Me } from "./api";
import { AppNavbar } from "./AppNavbar";
import { SideBar } from "./SideBar";

const drawerWidth = 240;

type Props = {
  me: Me;
  onLogout: () => void;
};

/** The signed-in chrome: navbar, sidebar, and whichever page the route selected. */
export function Dashboard({ me, onLogout }: Props) {
  const [mobileOpen, setMobileOpen] = useState(false);
  const [isClosing, setIsClosing] = useState(false);

  const handleDrawerClose = () => {
    setIsClosing(true);
    setMobileOpen(false);
  };
  const handleDrawerTransitionEnd = () => setIsClosing(false);
  const handleDrawerToggle = () => {
    if (!isClosing) setMobileOpen(!mobileOpen);
  };

  return (
    <Box sx={{ display: "flex" }}>
      <AppNavbar me={me} onLogout={onLogout} handleDrawerToggle={handleDrawerToggle} />
      <SideBar
        me={me}
        onNavigate={() => setMobileOpen(false)}
        mobileOpen={mobileOpen}
        onClose={handleDrawerClose}
        onTransitionEnd={handleDrawerTransitionEnd}
      />
      <Box
        component="main"
        sx={{
          flexGrow: 1,
          p: { xs: 2, sm: 3 },
          width: { sm: `calc(100% - ${drawerWidth}px)` },
        }}
      >
        <Toolbar />
        <Outlet />
      </Box>
    </Box>
  );
}
