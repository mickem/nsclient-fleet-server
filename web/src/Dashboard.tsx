import { useState } from "react";
import { Box, Toolbar } from "@mui/material";
import { Me } from "./api";
import { AppNavbar } from "./AppNavbar";
import { Page, SideBar } from "./SideBar";
import { HostsPage } from "./HostsPage";
import { HostDetailPage } from "./HostDetailPage";
import { GroupsPage } from "./GroupsPage";
import { BundlesPage } from "./BundlesPage";
import { AuditPage } from "./AuditPage";
import { UsersPage } from "./UsersPage";

const drawerWidth = 240;

type Props = {
  me: Me;
  onLogout: () => void;
};

export function Dashboard({ me, onLogout }: Props) {
  const [page, setPage] = useState<Page>("hosts");
  const [hostId, setHostId] = useState<string | null>(null);
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

  const navigate = (p: Page) => {
    setPage(p);
    setHostId(null);
    setMobileOpen(false);
  };

  return (
    <Box sx={{ display: "flex" }}>
      <AppNavbar me={me} onLogout={onLogout} handleDrawerToggle={handleDrawerToggle} />
      <SideBar
        me={me}
        page={page}
        onNavigate={navigate}
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
        {page === "hosts" &&
          (hostId ? (
            <HostDetailPage me={me} hostId={hostId} onBack={() => setHostId(null)} />
          ) : (
            <HostsPage me={me} onOpen={setHostId} />
          ))}
        {page === "groups" && <GroupsPage me={me} />}
        {page === "bundles" && <BundlesPage me={me} />}
        {page === "audit" && <AuditPage />}
        {page === "users" && <UsersPage me={me} />}
      </Box>
    </Box>
  );
}
