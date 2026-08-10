import { styled } from "@mui/material/styles";
import MuiDrawer, { drawerClasses } from "@mui/material/Drawer";
import Box from "@mui/material/Box";
import { Toolbar } from "@mui/material";
import Divider from "@mui/material/Divider";
import { List, ListItem, ListItemButton, ListItemIcon, ListItemText } from "@mui/material";
import DnsIcon from "@mui/icons-material/Dns";
import WorkspacesIcon from "@mui/icons-material/Workspaces";
import Inventory2Icon from "@mui/icons-material/Inventory2";
import HistoryIcon from "@mui/icons-material/History";

export type Page = "hosts" | "groups" | "bundles" | "audit";

const drawerWidth = 240;

const Drawer = styled(MuiDrawer)({
  width: drawerWidth,
  flexShrink: 0,
  boxSizing: "border-box",
  mt: 10,
  [`& .${drawerClasses.paper}`]: {
    width: drawerWidth,
    boxSizing: "border-box",
  },
});

const MENU: { id: Page; label: string; icon: JSX.Element }[][] = [
  [{ id: "hosts", label: "Hosts", icon: <DnsIcon /> }],
  [
    { id: "groups", label: "Groups", icon: <WorkspacesIcon /> },
    { id: "bundles", label: "Bundles", icon: <Inventory2Icon /> },
  ],
  [{ id: "audit", label: "Audit log", icon: <HistoryIcon /> }],
];

function SideMenu({ page, onNavigate }: { page: Page; onNavigate: (p: Page) => void }) {
  return (
    <div>
      <Toolbar />
      {MENU.map((group, i) => (
        <div key={i}>
          {i > 0 && <Divider />}
          <List>
            {group.map((item) => (
              <ListItem key={item.id} disablePadding>
                <ListItemButton selected={page === item.id} onClick={() => onNavigate(item.id)}>
                  <ListItemIcon>{item.icon}</ListItemIcon>
                  <ListItemText primary={item.label} />
                </ListItemButton>
              </ListItem>
            ))}
          </List>
        </div>
      ))}
    </div>
  );
}

type Props = {
  page: Page;
  onNavigate: (p: Page) => void;
  mobileOpen: boolean;
  onTransitionEnd: () => void;
  onClose: () => void;
};

export function SideBar({ page, onNavigate, mobileOpen, onTransitionEnd, onClose }: Props) {
  return (
    <Box component="nav" sx={{ width: { sm: drawerWidth }, flexShrink: { sm: 0 } }}>
      <Toolbar />
      <Drawer
        variant="temporary"
        open={mobileOpen}
        onTransitionEnd={onTransitionEnd}
        onClose={onClose}
        ModalProps={{ keepMounted: true }}
        sx={{
          display: { xs: "block", sm: "none" },
          "& .MuiDrawer-paper": { boxSizing: "border-box", width: drawerWidth },
        }}
      >
        <SideMenu page={page} onNavigate={onNavigate} />
      </Drawer>
      <Drawer
        variant="permanent"
        sx={{
          display: { xs: "none", sm: "block" },
          "& .MuiDrawer-paper": { boxSizing: "border-box", width: drawerWidth },
        }}
        open
      >
        <SideMenu page={page} onNavigate={onNavigate} />
      </Drawer>
    </Box>
  );
}
