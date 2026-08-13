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
import GroupIcon from "@mui/icons-material/Group";
import KeyIcon from "@mui/icons-material/Key";
import AdminPanelSettingsIcon from "@mui/icons-material/AdminPanelSettings";
import { canManageUsers, Me } from "./api";

export type Page = "hosts" | "groups" | "bundles" | "audit" | "users" | "keys" | "platform";

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

type MenuItemDef = { id: Page; label: string; icon: JSX.Element };

/// Groups are rendered with a divider between them. The last group is hidden entirely for
/// roles that cannot manage users — the API refuses them anyway, so a visible-but-broken
/// entry would only be a dead end.
function menuFor(me: Me): MenuItemDef[][] {
  const groups: MenuItemDef[][] = [
    [{ id: "hosts", label: "Hosts", icon: <DnsIcon /> }],
    [
      { id: "groups", label: "Groups", icon: <WorkspacesIcon /> },
      { id: "bundles", label: "Bundles", icon: <Inventory2Icon /> },
    ],
    [{ id: "audit", label: "Audit log", icon: <HistoryIcon /> }],
    // Own-account settings: any role has keys, because a read-only key is a legitimate
    // thing to want.
    [{ id: "keys", label: "API keys", icon: <KeyIcon /> }],
  ];
  if (canManageUsers(me.role)) {
    groups.push([{ id: "users", label: "Users", icon: <GroupIcon /> }]);
  }
  // Last, and in a group of its own: this one leaves the tenant entirely. Most operators of
  // this UI are customers who will never see it.
  if (me.is_platform_admin) {
    groups.push([{ id: "platform", label: "Platform", icon: <AdminPanelSettingsIcon /> }]);
  }
  return groups;
}

function SideMenu({
  me,
  page,
  onNavigate,
}: {
  me: Me;
  page: Page;
  onNavigate: (p: Page) => void;
}) {
  return (
    <div>
      <Toolbar />
      {menuFor(me).map((group, i) => (
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
  me: Me;
  page: Page;
  onNavigate: (p: Page) => void;
  mobileOpen: boolean;
  onTransitionEnd: () => void;
  onClose: () => void;
};

export function SideBar({ me, page, onNavigate, mobileOpen, onTransitionEnd, onClose }: Props) {
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
        <SideMenu me={me} page={page} onNavigate={onNavigate} />
      </Drawer>
      <Drawer
        variant="permanent"
        sx={{
          display: { xs: "none", sm: "block" },
          "& .MuiDrawer-paper": { boxSizing: "border-box", width: drawerWidth },
        }}
        open
      >
        <SideMenu me={me} page={page} onNavigate={onNavigate} />
      </Drawer>
    </Box>
  );
}
