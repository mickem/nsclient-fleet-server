import { useEffect, useState } from "react";
import { useMatch, useNavigate, useParams } from "react-router-dom";
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  MenuItem,
  Select,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import AddIcon from "@mui/icons-material/Add";
import {
  apiGet,
  apiSend,
  AssignmentView,
  canWriteConfig,
  Me,
  BundleView,
  GroupView,
  HostView,
  PreviewMatch,
  Selector,
} from "./api";
import {
  describeSelector,
  KnownTags,
  knownTagsFromHosts,
  SelectorEditor,
  selectorIsHostControlled,
} from "./SelectorBuilder";
import { RefreshButton } from "./RefreshButton";

export function GroupsPage({ me }: { me: Me }) {
  const [groups, setGroups] = useState<GroupView[] | null>(null);
  const [bundles, setBundles] = useState<BundleView[]>([]);
  // The tags the fleet reports right now, so the selector editor can offer them. Derived
  // from the host list, which already carries every host's tags for the hosts page.
  const [known, setKnown] = useState<KnownTags>(() => new Map());
  // Which editor is open lives in the URL — /groups/new, or /groups/:id for the card
  // being edited — so the "Groups" sidebar entry closes it and a refresh reopens it.
  const navigate = useNavigate();
  const creating = useMatch("/groups/new") !== null;
  const { groupId: editingId } = useParams();
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  // Returns void, not the promise: `useEffect` below takes this directly, and a returned
  // promise would be mistaken for a cleanup function.
  const refresh = () => {
    setRefreshing(true);
    setError(null);
    void Promise.all([
      apiGet<GroupView[]>("/api/groups").then(setGroups, (e) => setError(e.message)),
      apiGet<BundleView[]>("/api/bundles").then(setBundles, () => {}),
      apiGet<HostView[]>("/api/hosts").then(
        (hosts) => setKnown(knownTagsFromHosts(hosts)),
        () => {},
      ),
    ]).finally(() => setRefreshing(false));
  };
  useEffect(refresh, []);

  return (
    <Box>
      <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 1 }}>
        <Typography variant="h4">Groups</Typography>
        <Stack direction="row" spacing={1} alignItems="center">
          <RefreshButton refreshing={refreshing} onClick={refresh} />
          {!creating && canWriteConfig(me.role) && (
            <Button variant="contained" startIcon={<AddIcon />} onClick={() => navigate("/groups/new")}>
              New group
            </Button>
          )}
        </Stack>
      </Stack>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        A group is a saved rule over host tags. Bundles assigned to a group apply to every host
        the rule matches.
      </Typography>
      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}
      {creating && (
        <GroupEditor
          known={known}
          initialName=""
          initialSelector={{ clauses: [] }}
          onCancel={() => navigate("/groups")}
          onSave={async (name, selector) => {
            await apiSend("POST", "/api/groups", { name, selector });
            navigate("/groups");
            refresh();
          }}
        />
      )}
      {groups === null ? (
        <Typography>Loading…</Typography>
      ) : groups.length === 0 && !creating ? (
        <Card>
          <CardContent>
            <Typography color="text.secondary">No groups yet.</Typography>
          </CardContent>
        </Card>
      ) : (
        <Stack spacing={2}>
          {groups.map((g) => (
            <GroupCard
              known={known}
              key={g.id}
              group={g}
              bundles={bundles}
              canWrite={canWriteConfig(me.role)}
              editing={editingId === g.id}
              onEdit={(open) => navigate(open ? `/groups/${g.id}` : "/groups")}
              onChanged={refresh}
            />
          ))}
        </Stack>
      )}
    </Box>
  );
}

function GroupCard({
  known,
  group,
  bundles,
  canWrite,
  editing,
  onEdit,
  onChanged,
}: {
  known: KnownTags;
  group: GroupView;
  bundles: BundleView[];
  canWrite: boolean;
  /** Whether this card's editor is open — decided by the URL, not held here. */
  editing: boolean;
  onEdit: (open: boolean) => void;
  onChanged: () => void;
}) {
  const [error, setError] = useState<string | null>(null);

  const remove = async () => {
    setError(null);
    try {
      await apiSend("DELETE", `/api/groups/${group.id}`);
      onChanged();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <Card variant="outlined">
      <CardContent>
        <Stack direction="row" justifyContent="space-between" alignItems="center">
          <Typography variant="h5">{group.name}</Typography>
          {canWrite && (
            <Stack direction="row" spacing={1}>
              <Button size="small" onClick={() => onEdit(!editing)}>
                {editing ? "Close" : "Edit"}
              </Button>
              <Button size="small" color="error" onClick={remove}>
                Delete
              </Button>
            </Stack>
          )}
        </Stack>
        {error && (
          <Alert severity="error" sx={{ my: 1 }}>
            {error}
          </Alert>
        )}
        <Typography
          variant="body2"
          sx={{ fontFamily: "monospace", color: "text.secondary", my: 1 }}
        >
          {describeSelector(group.selector)}
        </Typography>
        {selectorIsHostControlled(group.selector) && (
          <Alert severity="warning" sx={{ my: 1 }}>
            Hosts can join this group by reporting the tag themselves, and will then be served
            its bundles.
          </Alert>
        )}
        {editing && (
          <GroupEditor
            known={known}
            initialName={group.name}
            initialSelector={group.selector}
            onCancel={() => onEdit(false)}
            onSave={async (name, selector) => {
              await apiSend("PATCH", `/api/groups/${group.id}`, { name, selector });
              onEdit(false);
              onChanged();
            }}
          />
        )}
        <AssignmentsPanel groupId={group.id} bundles={bundles} />
      </CardContent>
    </Card>
  );
}

function GroupEditor({
  known,
  initialName,
  initialSelector,
  onSave,
  onCancel,
}: {
  known: KnownTags;
  initialName: string;
  initialSelector: Selector;
  onSave: (name: string, selector: Selector) => Promise<void>;
  onCancel: () => void;
}) {
  const [name, setName] = useState(initialName);
  const [selector, setSelector] = useState<Selector>(
    initialSelector.clauses ? initialSelector : { clauses: [] },
  );
  const [preview, setPreview] = useState<PreviewMatch[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const runPreview = async () => {
    setError(null);
    try {
      setPreview(await apiSend<PreviewMatch[]>("POST", "/api/groups/preview", { selector }));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const save = async () => {
    setError(null);
    try {
      await onSave(name.trim(), selector);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <Box sx={{ bgcolor: "background.default", p: 2, borderRadius: 1, my: 1 }}>
      <TextField
        size="small"
        label="Name"
        value={name}
        onChange={(e) => setName(e.target.value)}
        placeholder="sql-servers"
        sx={{ mb: 2 }}
      />
      <SelectorEditor selector={selector} onChange={setSelector} known={known} />
      {error && (
        <Alert severity="error" sx={{ my: 1 }}>
          {error}
        </Alert>
      )}
      <Stack direction="row" spacing={1} sx={{ mt: 2 }} alignItems="center">
        <Button size="small" onClick={runPreview}>
          Preview matching hosts
        </Button>
        <Button size="small" variant="contained" onClick={save} disabled={!name.trim()}>
          Save group
        </Button>
        <Button size="small" onClick={onCancel}>
          Cancel
        </Button>
      </Stack>
      {preview !== null && (
        <Typography variant="body2" sx={{ mt: 1 }}>
          {preview.length === 0
            ? "No hosts currently match."
            : `Matches ${preview.length} host(s): ` +
              preview.map((m) => m.hostname ?? m.id).join(", ")}
        </Typography>
      )}
    </Box>
  );
}

function AssignmentsPanel({ groupId, bundles }: { groupId: string; bundles: BundleView[] }) {
  const [assignments, setAssignments] = useState<AssignmentView[] | null>(null);
  const [bundleId, setBundleId] = useState("");
  const [priority, setPriority] = useState("100");
  const [error, setError] = useState<string | null>(null);

  const refresh = () => {
    apiGet<AssignmentView[]>(`/api/groups/${groupId}/bundles`).then(setAssignments, (e) =>
      setError(e.message),
    );
  };
  useEffect(refresh, [groupId]);

  const assign = async () => {
    if (!bundleId) return;
    setError(null);
    try {
      await apiSend("POST", `/api/groups/${groupId}/bundles`, {
        bundle_id: bundleId,
        priority: parseInt(priority, 10) || 100,
      });
      setBundleId("");
      refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const unassign = async (bid: string) => {
    setError(null);
    try {
      await apiSend("DELETE", `/api/groups/${groupId}/bundles/${bid}`);
      refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <Box sx={{ mt: 1 }}>
      <Typography variant="subtitle2" gutterBottom>
        Assigned bundles
      </Typography>
      {error && (
        <Alert severity="error" sx={{ mb: 1 }}>
          {error}
        </Alert>
      )}
      <Stack direction="row" spacing={1} useFlexGap sx={{ flexWrap: "wrap", mb: 1 }}>
        {assignments === null ? (
          <Typography variant="body2">Loading…</Typography>
        ) : assignments.length === 0 ? (
          <Typography variant="body2" color="text.secondary">
            No bundles assigned.
          </Typography>
        ) : (
          assignments.map((a) => (
            <Chip
              key={a.bundle_id}
              label={`${a.name}@${a.version} · p${a.priority}`}
              size="small"
              color="primary"
              onDelete={() => unassign(a.bundle_id)}
            />
          ))
        )}
      </Stack>
      <Stack direction="row" spacing={1} alignItems="center">
        <Select
          size="small"
          displayEmpty
          value={bundleId}
          onChange={(e) => setBundleId(e.target.value)}
          sx={{ minWidth: "14rem" }}
        >
          <MenuItem value="">
            <em>— pick a bundle —</em>
          </MenuItem>
          {bundles.map((b) => (
            <MenuItem key={b.id} value={b.id}>
              {b.name}@{b.version}
            </MenuItem>
          ))}
        </Select>
        <TextField
          size="small"
          label="Priority"
          value={priority}
          onChange={(e) => setPriority(e.target.value)}
          sx={{ width: "6rem" }}
        />
        <Button variant="contained" size="small" onClick={assign} disabled={!bundleId}>
          Assign
        </Button>
      </Stack>
    </Box>
  );
}
