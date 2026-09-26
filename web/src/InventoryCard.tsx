import { useMemo, useState } from "react";
import {
  Alert,
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TextField,
  Typography,
} from "@mui/material";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import { FactChange, FactsChanges, FactsStatus, fmtAgo, fmtBytes, fmtTime, HostFacts } from "./api";

// The host's inventory ("facts"), as its agent last uploaded it. The document is generic:
// sections of scalars, lists of records (each with an `id`), and plain string lists. It is
// rendered by shape rather than by set, so a set a newer agent adds shows up without a UI
// change.

type Obj = Record<string, unknown>;

const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);

// Ids should be unique within a list, but a Windows software inventory does produce
// duplicates, so nothing here keys on the id alone.
const isRecordList = (v: unknown): v is Obj[] =>
  Array.isArray(v) && v.length > 0 && v.every((x) => isObj(x) && typeof x.id === "string");

type StatusLook = { label: string; color: "success" | "info" | "warning" | "default" };

const STATUS: Record<FactsStatus, StatusLook> = {
  current: { label: "Up to date", color: "success" },
  pending: { label: "Inventory on its way", color: "info" },
  outdated: { label: "Newer inventory pending", color: "warning" },
  nothing_enabled: { label: "No fact sets enabled", color: "default" },
  switched_off: { label: "Switched off", color: "default" },
  not_reported: { label: "Not reported", color: "default" },
};

/** A status this bundle does not know yet (a server newer than the web UI) is shown by its
 *  name rather than breaking the page. */
function statusLook(status: string): StatusLook {
  return STATUS[status as FactsStatus] ?? { label: status.replace(/_/g, " "), color: "default" };
}

/** The key a change's value sits under, for its unit: `speed_bps` in
 *  `network.interfaces[eth0.100].speed_bps`. A path ending in a record (`…[eth0.100]`) names
 *  no key, and an id may itself contain dots, so this is not "whatever follows the last dot". */
function leafKey(path: string): string {
  const m = /(?:^|\.)([A-Za-z0-9_]+)$/.exec(path);
  return m ? m[1] : "";
}

/** A value as text, using the unit a key carries (`size_bytes`, `speed_bps`). */
function fmtValue(key: string, v: unknown): string {
  if (v === undefined || v === null) return "";
  if (typeof v === "boolean") return v ? "yes" : "no";
  if (typeof v === "number") {
    if (key.endsWith("_bytes")) return fmtBytes(v);
    if (key.endsWith("_bps")) return fmtBps(v);
    return v.toLocaleString();
  }
  if (Array.isArray(v)) return v.map((x) => fmtValue(key, x)).join(", ");
  if (typeof v === "string") return v;
  return JSON.stringify(v);
}

function fmtBps(n: number): string {
  if (n >= 1e9) return `${+(n / 1e9).toFixed(1)} Gbps`;
  if (n >= 1e6) return `${+(n / 1e6).toFixed(1)} Mbps`;
  if (n >= 1e3) return `${+(n / 1e3).toFixed(1)} kbps`;
  return `${n} bps`;
}

type Block =
  | { kind: "values"; path: string; rows: [string, unknown][] }
  | { kind: "records"; path: string; records: Obj[] };

/** Flatten one set into blocks: a table of the scalars of each section, and one table per
 *  record list. */
function blocksOf(path: string, value: unknown): Block[] {
  if (isRecordList(value)) return [{ kind: "records", path, records: value }];
  if (!isObj(value)) return [{ kind: "values", path, rows: [[path, value]] }];
  const rows: [string, unknown][] = [];
  const nested: Block[] = [];
  for (const key of Object.keys(value).sort()) {
    const v = value[key];
    const p = `${path}.${key}`;
    if (isRecordList(v)) nested.push({ kind: "records", path: p, records: v });
    else if (isObj(v)) nested.push(...blocksOf(p, v));
    else rows.push([key, Array.isArray(v) && v.length === 0 ? "—" : v]);
  }
  return rows.length > 0 ? [{ kind: "values", path, rows }, ...nested] : nested;
}

function countRecords(blocks: Block[]): number {
  return blocks.reduce((n, b) => n + (b.kind === "records" ? b.records.length : 0), 0);
}

function ValuesTable({ rows }: { rows: [string, unknown][] }) {
  return (
    <Table size="small" sx={{ mb: 1 }}>
      <TableBody>
        {rows.map(([k, v]) => (
          <TableRow key={k}>
            <TableCell sx={{ width: "12rem", color: "text.secondary", verticalAlign: "top" }}>
              {k}
            </TableCell>
            <TableCell sx={{ wordBreak: "break-word" }}>{fmtValue(k, v)}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

const PAGE = 50;

function RecordsTable({ records }: { records: Obj[] }) {
  const [filter, setFilter] = useState("");
  const [showAll, setShowAll] = useState(false);
  // `id` first, then every other key in the order records first use it.
  const columns = useMemo(() => {
    const cols = ["id"];
    for (const r of records) for (const k of Object.keys(r)) if (!cols.includes(k)) cols.push(k);
    return cols;
  }, [records]);
  const needle = filter.trim().toLowerCase();
  const matching = needle
    ? records.filter((r) => columns.some((c) => fmtValue(c, r[c]).toLowerCase().includes(needle)))
    : records;
  const shown = showAll ? matching : matching.slice(0, PAGE);
  return (
    <Box sx={{ mb: 1 }}>
      {records.length > 10 && (
        <TextField
          size="small"
          placeholder={`Filter ${records.length} records`}
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          sx={{ mb: 1, minWidth: "16rem" }}
        />
      )}
      <Box sx={{ overflowX: "auto" }}>
        <Table size="small">
          <TableHead>
            <TableRow>
              {columns.map((c) => (
                <TableCell key={c} sx={{ whiteSpace: "nowrap" }}>
                  {c}
                </TableCell>
              ))}
            </TableRow>
          </TableHead>
          <TableBody>
            {shown.map((r, i) => (
              <TableRow key={`${i}:${String(r.id)}`}>
                {columns.map((c) => (
                  <TableCell key={c} sx={c === "id" ? { fontFamily: "monospace" } : undefined}>
                    {fmtValue(c, r[c])}
                  </TableCell>
                ))}
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Box>
      {matching.length > shown.length && (
        <Button size="small" onClick={() => setShowAll(true)} sx={{ mt: 0.5 }}>
          Show all {matching.length}
        </Button>
      )}
      {needle && matching.length === 0 && (
        <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
          No record matches.
        </Typography>
      )}
    </Box>
  );
}

function FactSetSection({ name, value }: { name: string; value: unknown }) {
  const blocks = useMemo(() => blocksOf(name, value), [name, value]);
  const records = countRecords(blocks);
  const summary =
    records > 0
      ? `${records} record${records === 1 ? "" : "s"}`
      : `${blocks[0]?.kind === "values" ? blocks[0].rows.length : 0} values`;
  return (
    <Accordion disableGutters variant="outlined" defaultExpanded={records <= PAGE}>
      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
        <Typography sx={{ fontFamily: "monospace", mr: 1 }}>{name}</Typography>
        <Typography variant="body2" color="text.secondary">
          {summary}
        </Typography>
      </AccordionSummary>
      <AccordionDetails>
        {blocks.length === 0 && (
          <Typography variant="body2" color="text.secondary">
            Empty.
          </Typography>
        )}
        {blocks.map((b) => (
          <Box key={b.path}>
            {b.path !== name && (
              <Typography variant="subtitle2" sx={{ fontFamily: "monospace", mt: 1 }}>
                {b.path}
              </Typography>
            )}
            {b.kind === "values" ? (
              <ValuesTable rows={b.rows} />
            ) : (
              <RecordsTable records={b.records} />
            )}
          </Box>
        ))}
      </AccordionDetails>
    </Accordion>
  );
}

const CHANGE_COLOR: Record<FactChange["kind"], "success" | "error" | "info"> = {
  added: "success",
  removed: "error",
  changed: "info",
};

function ChangeLine({ c }: { c: FactChange }) {
  const leaf = leafKey(c.path);
  const detail =
    c.kind === "changed" && (c.old !== undefined || c.new !== undefined)
      ? `${fmtValue(leaf, c.old) || "—"} → ${fmtValue(leaf, c.new) || "—"}`
      : c.kind === "added" && c.new !== undefined
        ? fmtValue(leaf, c.new)
        : c.kind === "removed" && c.old !== undefined
          ? fmtValue(leaf, c.old)
          : "";
  return (
    <Stack direction="row" spacing={1} alignItems="baseline" sx={{ py: 0.25 }}>
      <Chip
        label={c.kind}
        size="small"
        color={CHANGE_COLOR[c.kind]}
        variant="outlined"
        sx={{ height: 20, minWidth: "4.5rem" }}
      />
      <Typography variant="body2" sx={{ fontFamily: "monospace", wordBreak: "break-all" }}>
        {c.path}
      </Typography>
      {detail && (
        <Typography variant="body2" color="text.secondary" sx={{ wordBreak: "break-word" }}>
          {detail}
        </Typography>
      )}
    </Stack>
  );
}

const CHANGES_SHOWN = 10;

function ChangeEntry({ entry }: { entry: FactsChanges }) {
  const [all, setAll] = useState(false);
  const shown = all ? entry.changes : entry.changes.slice(0, CHANGES_SHOWN);
  const hidden = entry.changes.length - shown.length;
  return (
    <Box sx={{ mb: 1.5 }}>
      <Typography variant="caption" color="text.secondary">
        {fmtTime(entry.at)}
      </Typography>
      {entry.initial ? (
        <Typography variant="body2">First inventory received.</Typography>
      ) : (
        shown.map((c) => <ChangeLine key={`${c.kind}:${c.path}`} c={c} />)
      )}
      {hidden > 0 && (
        <Button size="small" onClick={() => setAll(true)}>
          {hidden} more
        </Button>
      )}
      {entry.truncated > 0 && (
        <Typography variant="caption" color="text.secondary" display="block">
          …and {entry.truncated} more change{entry.truncated === 1 ? "" : "s"} not recorded
          individually.
        </Typography>
      )}
    </Box>
  );
}

/** What to tell the operator when there is no inventory to show. */
function emptyExplanation(status: FactsStatus): string {
  switch (status) {
    case "pending":
    case "outdated":
      // `outdated` with an empty document: the sets were switched back on after a clear.
      return "The agent has an inventory for this host and sends it after its next poll.";
    case "not_reported":
      return (
        "This agent has not reported an inventory hash — it may predate host facts, or has " +
        "not polled since the server was upgraded. To collect an inventory, assign a bundle " +
        "made from the “Host inventory (facts)” template to a group this host is in."
      );
    default:
      return (
        "No fact sets are enabled on this host. Assign a bundle made from the “Host " +
        "inventory (facts)” template to a group this host is in, and pick the sets to collect."
      );
  }
}

export function InventoryCard({
  facts,
  error,
}: {
  facts: HostFacts | null;
  /** Why the inventory could not be loaded, when it could not. */
  error?: string | null;
}) {
  const [showHistory, setShowHistory] = useState(false);
  const sets = facts?.facts ? Object.keys(facts.facts).sort() : [];
  const history = facts?.changes ?? [];
  return (
    <Card variant="outlined">
      <CardContent>
        <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1 }}>
          <Typography variant="h5" sx={{ flexGrow: 1 }}>
            Inventory
          </Typography>
          {facts && (
            <Chip
              label={statusLook(facts.status).label}
              color={statusLook(facts.status).color}
              size="small"
              variant={facts.status === "current" ? "filled" : "outlined"}
            />
          )}
        </Stack>
        {!facts && error ? (
          <Alert severity="error">Could not load the inventory: {error}</Alert>
        ) : !facts ? (
          <Typography>Loading…</Typography>
        ) : (
          <>
            {facts.facts_hash && (
              <Typography variant="caption" color="text.secondary" display="block" sx={{ mb: 1.5 }}>
                {facts.collected_at && <>collected {fmtCollected(facts.collected_at)} · </>}
                received {fmtAgo(facts.received_at)}
                {facts.size_bytes !== null && <> · {fmtBytes(facts.size_bytes)}</>}
                {facts.status === "outdated" &&
                  " · the agent has a newer inventory, which follows its next poll"}
                {facts.status === "switched_off" &&
                  " · every fact set was switched off on the host; this inventory is cleared " +
                    "once it has stayed off for ten minutes"}
              </Typography>
            )}
            {sets.length === 0 ? (
              <Typography variant="body2" color="text.secondary">
                {
                  // By status, not by whether a document is stored: an empty one stored after
                  // a clear stays until the agent's new inventory arrives.
                  emptyExplanation(facts.status)
                }
              </Typography>
            ) : (
              <Box>
                {sets.map((name) => (
                  <FactSetSection key={name} name={name} value={facts.facts![name]} />
                ))}
              </Box>
            )}
            {history.length > 0 && (
              <Box sx={{ mt: 2 }}>
                <Stack direction="row" alignItems="center" spacing={1}>
                  <Typography variant="h6">Recent changes</Typography>
                  <Button size="small" onClick={() => setShowHistory((v) => !v)}>
                    {showHistory ? "Hide" : `Show ${history.length}`}
                  </Button>
                </Stack>
                {showHistory && history.map((e) => <ChangeEntry key={e.id} entry={e} />)}
              </Box>
            )}
          </>
        )}
      </CardContent>
    </Card>
  );
}

/** The agent's own timestamp, in the viewer's time zone when it parses. */
function fmtCollected(iso: string): string {
  const t = Date.parse(iso);
  return Number.isNaN(t) ? iso : new Date(t).toLocaleString();
}
