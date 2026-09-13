import {
  Alert,
  Autocomplete,
  Box,
  Button,
  IconButton,
  MenuItem,
  Select,
  Stack,
  TextField,
  Tooltip,
  Typography,
} from "@mui/material";
import CloseIcon from "@mui/icons-material/Close";
import AddIcon from "@mui/icons-material/Add";
import { Expr, HostView, Selector, SourceFilter, TagView } from "./api";

// Structured selector editor — every field is a discrete input; the selector is never
// entered as raw text (locked design decision from PLAN.md).

/** What the fleet currently reports: tag key → value → number of hosts carrying it. Feeds
 *  the key and value pickers so an operator chooses from what exists (os, os_name,
 *  os_version, the service tags…) instead of guessing spellings. Free text still works —
 *  a group is often written before the first host that will match it enrolls. */
/** What the fleet currently reports under one tag key: the values and their host counts,
 *  and which sources those values came from. The sources matter because a clause reading a
 *  key only ever reported by agents has to say so, or it silently matches nothing. */
export type KnownTag = { values: Map<string, number>; sources: Set<TagView["source"]> };
export type KnownTags = Map<string, KnownTag>;

export function knownTagsFromHosts(hosts: HostView[]): KnownTags {
  const out: KnownTags = new Map();
  for (const h of hosts) {
    for (const t of h.tags) {
      let known = out.get(t.key);
      if (!known) {
        known = { values: new Map(), sources: new Set() };
        out.set(t.key, known);
      }
      known.values.set(t.value, (known.values.get(t.value) ?? 0) + 1);
      known.sources.add(t.source);
    }
  }
  return out;
}

/** The source filter a clause on `key` should carry, given what the fleet reports.
 *
 *  A key the fleet only ever reports from agents — anything published by the service-tags
 *  template, for instance — needs `agent`, because the default is operator-set tags and a
 *  clause reading one of those would match nothing at all. Returns null when there is
 *  nothing to say: an unknown key, or one operators do set, both keep the safe default.
 *
 *  This is the one place the safe default is relaxed automatically, and it is not silent:
 *  the leaf's own dropdown shows "host-reported" and the editor shows the warning above. */
export function suggestedSource(known: KnownTags | undefined, key: string): SourceFilter | null {
  const sources = known?.get(key)?.sources;
  if (!sources || sources.size !== 1) return null;
  return sources.has("agent") ? "agent" : null;
}

const hostCount = (n: number) => `${n} host${n === 1 ? "" : "s"}`;

/** Free-text input with a dropdown of what the fleet already reports. `options` carry the
 *  host count so the common choice is recognisable at a glance. */
function TagAutocomplete({
  value,
  onChange,
  options,
  placeholder,
  minWidth,
}: {
  value: string;
  onChange: (v: string) => void;
  options: [string, number][];
  placeholder: string;
  minWidth: string;
}) {
  const counts = new Map(options);
  return (
    <Autocomplete
      freeSolo
      size="small"
      options={options.map(([v]) => v)}
      inputValue={value}
      onInputChange={(_, v) => onChange(v)}
      renderOption={(props, option) => {
        const { key, ...rest } = props as typeof props & { key?: string };
        return (
          <li key={key ?? option} {...rest}>
            <Stack direction="row" spacing={1} alignItems="baseline" sx={{ width: "100%" }}>
              <Typography component="span" sx={{ fontFamily: "monospace" }}>
                {option}
              </Typography>
              <Typography component="span" variant="caption" color="text.secondary">
                {hostCount(counts.get(option) ?? 0)}
              </Typography>
            </Stack>
          </li>
        );
      }}
      sx={{ minWidth }}
      renderInput={(params) => <TextField {...params} size="small" placeholder={placeholder} />}
    />
  );
}

/** Keys sorted by how many hosts carry them, then by name. */
function keyOptions(known: KnownTags | undefined): [string, number][] {
  if (!known) return [];
  return [...known.entries()]
    .map(([k, t]): [string, number] => [k, [...t.values.values()].reduce((a, b) => a + b, 0)])
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
}

/** Values reported under `key`, most common first. */
function valueOptions(known: KnownTags | undefined, key: string): [string, number][] {
  const values = known?.get(key)?.values;
  if (!values) return [];
  return [...values.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
}

const OPS: { id: Expr["op"]; label: string }[] = [
  { id: "eq", label: "equals" },
  { id: "in", label: "in list" },
  { id: "exists", label: "exists" },
  { id: "not", label: "NOT" },
  { id: "and", label: "AND group" },
  { id: "or", label: "OR group" },
];

/** The three trust settings a leaf can have, in the order an operator should consider
 *  them: the safe default first, then the two that hand the decision to the host. */
const SOURCES: { id: SourceFilter; label: string; help: string }[] = [
  {
    id: "manual",
    label: "operator tags",
    help: "Only tags an operator set here. Hosts cannot put themselves in this group.",
  },
  {
    id: "agent",
    label: "host-reported",
    help:
      "Only tags the host reports about itself. A compromised host can claim this tag and " +
      "join the group, so it will receive whatever bundles the group carries.",
  },
  {
    id: "any",
    label: "either source",
    help:
      "An operator tag or one the host reports. A compromised host can claim this tag and " +
      "join the group, so it will receive whatever bundles the group carries.",
  },
];

type Leaf = Extract<Expr, { op: "eq" | "in" | "exists" }>;

/** Leaves default to operator-set tags, matching the server's serde default. */
function sourceOf(e: Leaf): SourceFilter {
  return e.source ?? "manual";
}

function isHostControlled(e: Expr): boolean {
  switch (e.op) {
    case "eq":
    case "in":
    case "exists":
      return sourceOf(e) !== "manual";
    case "not":
      return isHostControlled(e.expr);
    case "and":
    case "or":
      return e.exprs.some(isHostControlled);
  }
}

export function selectorIsHostControlled(s: Selector): boolean {
  return (s.clauses ?? []).some(isHostControlled);
}

export function defaultExpr(op: Expr["op"]): Expr {
  switch (op) {
    case "eq":
      return { op: "eq", key: "", value: "" };
    case "in":
      return { op: "in", key: "", values: [""] };
    case "exists":
      return { op: "exists", key: "" };
    case "not":
      return { op: "not", expr: { op: "eq", key: "", value: "" } };
    case "and":
      return { op: "and", exprs: [{ op: "eq", key: "", value: "" }] };
    case "or":
      return { op: "or", exprs: [{ op: "eq", key: "", value: "" }] };
  }
}

type ExprProps = {
  expr: Expr;
  onChange: (e: Expr) => void;
  onRemove?: () => void;
  /** Tags the fleet reports today, for the pickers. Optional: without it every input is
   *  plain free text. */
  known?: KnownTags;
};

export function ExprEditor({ expr, onChange, onRemove, known }: ExprProps) {
  const opSelect = (
    <Select
      size="small"
      value={expr.op}
      onChange={(e) => onChange(defaultExpr(e.target.value as Expr["op"]))}
    >
      {OPS.map((o) => (
        <MenuItem key={o.id} value={o.id}>
          {o.label}
        </MenuItem>
      ))}
    </Select>
  );

  /** Rendered on every leaf, because which source a clause trusts is as much part of what
   *  it means as the key and the value. */
  const sourceSelect = (leaf: Leaf) => {
    const current = sourceOf(leaf);
    return (
      <Tooltip title={SOURCES.find((s) => s.id === current)?.help ?? ""}>
        <Select
          size="small"
          value={current}
          color={current === "manual" ? undefined : "warning"}
          onChange={(e) => onChange({ ...leaf, source: e.target.value as SourceFilter })}
        >
          {SOURCES.map((s) => (
            <MenuItem key={s.id} value={s.id}>
              {s.label}
            </MenuItem>
          ))}
        </Select>
      </Tooltip>
    );
  };
  const removeBtn = onRemove ? (
    <IconButton size="small" onClick={onRemove} title="remove clause">
      <CloseIcon fontSize="small" />
    </IconButton>
  ) : null;

  /** Set a leaf's key, adopting the source the fleet actually reports that key under.
   *
   *  Without this, picking a key the service-tags template publishes gives a clause that
   *  matches nothing and says nothing about why — the kind of dead end people escape by
   *  setting every clause to "either source". The dropdown beside it shows what was chosen. */
  const withKey = <T extends Leaf>(leaf: T, key: string): T => {
    const suggested = suggestedSource(known, key);
    return suggested ? { ...leaf, key, source: suggested } : { ...leaf, key };
  };

  const keyInput = (key: string, set: (k: string) => void) => (
    <TagAutocomplete
      value={key}
      onChange={set}
      options={keyOptions(known)}
      placeholder="tag key"
      minWidth="12rem"
    />
  );
  const valueInput = (key: string, value: string, set: (v: string) => void, placeholder: string) => (
    <TagAutocomplete
      value={value}
      onChange={set}
      options={valueOptions(known, key)}
      placeholder={placeholder}
      minWidth="12rem"
    />
  );

  switch (expr.op) {
    case "eq":
      return (
        <Stack direction="row" spacing={1} alignItems="center" useFlexGap sx={{ flexWrap: "wrap" }}>
          {opSelect}
          {keyInput(expr.key, (key) => onChange(withKey(expr, key)))}
          <Typography>=</Typography>
          {valueInput(expr.key, expr.value, (value) => onChange({ ...expr, value }), "value")}
          {sourceSelect(expr)}
          {removeBtn}
        </Stack>
      );
    case "in":
      return (
        <Stack direction="row" spacing={1} alignItems="center" useFlexGap sx={{ flexWrap: "wrap" }}>
          {opSelect}
          {keyInput(expr.key, (key) => onChange(withKey(expr, key)))}
          <Typography>∈</Typography>
          {expr.values.map((v, i) => (
            <Box key={i}>
              {valueInput(
                expr.key,
                v,
                (value) => {
                  const values = [...expr.values];
                  values[i] = value;
                  onChange({ ...expr, values });
                },
                `value ${i + 1}`,
              )}
            </Box>
          ))}
          <Button size="small" onClick={() => onChange({ ...expr, values: [...expr.values, ""] })}>
            + value
          </Button>
          {expr.values.length > 1 && (
            <Button size="small" onClick={() => onChange({ ...expr, values: expr.values.slice(0, -1) })}>
              − value
            </Button>
          )}
          {sourceSelect(expr)}
          {removeBtn}
        </Stack>
      );
    case "exists":
      return (
        <Stack direction="row" spacing={1} alignItems="center" useFlexGap sx={{ flexWrap: "wrap" }}>
          {opSelect}
          {keyInput(expr.key, (key) => onChange(withKey(expr, key)))}
          {sourceSelect(expr)}
          {removeBtn}
        </Stack>
      );
    case "not":
      return (
        <Stack direction="row" spacing={1} alignItems="flex-start" useFlexGap sx={{ flexWrap: "wrap" }}>
          {opSelect}
          <Box sx={{ borderLeft: 3, borderColor: "error.main", pl: 1 }}>
            <ExprEditor
              expr={expr.expr}
              known={known}
              onChange={(inner) => onChange({ ...expr, expr: inner })}
            />
          </Box>
          {removeBtn}
        </Stack>
      );
    case "and":
    case "or":
      return (
        <Stack direction="row" spacing={1} alignItems="flex-start" useFlexGap sx={{ flexWrap: "wrap" }}>
          {opSelect}
          <Stack
            spacing={1}
            sx={{
              borderLeft: 3,
              borderColor: expr.op === "and" ? "success.main" : "info.main",
              pl: 1,
            }}
          >
            {expr.exprs.map((child, i) => (
              <ExprEditor
                key={i}
                expr={child}
                known={known}
                onChange={(c) => {
                  const exprs = [...expr.exprs];
                  exprs[i] = c;
                  onChange({ ...expr, exprs });
                }}
                onRemove={
                  expr.exprs.length > 1
                    ? () => onChange({ ...expr, exprs: expr.exprs.filter((_, j) => j !== i) })
                    : undefined
                }
              />
            ))}
            <Button
              size="small"
              startIcon={<AddIcon />}
              sx={{ alignSelf: "flex-start" }}
              onClick={() => onChange({ ...expr, exprs: [...expr.exprs, defaultExpr("eq")] })}
            >
              clause
            </Button>
          </Stack>
          {removeBtn}
        </Stack>
      );
  }
}

type SelectorProps = {
  selector: Selector;
  onChange: (s: Selector) => void;
  /** See `ExprProps.known`. */
  known?: KnownTags;
};

export function SelectorEditor({ selector, onChange, known }: SelectorProps) {
  return (
    <Stack spacing={1}>
      <Typography variant="caption" color="text.secondary">
        All top-level clauses must match (implicit AND). An empty selector matches every host.
        Each clause says which tags it trusts: operator-set tags, tags the host reports about
        itself, or either.
      </Typography>
      {selectorIsHostControlled(selector) && (
        <Alert severity="warning">
          A clause here trusts host-reported tags, so a host can put <em>itself</em> in this
          group by claiming that tag — and will then be served this group&apos;s bundles.
          Use operator tags for anything that gates access to scripts or secrets.
        </Alert>
      )}
      {selector.clauses.map((c, i) => (
        <ExprEditor
          key={i}
          expr={c}
          known={known}
          onChange={(e) => {
            const clauses = [...selector.clauses];
            clauses[i] = e;
            onChange({ clauses });
          }}
          onRemove={() => onChange({ clauses: selector.clauses.filter((_, j) => j !== i) })}
        />
      ))}
      <Button
        size="small"
        startIcon={<AddIcon />}
        sx={{ alignSelf: "flex-start" }}
        onClick={() => onChange({ clauses: [...selector.clauses, defaultExpr("eq")] })}
      >
        clause
      </Button>
    </Stack>
  );
}

/** Only shown when it is not the default, so the common selector reads as it always did. */
function sourceSuffix(e: Leaf): string {
  const src = sourceOf(e);
  return src === "manual" ? "" : ` [${src}]`;
}

export function describeExpr(e: Expr): string {
  switch (e.op) {
    case "eq":
      return `${e.key} = "${e.value}"${sourceSuffix(e)}`;
    case "in":
      return `${e.key} IN (${e.values.map((v) => `"${v}"`).join(", ")})${sourceSuffix(e)}`;
    case "exists":
      return `EXISTS ${e.key}${sourceSuffix(e)}`;
    case "not":
      return `NOT (${describeExpr(e.expr)})`;
    case "and":
      return `(${e.exprs.map(describeExpr).join(" AND ")})`;
    case "or":
      return `(${e.exprs.map(describeExpr).join(" OR ")})`;
  }
}

export function describeSelector(s: Selector): string {
  if (!s.clauses || s.clauses.length === 0) return "matches every host";
  return s.clauses.map(describeExpr).join(" AND ");
}
