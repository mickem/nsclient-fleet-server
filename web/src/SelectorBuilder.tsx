import { useState } from "react";
import {
  Alert,
  Autocomplete,
  Box,
  Button,
  Divider,
  IconButton,
  ListSubheader,
  Menu,
  MenuItem,
  Select,
  Stack,
  TextField,
  Tooltip,
  Typography,
} from "@mui/material";
import CloseIcon from "@mui/icons-material/Close";
import AddIcon from "@mui/icons-material/Add";
import {
  AGENT_FACTS,
  CatalogPath,
  Expr,
  FactsCatalog,
  FactTest,
  HostView,
  Selector,
  SourceFilter,
  TagView,
} from "./api";

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

/** What the fleet's facts documents look like: source → path → what is at it. From
 *  `GET /api/facts/catalog`; feeds the fact path and value pickers the way `KnownTags`
 *  feeds the tag ones. `truncated`: the catalog hit its caps for that source, so the
 *  pickers show only part of what the fleet has. */
export type KnownFacts = Map<string, { paths: Map<string, CatalogPath>; truncated: boolean }>;

export function knownFactsFromCatalog(c: FactsCatalog): KnownFacts {
  return new Map(
    c.sources.map((s) => [
      s.source,
      { paths: new Map(s.paths.map((p) => [p.path, p])), truncated: s.truncated },
    ]),
  );
}

/** The facts sources a clause can read: whatever the fleet holds, and always the agent's. */
function factSources(facts: KnownFacts | undefined): string[] {
  const out = new Set([AGENT_FACTS, ...(facts?.keys() ?? [])]);
  return [...out];
}

const factSourceLabel = (s: string) => (s === AGENT_FACTS ? "agent facts" : `${s} facts`);

const hostCount = (n: number) => `${n} host${n === 1 ? "" : "s"}`;

/** Free-text input with a dropdown of what the fleet already reports. `options` carry the
 *  host count so the common choice is recognisable at a glance; `note` adds a word more
 *  (what kind of value a fact path holds). */
function TagAutocomplete({
  value,
  onChange,
  options,
  placeholder,
  minWidth,
  note,
}: {
  value: string;
  onChange: (v: string) => void;
  options: [string, number][];
  placeholder: string;
  minWidth: string;
  note?: (option: string) => string | undefined;
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
                {[note?.(option), hostCount(counts.get(option) ?? 0)].filter(Boolean).join(" · ")}
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

type Compound = "not" | "and" | "or";

const COMPOUND_OPS: { id: Compound; label: string }[] = [
  { id: "not", label: "NOT" },
  { id: "and", label: "AND group" },
  { id: "or", label: "OR group" },
];

const OPS: { id: Expr["op"]; label: string }[] = [
  { id: "eq", label: "equals" },
  { id: "in", label: "in list" },
  { id: "exists", label: "exists" },
  ...COMPOUND_OPS,
];

/** A fact leaf's tests. `has` is the one tags do not need: a fact can be a list (installed
 *  packages, addresses) or a map (services by name), and the question is what it contains. */
const FACT_TESTS: { id: FactTest["test"]; label: string; help: string }[] = [
  { id: "eq", label: "equals", help: "A value at the path equals this." },
  { id: "in", label: "in list", help: "A value at the path is one of these." },
  {
    id: "has",
    label: "has",
    help: "The list at the path contains this value or a record with this id, or the map at the path has this key.",
  },
  { id: "exists", label: "exists", help: "The path is present in the document." },
];

type FactLeaf = Extract<Expr, { op: "fact" }>;

/** A fact leaf with another test, keeping its source and path — and the value, where the
 *  new test takes one. */
function withTest(leaf: FactLeaf, test: FactTest["test"]): FactLeaf {
  const base = { op: "fact" as const, facts: leaf.facts ?? AGENT_FACTS, path: leaf.path };
  const first = leaf.test === "in" ? (leaf.values[0] ?? "") : leaf.test === "exists" ? "" : leaf.value;
  switch (test) {
    case "exists":
      return { ...base, test };
    case "in":
      return { ...base, test, values: leaf.test === "in" ? leaf.values : [first] };
    case "eq":
    case "has":
      return { ...base, test, value: first };
  }
}

export function defaultFact(facts: string = AGENT_FACTS): FactLeaf {
  return { op: "fact", facts, path: "", test: "eq", value: "" };
}

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
    case "fact":
      // The agent's document is what the host says about itself, like an agent tag.
      return (e.facts ?? AGENT_FACTS) === AGENT_FACTS;
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
    case "fact":
      return defaultFact();
    case "not":
      return { op: "not", expr: { op: "eq", key: "", value: "" } };
    case "and":
      return { op: "and", exprs: [{ op: "eq", key: "", value: "" }] };
    case "or":
      return { op: "or", exprs: [{ op: "eq", key: "", value: "" }] };
  }
}

/** "+ clause", as a menu: the first thing to decide about a clause is what it reads —
 *  operator tags, host-reported tags, or a facts document — because that decides both what
 *  it can compare and whether the host gets a say in it. */
function AddClauseButton({ onAdd, facts }: { onAdd: (e: Expr) => void; facts?: KnownFacts }) {
  const [anchor, setAnchor] = useState<HTMLElement | null>(null);
  const add = (e: Expr) => {
    setAnchor(null);
    onAdd(e);
  };
  return (
    <>
      <Button
        size="small"
        startIcon={<AddIcon />}
        sx={{ alignSelf: "flex-start" }}
        onClick={(e) => setAnchor(e.currentTarget)}
      >
        clause
      </Button>
      <Menu anchorEl={anchor} open={anchor !== null} onClose={() => setAnchor(null)}>
        <ListSubheader>Tags</ListSubheader>
        <MenuItem onClick={() => add({ op: "eq", key: "", value: "" })}>Operator tag</MenuItem>
        <MenuItem onClick={() => add({ op: "eq", key: "", value: "", source: "agent" })}>
          Host-reported tag
        </MenuItem>
        <ListSubheader>Facts</ListSubheader>
        {factSources(facts).map((s) => (
          <MenuItem key={s} onClick={() => add(defaultFact(s))}>
            {s === AGENT_FACTS ? "Agent facts" : `${s} facts`}
          </MenuItem>
        ))}
        <Divider />
        {COMPOUND_OPS.map((o) => (
          <MenuItem key={o.id} onClick={() => add(defaultExpr(o.id))}>
            {o.label}
          </MenuItem>
        ))}
      </Menu>
    </>
  );
}

type ExprProps = {
  expr: Expr;
  onChange: (e: Expr) => void;
  onRemove?: () => void;
  /** Tags the fleet reports today, for the pickers. Optional: without it every input is
   *  plain free text. */
  known?: KnownTags;
  /** Fact paths the fleet reports today, likewise. */
  facts?: KnownFacts;
};

export function ExprEditor({ expr, onChange, onRemove, known, facts }: ExprProps) {
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

  const factEditor = (leaf: FactLeaf) => {
    const source = leaf.facts ?? AGENT_FACTS;
    const known = facts?.get(source);
    const paths = known?.paths;
    const at = paths?.get(leaf.path);
    const pathOptions: [string, number][] = [...(paths?.values() ?? [])]
      .map((p): [string, number] => [p.path, p.hosts])
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
    const values: [string, number][] = at?.values ?? [];

    /** Pick a path, and the test that suits what is at it: a list or map is asked what it
     *  has, a scalar what it equals. Only between those two, so a deliberate `in` or
     *  `exists` is never overridden. */
    const setPath = (path: string) => {
      const kind = paths?.get(path)?.kind;
      let next: FactLeaf = { ...leaf, path };
      if ((kind === "list" || kind === "map") && leaf.test === "eq") next = withTest(next, "has");
      if (kind === "scalar" && leaf.test === "has") next = withTest(next, "eq");
      onChange(next);
    };
    const valueBox = (value: string, set: (v: string) => void, placeholder: string) => (
      <TagAutocomplete
        value={value}
        onChange={set}
        options={values}
        placeholder={placeholder}
        minWidth="12rem"
      />
    );

    return (
      <Stack spacing={0.5}>
        <Stack direction="row" spacing={1} alignItems="center" useFlexGap sx={{ flexWrap: "wrap" }}>
          <Select
            size="small"
            value={leaf.test}
            onChange={(e) => {
              // Only the options below can be chosen; anything else (there should be nothing)
              // is ignored rather than turned into a clause the rest of the editor cannot read.
              const v = e.target.value as string;
              const compound = COMPOUND_OPS.find((o) => o.id === v);
              const test = FACT_TESTS.find((t) => t.id === v);
              if (compound) onChange(defaultExpr(compound.id));
              else if (test) onChange(withTest(leaf, test.id));
            }}
          >
            {FACT_TESTS.map((t) => (
              <MenuItem key={t.id} value={t.id} title={t.help}>
                {t.label}
              </MenuItem>
            ))}
            {/* A subheader, not a Divider: Select turns every child into a selectable option,
                and a divider chosen by click has no value. */}
            <ListSubheader>Combine</ListSubheader>
            {COMPOUND_OPS.map((o) => (
              <MenuItem key={o.id} value={o.id}>
                {o.label}
              </MenuItem>
            ))}
          </Select>
          <Tooltip
            title={
              source === AGENT_FACTS
                ? "The inventory the host uploads about itself. A compromised host can report " +
                  "anything here and join the group, so it will receive whatever bundles the group carries."
                : `Facts from ${source}, not written by the host.`
            }
          >
            <Select
              size="small"
              value={source}
              color={source === AGENT_FACTS ? "warning" : undefined}
              onChange={(e) => onChange({ ...leaf, facts: e.target.value })}
            >
              {factSources(facts).map((s) => (
                <MenuItem key={s} value={s}>
                  {factSourceLabel(s)}
                </MenuItem>
              ))}
            </Select>
          </Tooltip>
          <TagAutocomplete
            value={leaf.path}
            onChange={setPath}
            options={pathOptions}
            placeholder="path, e.g. software.installed"
            minWidth="18rem"
            note={(p) => paths?.get(p)?.kind}
          />
          {(leaf.test === "eq" || leaf.test === "has") && (
            <>
              <Typography>{leaf.test === "eq" ? "=" : "∋"}</Typography>
              {valueBox(leaf.value, (value) => onChange({ ...leaf, value }), "value")}
            </>
          )}
          {leaf.test === "in" && (
            <>
              <Typography>∈</Typography>
              {leaf.values.map((v, i) => (
                <Box key={i}>
                  {valueBox(
                    v,
                    (value) => {
                      const vs = [...leaf.values];
                      vs[i] = value;
                      onChange({ ...leaf, values: vs });
                    },
                    `value ${i + 1}`,
                  )}
                </Box>
              ))}
              <Button size="small" onClick={() => onChange({ ...leaf, values: [...leaf.values, ""] })}>
                + value
              </Button>
              {leaf.values.length > 1 && (
                <Button
                  size="small"
                  onClick={() => onChange({ ...leaf, values: leaf.values.slice(0, -1) })}
                >
                  − value
                </Button>
              )}
            </>
          )}
          {removeBtn}
        </Stack>
        {at?.kind === "mixed" && (
          <Alert severity="warning">
            This path holds different kinds of value on different hosts — a list on some, a map
            or a single value on others — so one test does not read the same on all of them. A
            bracketed part such as <code>[eth0.100]</code> picks a record by id where the path is a
            list, but a key where it is a map.
          </Alert>
        )}
        {known?.truncated && (
          <Typography variant="caption" color="text.secondary">
            The fleet&apos;s {factSourceLabel(source)} have more hosts or paths than the pickers
            list, so they show only part of them. Any path can still be typed.
          </Typography>
        )}
      </Stack>
    );
  };

  switch (expr.op) {
    case "fact":
      return factEditor(expr);
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
              facts={facts}
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
                facts={facts}
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
            <AddClauseButton
              facts={facts}
              onAdd={(e) => onChange({ ...expr, exprs: [...expr.exprs, e] })}
            />
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
  /** See `ExprProps.facts`. */
  facts?: KnownFacts;
};

export function SelectorEditor({ selector, onChange, known, facts }: SelectorProps) {
  return (
    <Stack spacing={1}>
      <Typography variant="caption" color="text.secondary">
        All top-level clauses must match (implicit AND). An empty selector matches every host.
        Each clause reads one thing: operator-set tags, tags the host reports about itself, or a
        facts document such as the inventory the agent uploads.
      </Typography>
      {selectorIsHostControlled(selector) && (
        <Alert severity="warning">
          A clause here trusts what the host reports about itself — its tags or its facts — so a
          host can put <em>itself</em> in this group by claiming the right value, and will then
          be served this group&apos;s bundles. Use operator tags for anything that gates access
          to scripts or secrets.
        </Alert>
      )}
      {selector.clauses.map((c, i) => (
        <ExprEditor
          key={i}
          expr={c}
          known={known}
          facts={facts}
          onChange={(e) => {
            const clauses = [...selector.clauses];
            clauses[i] = e;
            onChange({ clauses });
          }}
          onRemove={() => onChange({ clauses: selector.clauses.filter((_, j) => j !== i) })}
        />
      ))}
      <AddClauseButton
        facts={facts}
        onAdd={(e) => onChange({ clauses: [...selector.clauses, e] })}
      />
    </Stack>
  );
}

/** Only shown when it is not the default, so the common selector reads as it always did. */
function sourceSuffix(e: Leaf): string {
  const src = sourceOf(e);
  return src === "manual" ? "" : ` [${src}]`;
}

function describeFact(e: FactLeaf): string {
  const src = ` [facts:${e.facts ?? AGENT_FACTS}]`;
  switch (e.test) {
    case "eq":
      return `${e.path} = "${e.value}"${src}`;
    case "in":
      return `${e.path} IN (${e.values.map((v) => `"${v}"`).join(", ")})${src}`;
    case "has":
      return `${e.path} HAS "${e.value}"${src}`;
    case "exists":
      return `EXISTS ${e.path}${src}`;
  }
}

export function describeExpr(e: Expr): string {
  switch (e.op) {
    case "fact":
      return describeFact(e);
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
