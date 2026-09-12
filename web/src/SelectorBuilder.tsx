import {
  Autocomplete,
  Box,
  Button,
  IconButton,
  MenuItem,
  Select,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import CloseIcon from "@mui/icons-material/Close";
import AddIcon from "@mui/icons-material/Add";
import { Expr, HostView, Selector } from "./api";

// Structured selector editor — every field is a discrete input; the selector is never
// entered as raw text (locked design decision from PLAN.md).

/** What the fleet currently reports: tag key → value → number of hosts carrying it. Feeds
 *  the key and value pickers so an operator chooses from what exists (os, os_name,
 *  os_version, the service tags…) instead of guessing spellings. Free text still works —
 *  a group is often written before the first host that will match it enrolls. */
export type KnownTags = Map<string, Map<string, number>>;

export function knownTagsFromHosts(hosts: HostView[]): KnownTags {
  const out: KnownTags = new Map();
  for (const h of hosts) {
    for (const t of h.tags) {
      let values = out.get(t.key);
      if (!values) {
        values = new Map();
        out.set(t.key, values);
      }
      values.set(t.value, (values.get(t.value) ?? 0) + 1);
    }
  }
  return out;
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
    .map(([k, values]): [string, number] => [k, [...values.values()].reduce((a, b) => a + b, 0)])
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
}

/** Values reported under `key`, most common first. */
function valueOptions(known: KnownTags | undefined, key: string): [string, number][] {
  const values = known?.get(key);
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
  const removeBtn = onRemove ? (
    <IconButton size="small" onClick={onRemove} title="remove clause">
      <CloseIcon fontSize="small" />
    </IconButton>
  ) : null;

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
          {keyInput(expr.key, (key) => onChange({ ...expr, key }))}
          <Typography>=</Typography>
          {valueInput(expr.key, expr.value, (value) => onChange({ ...expr, value }), "value")}
          {removeBtn}
        </Stack>
      );
    case "in":
      return (
        <Stack direction="row" spacing={1} alignItems="center" useFlexGap sx={{ flexWrap: "wrap" }}>
          {opSelect}
          {keyInput(expr.key, (key) => onChange({ ...expr, key }))}
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
          {removeBtn}
        </Stack>
      );
    case "exists":
      return (
        <Stack direction="row" spacing={1} alignItems="center" useFlexGap sx={{ flexWrap: "wrap" }}>
          {opSelect}
          {keyInput(expr.key, (key) => onChange({ ...expr, key }))}
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
      </Typography>
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

export function describeExpr(e: Expr): string {
  switch (e.op) {
    case "eq":
      return `${e.key} = "${e.value}"`;
    case "in":
      return `${e.key} IN (${e.values.map((v) => `"${v}"`).join(", ")})`;
    case "exists":
      return `EXISTS ${e.key}`;
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
