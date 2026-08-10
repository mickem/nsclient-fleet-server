import { Box, Button, IconButton, MenuItem, Select, Stack, TextField, Typography } from "@mui/material";
import CloseIcon from "@mui/icons-material/Close";
import AddIcon from "@mui/icons-material/Add";
import { Expr, Selector } from "./api";

// Structured selector editor — every field is a discrete input; the selector is never
// entered as raw text (locked design decision from PLAN.md).

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

type ExprProps = { expr: Expr; onChange: (e: Expr) => void; onRemove?: () => void };

export function ExprEditor({ expr, onChange, onRemove }: ExprProps) {
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
    <TextField size="small" placeholder="tag key" value={key} onChange={(e) => set(e.target.value)} />
  );

  switch (expr.op) {
    case "eq":
      return (
        <Stack direction="row" spacing={1} alignItems="center" useFlexGap sx={{ flexWrap: "wrap" }}>
          {opSelect}
          {keyInput(expr.key, (key) => onChange({ ...expr, key }))}
          <Typography>=</Typography>
          <TextField
            size="small"
            placeholder="value"
            value={expr.value}
            onChange={(e) => onChange({ ...expr, value: e.target.value })}
          />
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
            <TextField
              key={i}
              size="small"
              placeholder={`value ${i + 1}`}
              value={v}
              onChange={(e) => {
                const values = [...expr.values];
                values[i] = e.target.value;
                onChange({ ...expr, values });
              }}
            />
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
            <ExprEditor expr={expr.expr} onChange={(inner) => onChange({ ...expr, expr: inner })} />
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

type SelectorProps = { selector: Selector; onChange: (s: Selector) => void };

export function SelectorEditor({ selector, onChange }: SelectorProps) {
  return (
    <Stack spacing={1}>
      <Typography variant="caption" color="text.secondary">
        All top-level clauses must match (implicit AND). An empty selector matches every host.
      </Typography>
      {selector.clauses.map((c, i) => (
        <ExprEditor
          key={i}
          expr={c}
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
