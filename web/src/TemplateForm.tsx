import { useEffect, useState } from "react";
import {
  FormControlLabel,
  FormHelperText,
  IconButton,
  MenuItem,
  Stack,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TextField,
  Tooltip,
  Typography,
} from "@mui/material";
import DeleteIcon from "@mui/icons-material/Delete";
import {
  applyFieldChange,
  BundleTemplate,
  fieldDefault,
  fieldPresent,
  fieldValue,
  fieldVisible,
  tableAddRow,
  tableRemoveRow,
  tableRenameRow,
  tableRows,
  tableSetRow,
  TemplateField,
  validTableKey,
} from "./templates";

type Props = {
  template: BundleTemplate;
  /** The INI document — single source of truth shared with the text view. */
  ini: string;
  onChange: (ini: string) => void;
};

/** Text input that buffers while focused and commits on blur, so surgical INI rewrites
 *  (which trim values) don't eat trailing spaces mid-typing. */
function CommittedTextField({
  label,
  help,
  value,
  onCommit,
  validate,
  monospace,
}: {
  label?: string;
  help?: string;
  value: string;
  onCommit: (v: string) => void;
  /** Invalid drafts show an error and are not committed (they revert on blur). */
  validate?: (v: string) => boolean;
  monospace?: boolean;
}) {
  const [draft, setDraft] = useState(value);
  const [focused, setFocused] = useState(false);
  useEffect(() => {
    if (!focused) setDraft(value);
  }, [value, focused]);
  const invalid = validate !== undefined && !validate(draft);
  return (
    <TextField
      size="small"
      fullWidth
      label={label}
      helperText={help}
      error={invalid}
      value={draft}
      onChange={(e) => setDraft(e.target.value)}
      onFocus={() => setFocused(true)}
      onBlur={() => {
        setFocused(false);
        if (draft !== value && !invalid) onCommit(draft);
        else if (invalid) setDraft(value);
      }}
      slotProps={
        monospace
          ? { input: { sx: { fontFamily: "monospace", fontSize: "0.85rem" } } }
          : undefined
      }
    />
  );
}

/** Wraps a control in an on/off switch whose state IS the key's presence in the INI:
 *  off removes the key (inheriting whatever else defines it), on writes the default. */
function OptionalShell({
  label,
  enabled,
  onToggle,
  children,
}: {
  label: string;
  enabled: boolean;
  onToggle: (on: boolean) => void;
  children: React.ReactNode;
}) {
  return (
    <div>
      <FormControlLabel
        control={
          <Switch
            size="small"
            checked={enabled}
            onChange={(e) => onToggle(e.target.checked)}
          />
        }
        label={label}
      />
      {enabled ? (
        children
      ) : (
        <FormHelperText sx={{ mt: -0.5 }}>not set in this bundle</FormHelperText>
      )}
    </div>
  );
}

/** Editable rows of a section: rename, edit the command, delete, add from presets. */
function TableField({
  field,
  ini,
  onChange,
}: {
  field: TemplateField & { kind: "table" };
  ini: string;
  onChange: (ini: string) => void;
}) {
  const rows = tableRows(ini, field);
  const taken = new Set(rows.map((r) => r.key));
  return (
    <div>
      <Typography variant="subtitle2">{field.label}</Typography>
      {field.help && <FormHelperText sx={{ mt: 0, mb: 1 }}>{field.help}</FormHelperText>}
      <Table size="small" sx={{ mb: 1 }}>
        <TableHead>
          <TableRow>
            <TableCell sx={{ width: "14rem" }}>Name</TableCell>
            <TableCell>Command</TableCell>
            <TableCell sx={{ width: "3rem" }} />
          </TableRow>
        </TableHead>
        <TableBody>
          {rows.length === 0 && (
            <TableRow>
              <TableCell colSpan={3}>
                <Typography variant="body2" color="text.secondary">
                  No checks yet — add one below.
                </Typography>
              </TableCell>
            </TableRow>
          )}
          {rows.map((r) => (
            <TableRow key={r.key}>
              <TableCell sx={{ verticalAlign: "top" }}>
                <CommittedTextField
                  value={r.key}
                  monospace
                  validate={(v) => v === r.key || (validTableKey(v) && !taken.has(v))}
                  onCommit={(v) => onChange(tableRenameRow(ini, field, r.key, v))}
                />
              </TableCell>
              <TableCell sx={{ verticalAlign: "top" }}>
                <CommittedTextField
                  value={r.value}
                  monospace
                  onCommit={(v) => onChange(tableSetRow(ini, field, r.key, v))}
                />
              </TableCell>
              <TableCell sx={{ verticalAlign: "top" }}>
                <Tooltip title="Remove this check">
                  <IconButton
                    size="small"
                    onClick={() => onChange(tableRemoveRow(ini, field, r.key))}
                  >
                    <DeleteIcon fontSize="small" />
                  </IconButton>
                </Tooltip>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      <TextField
        select
        size="small"
        label="Add check"
        value=""
        sx={{ minWidth: "18rem" }}
        onChange={(e) => {
          const preset = field.presets[Number(e.target.value)];
          if (preset) onChange(tableAddRow(ini, field, preset));
        }}
      >
        {field.presets.map((p, i) => (
          <MenuItem key={i} value={String(i)}>
            {p.label}
            {taken.has(p.key) && (
              <Typography component="span" variant="caption" color="text.secondary" sx={{ ml: 1 }}>
                (again)
              </Typography>
            )}
          </MenuItem>
        ))}
      </TextField>
    </div>
  );
}

/** The visual (form) editor view: the template's typed fields projected onto the INI
 *  text. Conditional fields appear/disappear as their parents change (e.g. the CA path
 *  only under mutual TLS), and hidden fields' keys are removed from the document. */
export function TemplateForm({ template, ini, onChange }: Props) {
  const apply = (f: TemplateField, v: string) =>
    onChange(applyFieldChange(ini, template, f, v));

  return (
    <Stack spacing={2} sx={{ my: 1, maxWidth: "40rem" }}>
      {template.fields
        .filter((f) => fieldVisible(ini, template, f))
        .map((f) => {
          const value = fieldValue(ini, f);
          switch (f.kind) {
            case "table":
              return <TableField key={f.id} field={f} ini={ini} onChange={onChange} />;
            case "bool":
              return (
                <div key={f.id}>
                  <FormControlLabel
                    control={
                      <Switch
                        size="small"
                        checked={value === "true" || value === "1"}
                        onChange={(e) => apply(f, e.target.checked ? "true" : "false")}
                      />
                    }
                    label={f.label}
                  />
                  {f.help && <FormHelperText sx={{ mt: -0.5 }}>{f.help}</FormHelperText>}
                </div>
              );
            case "select":
            case "choice": {
              // A value the options don't cover (hand-edited INI) still has to display.
              const custom = !f.options.some((o) => o.value === value);
              const optional = f.kind === "select" && f.optional === true;
              const select = (
                <TextField
                  select
                  size="small"
                  fullWidth
                  label={optional ? (f.valueLabel ?? "value") : f.label}
                  helperText={f.help}
                  value={value}
                  onChange={(e) => apply(f, e.target.value)}
                >
                  {custom && (
                    <MenuItem value={value} disabled>
                      {value === "" ? "(custom settings)" : `${value} (custom)`}
                    </MenuItem>
                  )}
                  {f.options.map((o) => (
                    <MenuItem key={o.value} value={o.value}>
                      {o.label}
                    </MenuItem>
                  ))}
                </TextField>
              );
              if (!optional) return <div key={f.id}>{select}</div>;
              return (
                <OptionalShell
                  key={f.id}
                  label={f.label}
                  enabled={fieldPresent(ini, f)}
                  onToggle={(on) => apply(f, on ? fieldDefault(template, f) : "")}
                >
                  {select}
                </OptionalShell>
              );
            }
            default: {
              if (!f.optional) {
                return (
                  <CommittedTextField
                    key={f.id}
                    label={f.label}
                    help={f.help}
                    value={value}
                    onCommit={(v) => apply(f, v)}
                  />
                );
              }
              // Optional: the switch is key presence. Off removes the key (the check is
              // not defined); on restores the template's default, then it's editable.
              return (
                <OptionalShell
                  key={f.id}
                  label={f.label}
                  enabled={fieldPresent(ini, f)}
                  onToggle={(on) => apply(f, on ? fieldDefault(template, f) : "")}
                >
                  <CommittedTextField
                    label={f.valueLabel ?? "value"}
                    help={f.help}
                    value={value}
                    onCommit={(v) => apply(f, v)}
                  />
                </OptionalShell>
              );
            }
          }
        })}
    </Stack>
  );
}
