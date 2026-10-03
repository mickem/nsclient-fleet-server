import {
  Alert,
  Autocomplete,
  Box,
  Checkbox,
  FormControlLabel,
  MenuItem,
  Stack,
  Switch,
  Table as MuiTable,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TextField,
  Typography,
} from "@mui/material";
import type { ImportNormalize } from "../api";
import { guessKeyTarget, KeyOption, keyTargetId, MapColumn, MAX_KEYS } from "./model";
import {
  CellError,
  COLUMN_TYPES,
  ColumnType,
  importNameError,
  JsonObject,
  MAX_IMPORT_NAME_LEN,
  Table,
  targetPathError,
} from "./parse";
import { cellText } from "./ShapeStep";

const DOCS_PREVIEWED = 3;

export function MapStep({
  table,
  mapping,
  onMapping,
  options,
  normalize,
  onNormalize,
  name,
  onName,
  documents,
  cellErrors,
  cellErrorCount,
  conflicts,
  issues,
}: {
  table: Table;
  mapping: MapColumn[];
  onMapping: (index: number, patch: Partial<MapColumn>) => void;
  options: KeyOption[];
  normalize: ImportNormalize;
  onNormalize: (n: ImportNormalize) => void;
  name: string;
  onName: (n: string) => void;
  documents: JsonObject[];
  cellErrors: CellError[];
  cellErrorCount: number;
  conflicts: Map<number, string>;
  /** What stops the step from going on, in words. */
  issues: string[];
}) {
  const keyCount = mapping.filter((m) => m.key).length;
  const nameError = importNameError(name);
  const sample = (i: number) => {
    const row = table.rows.find((r) => r[i] !== undefined && cellText(r[i]) !== "");
    return row ? cellText(row[i]) : "";
  };
  const byId = new Map(options.map((o) => [keyTargetId(o.target), o]));

  return (
    <Stack spacing={2}>
      <TextField
        label="Import name"
        size="small"
        value={name}
        onChange={(e) => onName(e.target.value.trim())}
        error={nameError !== null}
        helperText={
          nameError ??
          `Stored as the facts source "import:${name}". Importing again under the same name ` +
            "replaces these documents; selectors read them as that source."
        }
        inputProps={{ maxLength: MAX_IMPORT_NAME_LEN }}
        sx={{ maxWidth: 520 }}
      />

      <Box sx={{ overflowX: "auto", border: 1, borderColor: "divider", borderRadius: 1 }}>
        <MuiTable size="small">
          <TableHead>
            <TableRow>
              <TableCell>Column</TableCell>
              <TableCell padding="checkbox">Include</TableCell>
              <TableCell sx={{ minWidth: 220 }}>Target path</TableCell>
              <TableCell sx={{ minWidth: 120 }}>Type</TableCell>
              <TableCell padding="checkbox">Key</TableCell>
              <TableCell sx={{ minWidth: 280 }}>Match key against</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {table.columns.map((c, i) => {
              const m = mapping[i];
              if (!m) return null;
              const pathError = m.include ? (targetPathError(m.target) ?? conflicts.get(i) ?? null) : null;
              const current = m.keyTarget ? (byId.get(keyTargetId(m.keyTarget)) ?? null) : null;
              return (
                <TableRow key={c}>
                  <TableCell sx={{ verticalAlign: "top" }}>
                    <Typography variant="body2" sx={{ fontFamily: "monospace" }}>
                      {c}
                    </Typography>
                    <Typography
                      variant="caption"
                      color="text.secondary"
                      sx={{ display: "block", maxWidth: 220, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                      title={sample(i)}
                    >
                      {sample(i) || "(empty)"}
                    </Typography>
                  </TableCell>
                  <TableCell padding="checkbox" sx={{ verticalAlign: "top" }}>
                    <Checkbox
                      size="small"
                      checked={m.include}
                      onChange={(e) => onMapping(i, { include: e.target.checked })}
                    />
                  </TableCell>
                  <TableCell sx={{ verticalAlign: "top" }}>
                    <TextField
                      size="small"
                      fullWidth
                      value={m.target}
                      disabled={!m.include}
                      onChange={(e) => onMapping(i, { target: e.target.value })}
                      error={pathError !== null}
                      helperText={pathError ?? undefined}
                      slotProps={{ htmlInput: { style: { fontFamily: "monospace" } } }}
                    />
                  </TableCell>
                  <TableCell sx={{ verticalAlign: "top" }}>
                    <TextField
                      select
                      size="small"
                      fullWidth
                      value={m.type}
                      disabled={!m.include}
                      onChange={(e) => onMapping(i, { type: e.target.value as ColumnType })}
                    >
                      {COLUMN_TYPES.map((t) => (
                        <MenuItem key={t} value={t}>
                          {t}
                        </MenuItem>
                      ))}
                    </TextField>
                  </TableCell>
                  <TableCell padding="checkbox" sx={{ verticalAlign: "top" }}>
                    <Checkbox
                      size="small"
                      checked={m.key}
                      disabled={!m.key && keyCount >= MAX_KEYS}
                      onChange={(e) =>
                        onMapping(i, {
                          key: e.target.checked,
                          keyTarget: e.target.checked ? (m.keyTarget ?? guessKeyTarget(c, options)) : m.keyTarget,
                        })
                      }
                    />
                  </TableCell>
                  <TableCell sx={{ verticalAlign: "top" }}>
                    {m.key && (
                      <Autocomplete
                        size="small"
                        options={options}
                        groupBy={(o) => o.group}
                        value={current}
                        onChange={(_, o) => onMapping(i, { keyTarget: o?.target ?? null })}
                        isOptionEqualToValue={(a, b) => keyTargetId(a.target) === keyTargetId(b.target)}
                        getOptionLabel={(o) => o.label}
                        renderOption={(props, o) => {
                          const { key, ...rest } = props;
                          return (
                            <li key={key} {...rest}>
                              <Stack direction="row" spacing={1} sx={{ width: "100%" }}>
                                <Typography variant="body2" sx={{ flexGrow: 1, wordBreak: "break-all" }}>
                                  {o.label}
                                </Typography>
                                {o.hosts !== undefined && (
                                  <Typography variant="caption" color="text.secondary" sx={{ whiteSpace: "nowrap" }}>
                                    {o.hosts} host{o.hosts === 1 ? "" : "s"}
                                  </Typography>
                                )}
                              </Stack>
                            </li>
                          );
                        }}
                        renderInput={(params) => (
                          <TextField {...params} placeholder="Host field, tag or fact" error={current === null} />
                        )}
                      />
                    )}
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </MuiTable>
      </Box>

      <Typography variant="body2" color="text.secondary">
        Keys only find the host; they are not stored unless the column is also included.
        Several key columns must all match the same host. Dots in a target path nest:{" "}
        <code>cmdb.owner</code> stores <code>{'{"cmdb": {"owner": …}}'}</code>.
      </Typography>

      <Stack direction="row" spacing={2} useFlexGap flexWrap="wrap">
        <FormControlLabel
          control={
            <Switch
              checked={normalize.trim}
              onChange={(e) => onNormalize({ ...normalize, trim: e.target.checked })}
            />
          }
          label="Trim whitespace"
        />
        <FormControlLabel
          control={
            <Switch
              checked={normalize.case_insensitive}
              onChange={(e) => onNormalize({ ...normalize, case_insensitive: e.target.checked })}
            />
          }
          label="Ignore case"
        />
        <FormControlLabel
          control={
            <Switch
              checked={normalize.short_hostname}
              onChange={(e) => onNormalize({ ...normalize, short_hostname: e.target.checked })}
            />
          }
          label="Compare only the part before the first dot"
        />
      </Stack>

      {cellErrorCount > 0 && (
        <Alert severity="error">
          {cellErrorCount} cell{cellErrorCount === 1 ? "" : "s"} do not fit their column&apos;s type.
          Change the type or exclude the column.
          <Box component="ul" sx={{ m: 0, pl: 2 }}>
            {cellErrors.slice(0, 5).map((e) => (
              <li key={`${e.row}:${e.column}`}>
                Row {e.row + 1}, {table.columns[e.column]}: {e.message}
              </li>
            ))}
          </Box>
        </Alert>
      )}
      {issues.length > 0 && (
        <Alert severity="warning">
          <Box component="ul" sx={{ m: 0, pl: 2 }}>
            {issues.map((i) => (
              <li key={i}>{i}</li>
            ))}
          </Box>
        </Alert>
      )}

      <Box>
        <Typography variant="subtitle2" sx={{ mb: 0.5 }}>
          Preview of the first {Math.min(DOCS_PREVIEWED, documents.length)} documents
        </Typography>
        <Box
          component="pre"
          sx={{
            m: 0,
            p: 1.5,
            bgcolor: "action.hover",
            borderRadius: 1,
            fontSize: "0.8rem",
            overflow: "auto",
            maxHeight: 360,
          }}
        >
          {documents
            .slice(0, DOCS_PREVIEWED)
            .map((d) => JSON.stringify(d, null, 2))
            .join("\n\n")}
        </Box>
      </Box>
    </Stack>
  );
}
