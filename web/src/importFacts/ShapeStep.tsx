import {
  Alert,
  Box,
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
import { Delimiter, DELIMITERS, Format, JsonValue, Table } from "./parse";

const DELIMITER_LABELS: Record<Delimiter, string> = {
  ",": "Comma (,)",
  ";": "Semicolon (;)",
  "\t": "Tab",
  "|": "Pipe (|)",
};

/** A cell as preview text; a missing cell is blank, an empty string shows as such. */
export function cellText(v: JsonValue | undefined): string {
  if (v === undefined) return "";
  if (typeof v === "string") return v;
  return JSON.stringify(v);
}

export const PREVIEW_ROWS = 10;

export function PreviewTable({ table, rows = PREVIEW_ROWS }: { table: Table; rows?: number }) {
  return (
    <Box sx={{ overflowX: "auto", border: 1, borderColor: "divider", borderRadius: 1 }}>
      <MuiTable size="small">
        <TableHead>
          <TableRow>
            <TableCell sx={{ color: "text.secondary" }}>#</TableCell>
            {table.columns.map((c) => (
              <TableCell key={c} sx={{ whiteSpace: "nowrap", fontFamily: "monospace" }}>
                {c}
              </TableCell>
            ))}
          </TableRow>
        </TableHead>
        <TableBody>
          {table.rows.slice(0, rows).map((r, i) => (
            <TableRow key={i}>
              <TableCell sx={{ color: "text.secondary" }}>{i + 1}</TableCell>
              {table.columns.map((c, j) => (
                <TableCell
                  key={c}
                  sx={{ maxWidth: 240, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                  title={cellText(r[j])}
                >
                  {cellText(r[j])}
                </TableCell>
              ))}
            </TableRow>
          ))}
        </TableBody>
      </MuiTable>
    </Box>
  );
}

export function ShapeStep({
  format,
  table,
  delimiter,
  detectedDelimiter,
  header,
  onDelimiter,
  onHeader,
}: {
  format: Format;
  table: Table;
  delimiter: Delimiter | "auto";
  /** What `auto` chose, to show beside it. */
  detectedDelimiter: Delimiter | undefined;
  header: boolean;
  onDelimiter: (d: Delimiter | "auto") => void;
  onHeader: (h: boolean) => void;
}) {
  return (
    <Stack spacing={2}>
      {format === "csv" ? (
        <Stack direction="row" spacing={2} alignItems="center" useFlexGap flexWrap="wrap">
          <TextField
            select
            size="small"
            label="Delimiter"
            value={delimiter}
            onChange={(e) => onDelimiter(e.target.value as Delimiter | "auto")}
            sx={{ minWidth: 220 }}
          >
            <MenuItem value="auto">
              Auto{detectedDelimiter ? ` — ${DELIMITER_LABELS[detectedDelimiter]}` : ""}
            </MenuItem>
            {DELIMITERS.map((d) => (
              <MenuItem key={d} value={d}>
                {DELIMITER_LABELS[d]}
              </MenuItem>
            ))}
          </TextField>
          <FormControlLabel
            control={<Switch checked={header} onChange={(e) => onHeader(e.target.checked)} />}
            label="First row is a header"
          />
        </Stack>
      ) : (
        table.note && <Alert severity="info">{table.note}</Alert>
      )}
      {format !== "csv" && (
        <Typography variant="body2" color="text.secondary">
          Nested objects are shown as dotted columns; the stored document nests them again from
          the target paths you choose in the next step.
        </Typography>
      )}
      <Typography variant="body2">
        {table.rows.length.toLocaleString()} row{table.rows.length === 1 ? "" : "s"},{" "}
        {table.columns.length} column{table.columns.length === 1 ? "" : "s"}
        {table.rows.length > PREVIEW_ROWS && ` — the first ${PREVIEW_ROWS} are shown`}.
      </Typography>
      <PreviewTable table={table} />
    </Stack>
  );
}
