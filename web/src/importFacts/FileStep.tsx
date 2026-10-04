import { useRef, useState } from "react";
import { Alert, Box, Button, MenuItem, Stack, TextField, Typography } from "@mui/material";
import UploadFileIcon from "@mui/icons-material/UploadFile";
import { fmtBytes } from "../api";
import { Format, FORMATS } from "./parse";

export type LoadedFile = {
  name: string;
  text: string;
  size: number;
  lastModified: number;
  /** What detection made of it, before any override. */
  detected: Format;
};

const FORMAT_LABELS: Record<Format, string> = { csv: "CSV", json: "JSON", yaml: "YAML" };

/** Larger files are refused before reading: the request they make would exceed the
 *  server's 64 MiB body cap anyway. */
const MAX_FILE_BYTES = 64 * 1024 * 1024;

export function FileStep({
  file,
  format,
  onFile,
  onFormat,
  error,
}: {
  file: LoadedFile | null;
  format: Format;
  onFile: (f: File) => Promise<void>;
  onFormat: (f: Format) => void;
  /** Why the file could not be read as a table in the chosen format. */
  error: string | null;
}) {
  const input = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);

  const take = async (f: File | undefined) => {
    if (!f) return;
    setLoadError(null);
    if (f.size > MAX_FILE_BYTES) {
      setLoadError(`The file is ${fmtBytes(f.size)}; at most ${fmtBytes(MAX_FILE_BYTES)} can be imported.`);
      return;
    }
    try {
      await onFile(f);
    } catch (e) {
      setLoadError(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <Stack spacing={2}>
      <Box
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragging(false);
          void take(e.dataTransfer.files[0]);
        }}
        onClick={() => input.current?.click()}
        sx={{
          border: 2,
          borderStyle: "dashed",
          borderColor: dragging ? "primary.main" : "divider",
          borderRadius: 1,
          p: 4,
          textAlign: "center",
          cursor: "pointer",
          bgcolor: dragging ? "action.hover" : undefined,
        }}
      >
        <UploadFileIcon color="action" sx={{ fontSize: 40 }} />
        <Typography>Drop a CSV, JSON or YAML file here, or click to choose one.</Typography>
        <Typography variant="body2" color="text.secondary">
          Each row becomes one facts document on the host it matches. The file is read in the
          browser; nothing is sent until you resolve.
        </Typography>
        <input
          ref={input}
          type="file"
          hidden
          accept=".csv,.tsv,.txt,.json,.yaml,.yml,text/csv,application/json"
          onChange={(e) => {
            void take(e.target.files?.[0]);
            e.target.value = "";
          }}
        />
      </Box>
      {loadError && <Alert severity="error">{loadError}</Alert>}
      {file && (
        <Stack direction="row" spacing={2} alignItems="center" useFlexGap flexWrap="wrap">
          <Typography>
            <strong>{file.name}</strong> · {fmtBytes(file.size)}
          </Typography>
          <TextField
            select
            size="small"
            label="Format"
            value={format}
            onChange={(e) => onFormat(e.target.value as Format)}
            sx={{ minWidth: 160 }}
            helperText={`Detected: ${FORMAT_LABELS[file.detected]}`}
          >
            {FORMATS.map((f) => (
              <MenuItem key={f} value={f}>
                {FORMAT_LABELS[f]}
              </MenuItem>
            ))}
          </TextField>
          <Button size="small" onClick={() => input.current?.click()}>
            Choose another file
          </Button>
        </Stack>
      )}
      {file && error && <Alert severity="error">Could not read the file as {FORMAT_LABELS[format]}: {error}</Alert>}
    </Stack>
  );
}
