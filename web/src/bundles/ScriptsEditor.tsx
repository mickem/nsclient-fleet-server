import { type KeyboardEvent, useLayoutEffect, useRef, useState } from "react";
import {
  Alert,
  Box,
  Button,
  Checkbox,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControlLabel,
  IconButton,
  MenuItem,
  Stack,
  Tab,
  Tabs,
  TextField,
  ToggleButton,
  ToggleButtonGroup,
  Tooltip,
  Typography,
} from "@mui/material";
import AddIcon from "@mui/icons-material/Add";
import DeleteIcon from "@mui/icons-material/Delete";
import DownloadIcon from "@mui/icons-material/Download";
import UploadFileIcon from "@mui/icons-material/UploadFile";
import { fmtBytes } from "../api";
import {
  registerScript,
  SCRIPT_LANGUAGES,
  scriptLanguageById,
  scriptLanguageOf,
  type ScriptLanguageId,
  TABLE_KEY_RE,
} from "../config/templates";
import { type BundleScript, validScriptPath } from "./bundlezip";
import { safeFileName, scriptBytes, scriptText } from "./scriptFiles";

type Props = {
  scripts: BundleScript[];
  onChange: (scripts: BundleScript[]) => void;
  /** The bundle's INI, so a new script can be registered as a check as it is added. */
  ini: string;
  onIniChange: (ini: string) => void;
};

function downloadFile(s: BundleScript) {
  const url = URL.createObjectURL(new Blob([s.data as Uint8Array<ArrayBuffer>]));
  const a = document.createElement("a");
  a.href = url;
  a.download = s.path.split("/").pop() ?? "script";
  a.click();
  URL.revokeObjectURL(url);
}

/** The files under the bundle's scripts/ folder: a tab per file with a plain-text editor,
 *  plus adding one from a language's example or from an uploaded file. The agent stages
 *  them under its fleet folder; the configuration above says which of them run. */
export function ScriptsEditor({ scripts, onChange, ini, onIniChange }: Props) {
  const [selected, setSelected] = useState<string | null>(scripts[0]?.path ?? null);
  const [adding, setAdding] = useState(false);
  const replaceRef = useRef<HTMLInputElement>(null);
  const textRef = useRef<HTMLTextAreaElement>(null);
  /** Caret to restore after a Tab insertion re-renders the textarea. */
  const caret = useRef<number | null>(null);
  /** Esc then Tab leaves the editor, so the Tab key does not trap keyboard users. */
  const escaped = useRef(false);

  const current = scripts.find((s) => s.path === selected) ?? scripts[0];
  const text = current ? scriptText(current.data) : null;
  const lang = current ? scriptLanguageOf(current.path) : undefined;

  useLayoutEffect(() => {
    if (caret.current !== null && textRef.current) {
      textRef.current.setSelectionRange(caret.current, caret.current);
      caret.current = null;
    }
  });

  const update = (path: string, data: Uint8Array) =>
    onChange(scripts.map((s) => (s.path === path ? { path, data } : s)));

  const setText = (value: string) => {
    if (current) update(current.path, scriptBytes(current.path, value, current.data));
  };

  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key === "Escape") {
      escaped.current = true;
      return;
    }
    if (e.key === "Tab" && !e.shiftKey && !escaped.current && text !== null) {
      const el = e.target as HTMLTextAreaElement;
      e.preventDefault();
      const pad = " ".repeat(lang?.indent ?? 2);
      const { selectionStart: start, selectionEnd: end } = el;
      caret.current = start + pad.length;
      setText(text.slice(0, start) + pad + text.slice(end));
    }
    escaped.current = false;
  };

  const replaceFromFile = async (file: File | undefined) => {
    if (!file || !current) return;
    update(current.path, new Uint8Array(await file.arrayBuffer()));
  };

  const remove = () => {
    if (!current) return;
    const rest = scripts.filter((s) => s.path !== current.path);
    onChange(rest);
    setSelected(rest[0]?.path ?? null);
  };

  return (
    <Box sx={{ mt: 3 }}>
      <Stack direction="row" spacing={1} sx={{ alignItems: "center", mb: 1 }}>
        <Typography variant="h6">Scripts</Typography>
        <Typography variant="body2" sx={{ color: "text.secondary", flexGrow: 1 }}>
          Shipped to the agent&apos;s fleet folder; the configuration above decides which
          run.
        </Typography>
        <Button size="small" startIcon={<AddIcon />} onClick={() => setAdding(true)}>
          Add script
        </Button>
      </Stack>

      {current === undefined ? (
        <Typography variant="body2" sx={{ color: "text.secondary" }}>
          No scripts in this bundle. Add one from an example (batch, shell, Python or Lua) or
          upload your own.
        </Typography>
      ) : (
        <>
          <Tabs
            value={current.path}
            onChange={(_, v: string) => setSelected(v)}
            variant="scrollable"
            allowScrollButtonsMobile
            sx={{ borderBottom: 1, borderColor: "divider", mb: 1 }}
          >
            {scripts.map((s) => (
              <Tab
                key={s.path}
                value={s.path}
                label={s.path.slice("scripts/".length)}
                sx={{ textTransform: "none", fontFamily: "monospace" }}
              />
            ))}
          </Tabs>
          <Stack
            direction="row"
            spacing={1}
            useFlexGap
            sx={{ alignItems: "center", flexWrap: "wrap", mb: 1 }}
          >
            <Typography variant="body2" component="code">
              {current.path}
            </Typography>
            <Chip size="small" variant="outlined" label={lang?.label ?? "other file"} />
            <Typography variant="caption" sx={{ color: "text.secondary", flexGrow: 1 }}>
              {fmtBytes(current.data.length)}
            </Typography>
            <Tooltip title="Replace this file's contents with a file from your computer">
              <IconButton size="small" onClick={() => replaceRef.current?.click()}>
                <UploadFileIcon fontSize="small" />
              </IconButton>
            </Tooltip>
            <input
              ref={replaceRef}
              type="file"
              hidden
              onChange={(e) => {
                void replaceFromFile(e.target.files?.[0]);
                e.target.value = "";
              }}
            />
            <Tooltip title="Download this file">
              <IconButton size="small" onClick={() => downloadFile(current)}>
                <DownloadIcon fontSize="small" />
              </IconButton>
            </Tooltip>
            <Tooltip title="Remove this file from the bundle">
              <IconButton size="small" color="error" onClick={remove}>
                <DeleteIcon fontSize="small" />
              </IconButton>
            </Tooltip>
          </Stack>
          {text === null ? (
            <Alert severity="info">
              This file is not UTF-8 text (binary, or UTF-16), so it is shipped exactly as
              uploaded and cannot be edited here. Replace it with an upload to change it.
            </Alert>
          ) : (
            <TextField
              multiline
              minRows={14}
              maxRows={40}
              fullWidth
              spellCheck={false}
              value={text}
              onChange={(e) => setText(e.target.value)}
              onKeyDown={onKeyDown}
              inputRef={textRef}
              helperText="Tab indents; press Esc then Tab to move on."
              slotProps={{
                input: {
                  sx: { fontFamily: "monospace", fontSize: "0.9rem", whiteSpace: "pre" },
                },
                htmlInput: { wrap: "off" },
              }}
            />
          )}
        </>
      )}

      <AddScriptDialog
        open={adding}
        taken={new Set(scripts.map((s) => s.path))}
        onClose={() => setAdding(false)}
        onAdd={(script, register) => {
          onChange(
            [...scripts.filter((s) => s.path !== script.path), script].sort((a, b) =>
              a.path.localeCompare(b.path),
            ),
          );
          setSelected(script.path);
          if (register) {
            onIniChange(
              registerScript(ini, register.lang, register.name, script.path),
            );
          }
          setAdding(false);
        }}
      />
    </Box>
  );
}

type Registration = { lang: ReturnType<typeof scriptLanguageById>; name: string };

/** Add a script from a language's example or from an uploaded file, optionally
 *  registering it as a check in the bundle's configuration. */
function AddScriptDialog({
  open,
  taken,
  onClose,
  onAdd,
}: {
  open: boolean;
  taken: Set<string>;
  onClose: () => void;
  onAdd: (script: BundleScript, register: Registration | null) => void;
}) {
  const [mode, setMode] = useState<"example" | "upload">("example");
  const [langId, setLangId] = useState<ScriptLanguageId>("batch");
  const [file, setFile] = useState<{ name: string; data: Uint8Array } | null>(null);
  const [name, setName] = useState("check_batch");
  /** The path as typed; null while it still follows the name and language. */
  const [pathEdit, setPathEdit] = useState<string | null>(null);
  const [register, setRegister] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const lang =
    mode === "example" ? scriptLanguageById(langId) : file ? scriptLanguageOf(file.name) : undefined;
  const derivedPath =
    mode === "example"
      ? `${lang!.dir}${name}${lang!.extensions[0]}`
      : file
        ? `${lang?.dir ?? "scripts/"}${safeFileName(file.name)}`
        : "";
  const path = pathEdit ?? derivedPath;
  const pathOk = validScriptPath(path);
  const nameOk = TABLE_KEY_RE.test(name);
  const replacing = taken.has(path);
  const canRegister = lang !== undefined;
  const runsExternally = lang?.module === "CheckExternalScripts";
  const ready =
    pathOk &&
    (mode === "example" ? nameOk && !replacing : file !== null) &&
    (!register || !canRegister || nameOk);

  const reset = () => {
    setMode("example");
    setLangId("batch");
    setFile(null);
    setName("check_batch");
    setPathEdit(null);
    setRegister(true);
    setError(null);
  };
  const close = () => {
    reset();
    onClose();
  };

  const pickFile = async (f: File | undefined) => {
    if (!f) return;
    try {
      setFile({ name: f.name, data: new Uint8Array(await f.arrayBuffer()) });
      setName(safeFileName(f.name).replace(/\.[^.]*$/, "").replace(/[^A-Za-z0-9_-]/g, "_"));
      setPathEdit(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const add = () => {
    if (!ready) return;
    const data =
      mode === "example" ? scriptBytes(path, lang!.starter(name)) : file!.data;
    onAdd({ path, data }, register && canRegister ? { lang: lang!, name } : null);
    reset();
  };

  return (
    <Dialog open={open} onClose={close} fullWidth maxWidth="sm">
      <DialogTitle>Add script</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          <ToggleButtonGroup
            size="small"
            exclusive
            value={mode}
            onChange={(_, v: "example" | "upload" | null) => {
              if (v === null) return;
              setMode(v);
              setPathEdit(null);
              if (v === "example") setName(`check_${langId}`);
            }}
          >
            <ToggleButton value="example">Start from an example</ToggleButton>
            <ToggleButton value="upload">Upload your own</ToggleButton>
          </ToggleButtonGroup>

          {mode === "example" ? (
            <TextField
              select
              size="small"
              label="Language"
              value={langId}
              onChange={(e) => {
                const id = e.target.value as ScriptLanguageId;
                setLangId(id);
                if (name === `check_${langId}`) setName(`check_${id}`);
              }}
            >
              {SCRIPT_LANGUAGES.map((l) => (
                <MenuItem key={l.id} value={l.id}>
                  {l.label}
                </MenuItem>
              ))}
            </TextField>
          ) : (
            <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
              <Button component="label" variant="outlined" startIcon={<UploadFileIcon />}>
                Choose file
                <input
                  type="file"
                  hidden
                  onChange={(e) => {
                    void pickFile(e.target.files?.[0]);
                    e.target.value = "";
                  }}
                />
              </Button>
              <Typography variant="body2" sx={{ color: "text.secondary" }}>
                {file
                  ? `${file.name} (${fmtBytes(file.data.length)}${lang ? `, ${lang.label}` : ""})`
                  : "Batch, shell, Python, Lua — or any helper file the scripts need."}
              </Typography>
            </Stack>
          )}

          <TextField
            size="small"
            label={mode === "upload" && lang && !runsExternally ? "Script alias" : "Check name"}
            value={name}
            onChange={(e) => setName(e.target.value)}
            error={name !== "" && !nameOk}
            helperText={
              mode === "example"
                ? "The check command it registers, and its file name. Letters, digits, _ and -."
                : runsExternally
                  ? "The check command to register it as. Letters, digits, _ and -."
                  : "The key it is loaded under; the script registers its own commands."
            }
            disabled={mode === "upload" && !canRegister}
          />
          <TextField
            size="small"
            label="Path in bundle"
            value={path}
            onChange={(e) => setPathEdit(e.target.value)}
            error={path !== "" && !pathOk}
            helperText={
              path !== "" && !pathOk
                ? "Must be under scripts/, using letters, digits, '.', '_', '-' and '/'."
                : replacing
                  ? mode === "upload"
                    ? "A file with this path exists — it will be replaced."
                    : "A file with this path exists — pick another name."
                  : "Python files go in scripts/python/, Lua in scripts/lua/, where the " +
                    "agent looks for them."
            }
            slotProps={{ htmlInput: { sx: { fontFamily: "monospace" } } }}
          />
          <Tooltip
            title={
              canRegister
                ? ""
                : "Only batch, shell, Python and Lua files can be registered; other files " +
                  "are shipped for the scripts to use."
            }
          >
            <FormControlLabel
              control={
                <Checkbox
                  checked={register && canRegister}
                  disabled={!canRegister}
                  onChange={(e) => setRegister(e.target.checked)}
                />
              }
              label={
                runsExternally || lang === undefined
                  ? "Register it as a check in the configuration"
                  : `Load it with ${lang.module} in the configuration`
              }
            />
          </Tooltip>
          {error && <Alert severity="error">{error}</Alert>}
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={close}>Cancel</Button>
        <Button variant="contained" onClick={add} disabled={!ready}>
          {replacing && mode === "upload" ? "Replace" : "Add"}
        </Button>
      </DialogActions>
    </Dialog>
  );
}
