import { useEffect, useRef, useState } from "react";
import {
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Typography,
} from "@mui/material";
import AddIcon from "@mui/icons-material/Add";
import EditIcon from "@mui/icons-material/Edit";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import { apiGet, apiUpload, BundleView, fmtBytes, fmtTime } from "./api";
import { BundleEditor } from "./BundleEditor";

type EditorState = null | { editBundleId: string | null };

export function BundlesPage() {
  const [bundles, setBundles] = useState<BundleView[] | null>(null);
  const [editor, setEditor] = useState<EditorState>(null);
  const [name, setName] = useState("");
  const [version, setVersion] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  const refresh = () => {
    apiGet<BundleView[]>("/api/bundles").then(setBundles, (e) => setError(e.message));
  };
  useEffect(refresh, []);

  const upload = async () => {
    const file = fileRef.current?.files?.[0];
    if (!file || !name.trim() || !version.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const form = new FormData();
      form.set("name", name.trim());
      form.set("version", version.trim());
      form.set("bundle", file);
      await apiUpload("/api/bundles", form);
      setName("");
      setVersion("");
      if (fileRef.current) fileRef.current.value = "";
      refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Box>
      <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 1 }}>
        <Typography variant="h4">Bundles</Typography>
        {!editor && (
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={() => setEditor({ editBundleId: null })}
          >
            New bundle
          </Button>
        )}
      </Stack>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        A bundle is a zip (manifest + config patch + scripts) signed by your tenant key.
        Versions are immutable — to roll back, assign the older version to the group.
      </Typography>
      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {editor && (
        <BundleEditor
          editBundleId={editor.editBundleId}
          onSaved={() => {
            setEditor(null);
            refresh();
          }}
          onCancel={() => setEditor(null)}
        />
      )}

      {bundles === null ? (
        <Typography>Loading…</Typography>
      ) : bundles.length === 0 ? (
        <Card>
          <CardContent>
            <Typography color="text.secondary">
              No bundles yet — create one with the editor, or upload a zip below.
            </Typography>
          </CardContent>
        </Card>
      ) : (
        <TableContainer component={Card}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Name</TableCell>
                <TableCell>Version</TableCell>
                <TableCell>Size</TableCell>
                <TableCell>Uploaded</TableCell>
                <TableCell>sha256</TableCell>
                <TableCell />
              </TableRow>
            </TableHead>
            <TableBody>
              {bundles.map((b) => (
                <TableRow key={b.id} hover>
                  <TableCell>{b.name}</TableCell>
                  <TableCell>{b.version}</TableCell>
                  <TableCell>{fmtBytes(b.size_bytes)}</TableCell>
                  <TableCell>{fmtTime(b.uploaded_at)}</TableCell>
                  <TableCell>
                    <Typography variant="caption" component="code">
                      {b.sha256.slice(0, 16)}…
                    </Typography>
                  </TableCell>
                  <TableCell align="right">
                    <Button
                      size="small"
                      startIcon={<EditIcon />}
                      onClick={() => setEditor({ editBundleId: b.id })}
                    >
                      Edit
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      <Accordion sx={{ mt: 3 }} disableGutters>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography color="text.secondary">Upload a pre-built zip</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Stack direction="row" spacing={1} alignItems="center" useFlexGap flexWrap="wrap">
            <TextField
              size="small"
              label="name"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
            <TextField
              size="small"
              label="version"
              value={version}
              onChange={(e) => setVersion(e.target.value)}
            />
            <input type="file" ref={fileRef} accept=".zip" />
            <Button
              variant="contained"
              onClick={upload}
              disabled={busy || !name.trim() || !version.trim()}
            >
              {busy ? "Uploading…" : "Upload bundle"}
            </Button>
          </Stack>
        </AccordionDetails>
      </Accordion>
    </Box>
  );
}
