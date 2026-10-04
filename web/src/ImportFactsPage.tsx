import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Box, Button, Card, CardContent, Stack, Step, StepLabel, Stepper, Typography } from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import {
  ApiError,
  apiGet,
  apiSend,
  FactsCatalog,
  HostView,
  ImportCommitRequest,
  ImportCommitResponse,
  ImportConflict,
  ImportNormalize,
  ImportRequest,
  ImportResolveResponse,
} from "./api";
import { KnownFacts, knownFactsFromCatalog } from "./SelectorBuilder";
import { CommitStep } from "./importFacts/CommitStep";
import { FileStep, LoadedFile } from "./importFacts/FileStep";
import { MapStep } from "./importFacts/MapStep";
import {
  blockingRows,
  buildRequest,
  DEFAULT_NORMALIZE,
  defaultMapping,
  keyOptions,
  keyTargetLabel,
  MapColumn,
  MAX_IMPORT_ROWS,
  mergeRows,
} from "./importFacts/model";
import {
  buildDocuments,
  Delimiter,
  detectFormat,
  Format,
  importNameError,
  readTable,
  ReadResult,
  suggestImportName,
  targetConflicts,
  targetPathError,
} from "./importFacts/parse";
import { ResolveStep } from "./importFacts/ResolveStep";
import { ShapeStep } from "./importFacts/ShapeStep";

const STEPS = ["File", "Shape", "Map", "Resolve", "Commit"];
const RESOLVE_STEP = 3;

/** The server's message for a failed call: the `error` of a JSON body, else the body. */
function errorText(e: unknown): string {
  const msg = e instanceof Error ? e.message : String(e);
  try {
    const v: unknown = JSON.parse(msg);
    if (typeof v === "object" && v !== null && typeof (v as { error?: unknown }).error === "string") {
      return (v as { error: string }).error;
    }
  } catch {
    /* plain text */
  }
  return msg;
}

/** The rows of a 409 from the commit, when that is what `e` is. */
function conflictOf(e: unknown): ImportConflict | null {
  if (!(e instanceof ApiError) || e.status !== 409) return null;
  try {
    const v: unknown = JSON.parse(e.message);
    if (typeof v === "object" && v !== null && Array.isArray((v as { rows?: unknown }).rows)) {
      return v as ImportConflict;
    }
  } catch {
    /* not the structured conflict */
  }
  return null;
}

const columnsSig = (r: ReadResult | null) => (r?.ok ? r.table.columns.join("\u0000") : "");

/** Import facts from a file: each row becomes one facts document, stored under the source
 *  `import:<name>` on the host its key columns match. */
export function ImportFactsPage() {
  const navigate = useNavigate();
  const [step, setStep] = useState(0);

  // File and how it is read. The parsed table is kept in state, computed when one of these
  // changes, never during render.
  const [file, setFile] = useState<LoadedFile | null>(null);
  const [format, setFormat] = useState<Format>("csv");
  const [delimiter, setDelimiter] = useState<Delimiter | "auto">("auto");
  const [header, setHeader] = useState(true);
  const [read, setRead] = useState<ReadResult | null>(null);

  // Mapping.
  const [mapping, setMapping] = useState<MapColumn[]>([]);
  const [normalize, setNormalize] = useState<ImportNormalize>(DEFAULT_NORMALIZE);
  const [name, setName] = useState("");

  // Resolve.
  const [res, setRes] = useState<ImportResolveResponse | null>(null);
  const [resolvedRequest, setResolvedRequest] = useState<ImportRequest | null>(null);
  const [resolveBusy, setResolveBusy] = useState(false);
  const [resolveError, setResolveError] = useState<string | null>(null);
  const [overrides, setOverrides] = useState<Record<number, string>>({});
  const [skip, setSkip] = useState<ReadonlySet<number>>(new Set());
  const [prune, setPrune] = useState(false);
  const [highlight, setHighlight] = useState<ReadonlySet<number>>(new Set());

  // Commit.
  const [commitBusy, setCommitBusy] = useState(false);
  const [commitError, setCommitError] = useState<string | null>(null);
  const [result, setResult] = useState<ImportCommitResponse | null>(null);

  // What key columns can match against.
  const [hosts, setHosts] = useState<HostView[]>([]);
  const [facts, setFacts] = useState<KnownFacts | null>(null);
  useEffect(() => {
    let live = true;
    apiGet<HostView[]>("/api/hosts").then(
      (h) => live && setHosts(h),
      () => {},
    );
    apiGet<FactsCatalog>("/api/facts/catalog").then(
      (c) => live && setFacts(knownFactsFromCatalog(c)),
      () => {},
    );
    return () => {
      live = false;
    };
  }, []);
  const options = useMemo(() => keyOptions(hosts, facts), [hosts, facts]);

  const clearResolve = () => {
    setRes(null);
    setResolvedRequest(null);
    setResolveError(null);
    setOverrides({});
    setSkip(new Set());
    setPrune(false);
    setHighlight(new Set());
    setCommitError(null);
  };

  /** Read `text` again with new options; a mapping survives when the columns did. */
  const reparse = (text: string, opts: { format: Format; delimiter: Delimiter | "auto"; header: boolean }) => {
    const next = readTable(text, opts);
    if (columnsSig(next) !== columnsSig(read) || !next.ok) {
      setMapping(next.ok ? defaultMapping(next.table, options) : []);
    }
    setRead(next);
    clearResolve();
  };

  const onFile = async (f: File) => {
    const text = await f.text();
    const detected = detectFormat(f.name, text);
    setFile({ name: f.name, text, size: f.size, lastModified: f.lastModified, detected });
    setFormat(detected);
    setDelimiter("auto");
    setHeader(true);
    setName((prev) => (prev === "" || prev === suggestImportName(file?.name ?? "") ? suggestImportName(f.name) : prev));
    setResult(null);
    // Force a fresh mapping: same column names in a different file are a different import.
    const next = readTable(text, { format: detected, delimiter: "auto", header: true });
    setMapping(next.ok ? defaultMapping(next.table, options) : []);
    setRead(next);
    clearResolve();
  };

  const table = read?.ok ? read.table : null;
  const { documents, errors: cellErrors, errorCount: cellErrorCount } = useMemo(
    () => (table ? buildDocuments(table, mapping) : { documents: [], errors: [], errorCount: 0 }),
    [table, mapping],
  );
  const conflicts = useMemo(
    () => targetConflicts(mapping.map((m) => (m.include ? m.target : ""))),
    [mapping],
  );
  const collectedAt = file ? new Date(file.lastModified).toISOString() : undefined;

  const mapIssues = useMemo(() => {
    if (!table) return [];
    const out: string[] = [];
    if (table.rows.length === 0) out.push("The file has no rows.");
    if (table.rows.length > MAX_IMPORT_ROWS) {
      out.push(`The file has ${table.rows.length.toLocaleString()} rows; at most ${MAX_IMPORT_ROWS.toLocaleString()} can be imported at once.`);
    }
    const keys = mapping.filter((m) => m.key);
    if (keys.length === 0) out.push("Mark at least one column as a key.");
    mapping.forEach((m, i) => {
      if (m.key && !m.keyTarget) out.push(`Choose what "${table.columns[i]}" is matched against.`);
    });
    if (!mapping.some((m) => m.include)) out.push("Include at least one column in the document.");
    if (mapping.some((m, i) => m.include && (targetPathError(m.target) !== null || conflicts.has(i)))) {
      out.push("Fix the highlighted target paths.");
    }
    const nameIssue = importNameError(name);
    if (nameIssue) out.push(`Import name: ${nameIssue}`);
    return out;
  }, [table, mapping, conflicts, name]);
  const mapOk = table !== null && mapIssues.length === 0 && cellErrorCount === 0;

  const request = useMemo(
    () =>
      mapOk && table
        ? buildRequest(name, table, mapping, documents, normalize, overrides, collectedAt, skip)
        : null,
    [mapOk, table, name, mapping, documents, normalize, overrides, collectedAt, skip],
  );
  const stale = res !== null && resolvedRequest !== request;

  const resolve = async () => {
    if (!request) return;
    setResolveBusy(true);
    setResolveError(null);
    try {
      const r = await apiSend<ImportResolveResponse>("POST", "/api/facts/import/resolve", request);
      setRes(r);
      setResolvedRequest(request);
      setHighlight(new Set());
      if (!r.absent.some((a) => a.has_source) && r.absent_total <= r.absent.length) setPrune(false);
    } catch (e) {
      setResolveError(errorText(e));
    } finally {
      setResolveBusy(false);
    }
  };

  const commit = async () => {
    if (!request || !res) return;
    setCommitBusy(true);
    setCommitError(null);
    const body: ImportCommitRequest = {
      ...request,
      skip: request.skip ?? [],
      prune,
    };
    try {
      setResult(await apiSend<ImportCommitResponse>("POST", "/api/facts/import", body));
    } catch (e) {
      const conflict = conflictOf(e);
      if (conflict) {
        // The fleet changed between resolve and commit: show the rows the server named.
        setRes(mergeRows(res, conflict.rows));
        setHighlight(new Set(conflict.rows.map((r) => r.index)));
        setResolveError(
          `The server refused the import: ${conflict.rows.length} row${conflict.rows.length === 1 ? "" : "s"} ` +
            "no longer resolve to exactly one host. They are highlighted below.",
        );
        setStep(RESOLVE_STEP);
      } else {
        setCommitError(errorText(e));
      }
    } finally {
      setCommitBusy(false);
    }
  };

  const reset = () => {
    setStep(0);
    setFile(null);
    setRead(null);
    setMapping([]);
    setNormalize(DEFAULT_NORMALIZE);
    setName("");
    setResult(null);
    clearResolve();
  };

  const blocking = res ? blockingRows(res) : [];
  const canNext =
    step === 0
      ? read?.ok === true
      : step === 1
        ? table !== null && table.rows.length > 0
        : step === 2
          ? mapOk
          : step === RESOLVE_STEP
            ? res !== null && !stale && !resolveBusy && blocking.length === 0
            : false;

  const next = () => {
    if (step === 2 && (!res || stale)) void resolve();
    setStep((s) => s + 1);
  };

  const keyLabels = (resolvedRequest ?? request)?.keys.map(keyTargetLabel) ?? [];
  const rowKeys = (resolvedRequest ?? request)?.rows.map((r) => r.keys) ?? [];
  const toStore = res ? res.rows.filter((r) => r.status === "matched").length : 0;

  return (
    <Box>
      <Stack direction="row" alignItems="center" spacing={2} sx={{ mb: 2 }}>
        <Button startIcon={<ArrowBackIcon />} onClick={() => navigate("/hosts")}>
          Hosts
        </Button>
        <Typography variant="h4">Import facts</Typography>
      </Stack>

      <Stepper activeStep={result ? STEPS.length : step} sx={{ mb: 3 }}>
        {STEPS.map((s) => (
          <Step key={s}>
            <StepLabel>{s}</StepLabel>
          </Step>
        ))}
      </Stepper>

      <Card variant="outlined">
        <CardContent>
          {step === 0 && (
            <FileStep
              file={file}
              format={format}
              onFile={onFile}
              onFormat={(f) => {
                setFormat(f);
                if (file) reparse(file.text, { format: f, delimiter, header });
              }}
              error={read && !read.ok ? read.error : null}
            />
          )}
          {step === 1 && table && (
            <ShapeStep
              format={format}
              table={table}
              delimiter={delimiter}
              detectedDelimiter={read?.ok ? read.delimiter : undefined}
              header={header}
              onDelimiter={(d) => {
                setDelimiter(d);
                if (file) reparse(file.text, { format, delimiter: d, header });
              }}
              onHeader={(h) => {
                setHeader(h);
                if (file) reparse(file.text, { format, delimiter, header: h });
              }}
            />
          )}
          {step === 2 && table && (
            <MapStep
              table={table}
              mapping={mapping}
              onMapping={(i, patch) => setMapping((prev) => prev.map((m, j) => (j === i ? { ...m, ...patch } : m)))}
              options={options}
              normalize={normalize}
              onNormalize={setNormalize}
              name={name}
              onName={setName}
              documents={documents}
              cellErrors={cellErrors}
              cellErrorCount={cellErrorCount}
              conflicts={conflicts}
              issues={mapIssues}
            />
          )}
          {step === RESOLVE_STEP && (
            <ResolveStep
              res={res}
              keyLabels={keyLabels}
              rowKeys={rowKeys}
              hosts={hosts}
              overrides={overrides}
              onOverride={(i, id) =>
                setOverrides((prev) => {
                  const nextO = { ...prev };
                  if (id) nextO[i] = id;
                  else delete nextO[i];
                  return nextO;
                })
              }
              skip={skip}
              onSkip={(indices, skipped) =>
                setSkip((prev) => {
                  const nextS = new Set(prev);
                  for (const i of indices) {
                    if (skipped) nextS.add(i);
                    else nextS.delete(i);
                  }
                  return nextS;
                })
              }
              prune={prune}
              onPrune={setPrune}
              busy={resolveBusy}
              error={resolveError}
              stale={stale}
              onResolve={() => void resolve()}
              highlight={highlight}
            />
          )}
          {step === 4 && res && (
            <CommitStep
              summary={{
                source: res.source,
                toStore,
                skipped: skip.size,
                blocking: blocking.length,
                prune,
                absentTotal: res.absent_total,
                collectedAt,
              }}
              nameIssue={importNameError(name)}
              stale={stale}
              busy={commitBusy}
              error={commitError}
              result={result}
              onCommit={() => void commit()}
              onReset={reset}
            />
          )}
        </CardContent>
      </Card>

      {!result && (
        <Stack direction="row" spacing={1} justifyContent="flex-end" sx={{ mt: 2 }}>
          <Button disabled={step === 0 || commitBusy} onClick={() => setStep((s) => s - 1)}>
            Back
          </Button>
          {step < STEPS.length - 1 && (
            <Button variant="contained" disabled={!canNext} onClick={next}>
              Next
            </Button>
          )}
        </Stack>
      )}
    </Box>
  );
}
