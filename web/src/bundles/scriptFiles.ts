// Script files as the editor sees them: bytes in the bundle, text in the textarea.
//
// Only what is actually edited is re-encoded — an untouched file keeps its exact bytes —
// so an uploaded UTF-16 PowerShell file or a hand-tuned binary helper survives a save.

const UTF8_BOM = [0xef, 0xbb, 0xbf];

function hasBom(data: Uint8Array): boolean {
  return data.length >= 3 && UTF8_BOM.every((b, i) => data[i] === b);
}

/** The file as editor text (LF line endings, BOM dropped), or null when it is not UTF-8
 *  — binary, UTF-16 — and so cannot be edited here without corrupting it. */
export function scriptText(data: Uint8Array): string | null {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(data).replace(/\r\n/g, "\n");
  } catch {
    return null;
  }
}

/** Bytes of edited text for the file at `path`. Batch files get CRLF — cmd.exe misreads
 *  labels and GOTO targets in LF-only batch files — everything else LF. A UTF-8 BOM the
 *  previous content had is kept. */
export function scriptBytes(path: string, text: string, previous?: Uint8Array): Uint8Array {
  let body = text.replace(/\r\n/g, "\n");
  if (/\.(bat|cmd)$/i.test(path)) body = body.replace(/\n/g, "\r\n");
  const encoded = new TextEncoder().encode(body);
  if (previous === undefined || !hasBom(previous)) return encoded;
  const out = new Uint8Array(encoded.length + 3);
  out.set(UTF8_BOM);
  out.set(encoded, 3);
  return out;
}

export function bytesToBase64(data: Uint8Array): string {
  let bin = "";
  // Chunked: spreading a whole large file into fromCharCode overflows the call stack.
  for (let i = 0; i < data.length; i += 0x8000) {
    bin += String.fromCharCode(...data.subarray(i, i + 0x8000));
  }
  return btoa(bin);
}

/** A file name made fit for a script path: anything outside [A-Za-z0-9._-] becomes "_". */
export function safeFileName(name: string): string {
  const base = name.split(/[\\/]/).pop() ?? "";
  const safe = base.replace(/[^A-Za-z0-9._-]/g, "_").replace(/^\.+/, "");
  return safe === "" ? "script" : safe.slice(0, 128);
}
