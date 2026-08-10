// Shared fetch helpers + wire types for the control-plane API.

export type Me = {
  user_id: number;
  email: string;
  role: string;
  tenant_id: number;
  tenant_slug: string;
  tenant_name: string;
  on_prem: boolean;
};

/** Derived server-side from `enrolled_at` + the bootstrap deadline. See `HostStatus` in
 *  `crates/core/src/host.rs` — `never_enrolled` is terminal, the row cannot be recovered. */
export type HostStatus = "enrolled" | "awaiting_enrollment" | "never_enrolled";

export type HostView = {
  id: string;
  hostname: string | null;
  os: string | null;
  enrolled_at: number | null;
  last_seen_at: number | null;
  current_state_hash: string | null;
  status: HostStatus;
  bootstrap_expires_at: number | null;
  created_at: number;
};

export type TagView = { key: string; value: string; source: "manual" | "agent" };

export type HostDetail = HostView & {
  tags: TagView[];
  override_meta: { priority: number } | null;
};

export type DesiredBundleView = {
  id: string;
  name: string;
  version: string;
  sha256: string;
  priority: number;
};

export type DesiredStateView = {
  state_hash: string;
  in_sync: boolean;
  bundles: DesiredBundleView[];
};

export type CreateHostResponse = {
  host_id: string;
  bootstrap_token: string;
  install_command: string;
  expires_at: number;
};

// Selector expression tree — mirrors fleet_core::selector::Expr (serde tag = "op").
export type Expr =
  | { op: "eq"; key: string; value: string }
  | { op: "in"; key: string; values: string[] }
  | { op: "exists"; key: string }
  | { op: "not"; expr: Expr }
  | { op: "and"; exprs: Expr[] }
  | { op: "or"; exprs: Expr[] };

export type Selector = { clauses: Expr[] };

export type GroupView = {
  id: string;
  name: string;
  selector: Selector;
  created_at: number;
};

export type BundleView = {
  id: string;
  name: string;
  version: string;
  sha256: string;
  size_bytes: number;
  signature: string;
  uploaded_at: number;
};

export type BundleConfigView = {
  id: string;
  name: string;
  version: string;
  config_json: Record<string, unknown>;
  scripts: string[];
};

export type AssignmentView = {
  bundle_id: string;
  name: string;
  version: string;
  priority: number;
};

export type PreviewMatch = { id: string; hostname: string | null };

export type AuditView = {
  id: number;
  user_id: number | null;
  action: string;
  target_type: string;
  target_id: string;
  metadata_json: string | null;
  ts: number;
};

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function handle<T>(r: Response): Promise<T> {
  if (!r.ok) {
    let msg = `HTTP ${r.status}`;
    try {
      msg = (await r.text()) || msg;
    } catch {
      /* keep default */
    }
    throw new ApiError(r.status, msg);
  }
  if (r.status === 204) return undefined as T;
  return (await r.json()) as T;
}

export function apiGet<T>(path: string): Promise<T> {
  return fetch(path, { credentials: "include" }).then((r) => handle<T>(r));
}

export function apiSend<T>(method: string, path: string, body?: unknown): Promise<T> {
  return fetch(path, {
    method,
    credentials: "include",
    headers: body !== undefined ? { "Content-Type": "application/json" } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  }).then((r) => handle<T>(r));
}

export function apiUpload<T>(path: string, form: FormData): Promise<T> {
  return fetch(path, { method: "POST", credentials: "include", body: form }).then((r) =>
    handle<T>(r),
  );
}

export function fmtTime(ts: number | null | undefined): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

export function fmtAgo(ts: number | null | undefined): string {
  if (!ts) return "never";
  const s = Math.max(0, Math.floor(Date.now() / 1000) - ts);
  if (s < 90) return `${s}s ago`;
  if (s < 5400) return `${Math.round(s / 60)}m ago`;
  if (s < 129600) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

export function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}
