// Shared fetch helpers + wire types for the control-plane API.

/** Mirrors `Role` in `crates/core/src/user.rs`. The server is the authority — these are used
 *  to hide controls the caller cannot use, never as the check itself. */
export type Role = "owner" | "admin" | "add_hosts" | "view_only";

/** Roles an admin can hand out. `owner` is established at signup and never assigned. */
export const ASSIGNABLE_ROLES: Role[] = ["admin", "add_hosts", "view_only"];

export const ROLE_LABELS: Record<Role, string> = {
  owner: "Owner",
  admin: "Admin",
  add_hosts: "Add hosts",
  view_only: "View only",
};

export const ROLE_DESCRIPTIONS: Record<Role, string> = {
  owner: "Full control. Created the tenant; cannot be removed or re-roled.",
  admin: "Full control, including managing users.",
  add_hosts: "Can see everything and add hosts. No configuration or user changes.",
  view_only: "Read-only.",
};

export const canManageUsers = (r: Role) => r === "owner" || r === "admin";
export const canWriteConfig = (r: Role) => r === "owner" || r === "admin";
export const canAddHosts = (r: Role) => r === "owner" || r === "admin" || r === "add_hosts";

export type Me = {
  user_id: number;
  email: string;
  role: Role;
  tenant_id: number;
  tenant_slug: string;
  tenant_name: string;
  on_prem: boolean;
  /** Cross-tenant privilege, orthogonal to `role`. Only decides whether the Platform entry
   *  appears — the routes behind it check the flag themselves. */
  is_platform_admin: boolean;
};

export type ApiKeyView = {
  id: string;
  name: string;
  /** e.g. `nsk_a1B2c3D4` — identifies a key without being usable as one. */
  token_prefix: string;
  created_at: number;
  last_used_at: number | null;
};

/** Only ever returned by `POST /api/keys`; the token is unrecoverable afterwards. */
export type CreatedApiKey = ApiKeyView & { token: string };

export type UserView = {
  id: number;
  email: string;
  role: Role;
  created_at: number;
  is_self: boolean;
  /** Blocked by a platform admin. Read-only for a tenant — shown so that a colleague who
   *  cannot sign in has a visible reason. */
  blocked: boolean;
};

/** What a host is actually doing, in one field: enrollment, then liveness, then whether it
 *  is running the configuration we want — worst-first, so a host that stopped calling home
 *  reads `offline` rather than claiming the sync state of whatever it last reported. Derived
 *  server-side; see `HostStatus` in `crates/core/src/host.rs`. `never_enrolled` is terminal,
 *  the row cannot be recovered. */
export type HostStatus =
  | "in_sync"
  | "out_of_sync"
  | "offline"
  | "lost"
  | "awaiting_enrollment"
  | "never_enrolled";

export type HostView = {
  id: string;
  hostname: string | null;
  os: string | null;
  enrolled_at: number | null;
  last_seen_at: number | null;
  current_state_hash: string | null;
  status: HostStatus;
  bootstrap_expires_at: number | null;
  /** Whether the host carries configuration of its own that outranks what the fleet sends.
   *  `null` means the agent has never reported either way (a build older than the field) —
   *  render that as unknown, never as "no". The agent sends only this fact; no local
   *  configuration is ever uploaded. */
  local_config_present: boolean | null;
  created_at: number;
  /** All tags, manual and agent-reported. Present on the list view too, so the hosts page
   *  can filter and bulk-select by tag without a request per row. */
  tags: TagView[];
};

export type TagView = { key: string; value: string; source: "manual" | "agent" };

export type HostDetail = HostView & {
  override_meta: { priority: number } | null;
};

/** Response of the bulk host endpoints. `not_found` lists ids that no longer exist (deleted
 *  from another tab since the list loaded); the rest were processed. */
export type BulkResult = { updated: number; not_found: string[] };

export type DesiredBundleView = {
  id: string;
  name: string;
  version: string;
  sha256: string;
  priority: number;
  format: BundleFormat;
};

export type DesiredStateView = {
  state_hash: string;
  in_sync: boolean;
  bundles: DesiredBundleView[];
};

export type CreateHostResponse = {
  host_id: string;
  bootstrap_token: string;
  /** The enrollment address. The console builds its own commands from this and the
   *  token (see installCommands.ts) so they can carry the browser-held bundle key. */
  server_url: string;
  /** `nscp enroll …` without the bundle key — what API users get. */
  install_command: string;
  expires_at: number;
};

/** Which tag source a leaf will accept a value from. Omitted means `manual`, which is
 *  what every selector written before this field existed means. `agent` and `any` accept
 *  values the host reports about itself, so a leaf using either lets hosts decide their
 *  own membership — and therefore which bundles they are served. */
export type SourceFilter = "manual" | "agent" | "any";

// Selector expression tree — mirrors fleet_core::selector::Expr (serde tag = "op").
export type Expr =
  | { op: "eq"; key: string; value: string; source?: SourceFilter }
  | { op: "in"; key: string; values: string[]; source?: SourceFilter }
  | { op: "exists"; key: string; source?: SourceFilter }
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

export type BundleFormat = "plain" | "enc-v1";

export type BundleView = {
  id: string;
  name: string;
  version: string;
  sha256: string;
  size_bytes: number;
  signature: string;
  uploaded_at: number;
  /** `enc-v1` bundles are encrypted client-side; the server stores ciphertext it can
   *  neither read nor edit, so the INI editor is unavailable for them. */
  format: BundleFormat;
  key_fingerprint: string | null;
};

/** The tenant's registered bundle-encryption-key fingerprint (never the key itself). */
export type BundleKeyView = { fingerprint: string | null };

export type BundleConfigView = {
  id: string;
  name: string;
  version: string;
  config_json: Record<string, unknown>;
  scripts: string[];
  /** Template id recorded in bundle.toml when created from a UI template, else null. */
  template: string | null;
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

// --- Platform console (cross-tenant) ---------------------------------------------------

/** Mirrors `fleet_core::tier::TierLimits`. Tiers are defined in code, so the console reads
 *  them from `/api/platform/tiers` rather than keeping a second copy that drifts. */
export type TierLimits = {
  name: string;
  max_hosts: number;
  min_poll_interval_secs: number;
  per_host_requests_per_minute: number;
  max_bundle_mb: number;
};

/** The numeric fields that may be overridden per tenant. `null` in any field means "inherit
 *  from the named tier" — which is what an empty input in the subscription form sends. */
export type TierOverrides = {
  max_hosts: number | null;
  min_poll_interval_secs: number | null;
  per_host_requests_per_minute: number | null;
  max_bundle_mb: number | null;
};

export type PlatformTenantView = {
  id: number;
  slug: string;
  name: string;
  tier: string;
  overrides: TierOverrides | null;
  /** Tier plus overrides: the numbers this tenant is actually held to. */
  effective: TierLimits;
  trial_expires_at: number | null;
  trial_expired: boolean;
  user_count: number;
  blocked_user_count: number;
  /** Counted the way the `max_hosts` check counts: enrolled, plus hosts still inside their
   *  24h bootstrap window. */
  host_count: number;
  /** How many of those hosts report local configuration outranking the fleet's — how much
   *  of this tenant is only partly centrally managed. */
  local_config_host_count: number;
  created_at: number;
};

export type PlatformUserView = {
  id: number;
  tenant_id: number;
  email: string;
  role: Role;
  blocked_at: number | null;
  is_platform_admin: boolean;
  created_at: number;
  is_self: boolean;
};

export type PlatformSettings = { signups_enabled: boolean; on_prem: boolean };

/** Unauthenticated: whether the sign-in page should offer a signup link at all. */
export type PublicConfig = {
  signups_enabled: boolean;
  on_prem: boolean;
  /** Null when Turnstile is off for this deployment. Public by design — the site key
   *  names the widget, it is not a credential. */
  turnstile_site_key: string | null;
};

/** Result of revoking a host's certificates. The bootstrap token is part of the answer,
 *  not a separate step: revoking without one would strand the host, since enrollment
 *  refuses a host that is already enrolled. */
export type RevokeHostResponse = {
  host_id: string;
  revoked_certs: number;
  bootstrap_token: string;
  install_command: string;
  expires_at: number;
};

export type CreateTenantResponse = {
  tenant: PlatformTenantView;
  /** False when no owner was requested, or when the account was created but its sign-in
   *  link could not be delivered. The tenant exists in both cases. */
  owner_invited: boolean;
};

/** `onprem` sets max_hosts to u32::MAX, which is a limit in name only. */
export const UNLIMITED = 4294967295;
export const fmtLimit = (n: number) => (n >= UNLIMITED ? "unlimited" : n.toLocaleString());

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

/** Like `apiGet`, but for binary responses (bundle bytes). */
export async function apiGetBytes(path: string): Promise<Uint8Array<ArrayBuffer>> {
  const r = await fetch(path, { credentials: "include" });
  if (!r.ok) {
    let msg = `HTTP ${r.status}`;
    try {
      msg = (await r.text()) || msg;
    } catch {
      /* keep default */
    }
    throw new ApiError(r.status, msg);
  }
  return new Uint8Array(await r.arrayBuffer());
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
