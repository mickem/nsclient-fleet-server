import { describe, expect, it } from "vitest";
import type { HostView, ImportResolveResponse } from "../api";
import { blockingRows, buildRequest, DEFAULT_NORMALIZE, defaultMapping, keyOptions, mergeRows } from "./model";

const host = (id: string, tags: [string, string][]): HostView => ({
  id,
  hostname: id,
  os: null,
  enrolled_at: null,
  last_seen_at: null,
  current_state_hash: null,
  status: "in_sync",
  bootstrap_expires_at: null,
  local_config_present: null,
  host_override_last: null,
  created_at: 0,
  tags: tags.map(([key, value]) => ({ key, value, source: "manual" })),
});

describe("model", () => {
  it("lists host fields, tags and scalar facts as key options", () => {
    const facts = new Map([
      [
        "agent",
        {
          truncated: false,
          paths: new Map([
            ["os.name", { path: "os.name", kind: "scalar" as const, hosts: 3, values: [] }],
            ["disks", { path: "disks", kind: "list" as const, hosts: 3, values: [] }],
          ]),
        },
      ],
    ]);
    const opts = keyOptions([host("a", [["site", "x"]]), host("b", [["site", "y"]])], facts);
    expect(opts.map((o) => o.label)).toEqual(["Hostname", "Host ID", "site", "agent: os.name"]);
    expect(opts[2].hosts).toBe(2);
  });

  it("picks a hostname-like column as the default key and builds the request", () => {
    const table = { columns: ["serial", "Hostname", "owner"], rows: [["S1", "web-01", "ann"]] };
    const mapping = defaultMapping(table, keyOptions([], null));
    expect(mapping.map((m) => m.key)).toEqual([false, true, false]);
    expect(mapping[1].keyTarget).toEqual({ kind: "host", field: "hostname" });
    const req = buildRequest("cmdb", table, mapping, [{ owner: "ann" }], DEFAULT_NORMALIZE, { 0: "h1" }, undefined);
    expect(req).toEqual({
      name: "cmdb",
      keys: [{ kind: "host", field: "hostname" }],
      normalize: DEFAULT_NORMALIZE,
      rows: [{ keys: ["web-01"], facts: { owner: "ann" }, host_id: "h1" }],
      skip: [],
    });
    const skipped = buildRequest("cmdb", table, mapping, [{}], DEFAULT_NORMALIZE, {}, undefined, new Set([3, 0]));
    expect(skipped.skip).toEqual([0, 3]);
  });

  it("blocks on anything neither matched nor skipped, and merges a 409", () => {
    const res: ImportResolveResponse = {
      source: "import:cmdb",
      rows: [
        { index: 0, status: "matched", host_id: "h1", hostname: "a" },
        { index: 1, status: "unmatched" },
        { index: 2, status: "skipped" },
      ],
      absent: [],
      absent_total: 0,
      stats: { matched: 1, unmatched: 1, ambiguous: 0, duplicate: 0, skipped: 1 },
    };
    expect(blockingRows(res)).toEqual([1]);
    const merged = mergeRows(res, [{ index: 0, status: "duplicate", host_id: "h1", of: 1 }]);
    expect(merged.stats).toEqual({ matched: 0, unmatched: 1, ambiguous: 0, duplicate: 1, skipped: 1 });
    expect(blockingRows(merged)).toEqual([0, 1]);
  });
});
