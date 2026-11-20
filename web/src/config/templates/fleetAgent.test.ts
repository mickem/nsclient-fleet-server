import { describe, expect, it } from "vitest";
import { getIniValue, iniToJson } from "../ini";
import { DIAGNOSTIC_SETS } from "./diagnosticSets";
import {
  applyFieldChange,
  factSetState,
  fieldDefault,
  fieldPresent,
  setFactSet,
  templateById,
  type TemplateField,
} from "./index";

const template = templateById("fleet-agent")!;
const field = (id: string): TemplateField => template.fields.find((f) => f.id === id)!;
const set = (id: string) => DIAGNOSTIC_SETS.find((s) => s.id === id)!;

describe("fleet agent settings template", () => {
  it("starts with nothing set, so the agent's defaults stay in force", () => {
    expect(iniToJson(template.ini)).toEqual({
      settings: { fleet: {}, facts: {}, core: { "failed checks": {} } },
    });
    for (const f of template.fields) expect(fieldPresent(template.ini, f)).toBe(false);
  });

  it("writes each optional setting under the key the agent reads", () => {
    const keys: [string, string, string, string][] = [
      ["poll_interval", "/settings/fleet", "poll interval", "60s"],
      ["min_poll_interval", "/settings/fleet", "min poll interval", "1s"],
      ["max_poll_interval", "/settings/fleet", "max poll interval", "1d"],
      ["timeout", "/settings/fleet", "timeout", "60s"],
      ["failure_context_interval", "/settings/fleet", "failure context interval", "1h"],
      ["facts_interval", "/settings/facts", "interval", "1h"],
      ["facts_max_size", "/settings/facts", "max size", "1048576"],
      ["record_arguments", "/settings/core/failed checks", "record arguments", "safe"],
      ["statuses", "/settings/core/failed checks", "statuses", "warning, critical, unknown"],
      ["prune_metrics", "/settings/core/failed checks", "prune metrics", "zeros, empty, duplicates"],
      ["prune_pattern", "/settings/core/failed checks", "prune pattern", "Hyper-V Virtual, VirtualBox"],
      ["diagnostics_rows", "/settings/core/failed checks", "diagnostics rows", "10"],
    ];
    let ini = template.ini;
    for (const [id, section, key, def] of keys) {
      // Switching a field on writes its default; every default is non-empty, or the
      // switch could never turn on.
      expect(fieldDefault(template, field(id))).toBe(def);
      ini = applyFieldChange(ini, template, field(id), def);
      expect(getIniValue(ini, section, key)).toBe(def);
    }
    ini = applyFieldChange(ini, template, field("min_poll_interval"), "5m");
    expect(getIniValue(ini, "/settings/fleet", "min poll interval")).toBe("5m");
    // Switched off, the key leaves the bundle rather than being forced to a value.
    ini = applyFieldChange(ini, template, field("min_poll_interval"), "");
    expect(getIniValue(ini, "/settings/fleet", "min poll interval")).toBeUndefined();
    expect(() => iniToJson(ini)).not.toThrow();
  });

  it("writes the capture switches as booleans", () => {
    let ini = applyFieldChange(template.ini, template, field("capture_metrics"), "true");
    ini = applyFieldChange(ini, template, field("capture_diagnostics"), "true");
    ini = applyFieldChange(ini, template, field("failure_context"), "false");
    expect(getIniValue(ini, "/settings/core/failed checks", "capture metrics")).toBe("true");
    expect(getIniValue(ini, "/settings/core/failed checks", "capture diagnostics")).toBe("true");
    expect(getIniValue(ini, "/settings/fleet", "failure context")).toBe("false");
  });

  it("switches a diagnostics table on by its settings key, on both platforms", () => {
    const ini = setFactSet(template.ini, set("services.problems"), true);
    expect(getIniValue(ini, "/settings/system/windows/diagnostics", "services")).toBe("true");
    expect(getIniValue(ini, "/settings/system/unix/diagnostics", "services")).toBe("true");
    expect(getIniValue(ini, "/modules", "CheckSystem")).toBe("enabled");
    // The Windows event log table of the same key is its own switch, in its own module.
    expect(getIniValue(ini, "/settings/eventlog/diagnostics", "services")).toBeUndefined();
    expect(getIniValue(ini, "/modules", "CheckEventLog")).toBeUndefined();
    expect(factSetState(ini, set("services.problems"))).toBe("on");
    expect(factSetState(ini, set("services.events"))).toBe("off");
  });

  it("keeps the Linux journal and Windows event log switches apart", () => {
    let ini = setFactSet(template.ini, set("journal.errors"), true);
    expect(getIniValue(ini, "/settings/system/unix/diagnostics", "errors")).toBe("true");
    expect(factSetState(ini, set("eventlog.errors"))).toBe("off");
    ini = setFactSet(ini, set("eventlog.errors"), true);
    expect(getIniValue(ini, "/settings/eventlog/diagnostics", "errors")).toBe("true");
    expect(getIniValue(ini, "/modules", "CheckEventLog")).toBe("enabled");
    ini = setFactSet(ini, set("journal.errors"), false);
    expect(getIniValue(ini, "/settings/system/unix/diagnostics", "errors")).toBeUndefined();
    expect(factSetState(ini, set("eventlog.errors"))).toBe("on");
  });

  it("writes a switch whose key has a space", () => {
    const ini = setFactSet(template.ini, set("disk.growth_spots"), true);
    expect(getIniValue(ini, "/settings/disk/diagnostics", "growth spots")).toBe("true");
    expect(iniToJson(ini)).toMatchObject({
      settings: { disk: { diagnostics: { "growth spots": "true" } } },
    });
  });

  it("gives every diagnostics table a distinct id", () => {
    const ids = DIAGNOSTIC_SETS.map((s) => s.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});
