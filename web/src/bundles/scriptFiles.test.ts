import { describe, expect, it } from "vitest";
import { buildBundleZip, readBundleZip, scriptPathClash, validScriptPath } from "./bundlezip";
import { bytesToBase64, safeFileName, scriptBytes, scriptText } from "./scriptFiles";
import {
  registerScript,
  registrableAt,
  registrationsOf,
  scriptLanguageById,
  scriptLanguageOf,
} from "../config/templates";
import { getIniValue, iniToJson } from "../config/ini";
import { TEMPLATES } from "../config/templates";

const bytes = (s: string) => new TextEncoder().encode(s);

describe("script text", () => {
  it("writes batch files with CRLF and everything else with LF", () => {
    expect(scriptBytes("scripts/a.bat", "a\nb\n")).toEqual(bytes("a\r\nb\r\n"));
    expect(scriptBytes("scripts/a.CMD", "a\r\nb")).toEqual(bytes("a\r\nb"));
    expect(scriptBytes("scripts/a.sh", "a\r\nb\n")).toEqual(bytes("a\nb\n"));
  });

  it("reads CRLF as LF, and keeps a BOM the file had", () => {
    const withBom = new Uint8Array([0xef, 0xbb, 0xbf, ...bytes("x\r\n")]);
    expect(scriptText(withBom)).toBe("x\n");
    expect(scriptBytes("scripts/a.bat", "y\n", withBom)).toEqual(
      new Uint8Array([0xef, 0xbb, 0xbf, ...bytes("y\r\n")]),
    );
  });

  it("refuses to show what is not UTF-8", () => {
    expect(scriptText(new Uint8Array([0xff, 0xfe, 0x41, 0x00]))).toBeNull();
  });

  it("base64-encodes large files without overflowing the stack", () => {
    const big = new Uint8Array(200_000).fill(65);
    expect(atob(bytesToBase64(big)).length).toBe(200_000);
  });

  it("makes uploaded file names path-safe", () => {
    expect(safeFileName("C:\\Users\\me\\check disk (1).ps1")).toBe("check_disk__1_.ps1");
    expect(safeFileName("..")).toBe("script");
  });
});

describe("script paths", () => {
  it("mirror the server's rule", () => {
    for (const ok of ["scripts/a.bat", "scripts/python/lib/x.py"]) {
      expect(validScriptPath(ok)).toBe(true);
    }
    for (const bad of [
      "a.bat",
      "scripts/",
      "scripts//a",
      "scripts/../a",
      "scripts/./a",
      "scripts/a b",
      "scripts/1/2/3/4/5/6/7/8/9",
    ]) {
      expect(validScriptPath(bad)).toBe(false);
    }
  });

  it("clash by case and as file against folder, like the server's", () => {
    const all = ["scripts/A.bat", "scripts/a.bat", "scripts/x", "scripts/x/y.sh", "scripts/xy"];
    expect(scriptPathClash("scripts/A.bat", all)).toBe("scripts/a.bat");
    expect(scriptPathClash("scripts/x", all)).toBe("scripts/x/y.sh");
    expect(scriptPathClash("scripts/x/y.sh", all)).toBe("scripts/x");
    expect(scriptPathClash("scripts/xy", all)).toBeUndefined();
  });

  it("round-trip through the client-built zip apart from other entries", () => {
    const zip = buildBundleZip(
      "b",
      "1",
      {},
      [["assets/x.txt", bytes("x")]],
      [{ path: "scripts/a.sh", data: bytes("echo") }],
    );
    const opened = readBundleZip(zip);
    expect(opened.scripts).toEqual([{ path: "scripts/a.sh", data: bytes("echo") }]);
    expect(opened.carried.map(([p]) => p)).toEqual(["assets/x.txt"]);
  });
});

describe("script registration", () => {
  it("enables the module, the fleet script root, and the entry", () => {
    const ini = registerScript("", scriptLanguageById("batch"), "check_x", "scripts/x.bat");
    expect(getIniValue(ini, "/modules", "CheckExternalScripts")).toBe("enabled");
    expect(getIniValue(ini, "/settings/default", "script root")).toBe("fleet");
    expect(getIniValue(ini, "/settings/external scripts/scripts", "check_x")).toBe(
      "scripts\\x.bat",
    );
  });

  it("names Python and Lua scripts relative to their module's folder", () => {
    const py = scriptLanguageById("python");
    const lua = scriptLanguageById("lua");
    expect(py.entry("c", "scripts/python/sub/c.py").value).toBe("sub/c.py");
    expect(lua.entry("c", "scripts/c.lua").value).toBe("c.lua");
    expect(scriptLanguageOf("scripts/x.SH")?.id).toBe("shell");
    expect(scriptLanguageOf("scripts/x.ps1")).toBeUndefined();
  });

  it("finds the entries that run a script, and only those", () => {
    let ini = registerScript("", scriptLanguageById("batch"), "check_x", "scripts/x.bat");
    ini = registerScript(ini, scriptLanguageById("shell"), "check_y", "scripts/y.sh");
    ini = registerScript(ini, scriptLanguageById("lua"), "check_z", "scripts/lua/z.lua");
    expect(registrationsOf(ini, "scripts/x.bat")).toEqual([
      { section: "/settings/external scripts/scripts", key: "check_x" },
    ]);
    expect(registrationsOf(ini, "scripts/y.sh").map((r) => r.key)).toEqual(["check_y"]);
    expect(registrationsOf(ini, "scripts/lua/z.lua").map((r) => r.key)).toEqual(["check_z"]);
    expect(registrationsOf(ini, "scripts/other.bat")).toEqual([]);
    expect(registrationsOf(ini, "scripts/x.ps1")).toEqual([]);
  });

  it("registers Python and Lua only where their module looks", () => {
    expect(registrableAt(scriptLanguageById("python"), "scripts/python/a.py")).toBe(true);
    expect(registrableAt(scriptLanguageById("python"), "scripts/a.py")).toBe(false);
    expect(registrableAt(scriptLanguageById("lua"), "scripts/a.lua")).toBe(false);
    expect(registrableAt(scriptLanguageById("batch"), "scripts/sub/a.bat")).toBe(true);
  });

  it("script templates ship a valid script their INI registers", () => {
    const scripted = TEMPLATES.filter((t) => t.scripts !== undefined);
    expect(scripted.map((t) => t.id)).toEqual([
      "batch-script",
      "shell-script",
      "python-script",
      "lua-script",
    ]);
    for (const t of scripted) {
      expect(() => iniToJson(t.ini)).not.toThrow();
      for (const s of t.scripts!) {
        expect(validScriptPath(s.path)).toBe(true);
        const lang = scriptLanguageOf(s.path)!;
        const file = s.path.split("/").pop()!;
        expect(t.ini).toContain(lang.module);
        expect(t.ini).toContain(file);
      }
    }
  });
});
