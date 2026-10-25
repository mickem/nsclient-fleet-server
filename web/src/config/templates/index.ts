// Pre-defined bundle templates, distilled from the NSClient scenario guides
// (docs/docs/scenarios in the nscp repo). Each template covers ONE concern so bundles
// stay composable: check templates define transport-neutral aliases, and each delivery
// mechanism (NRPE, Check_MK, NSCA, Icinga, …) is its own template — assign one of each
// to a group instead of baking the transport into every check bundle.
//
// The chosen template's id is recorded in the bundle's manifest (bundle.toml,
// `template = "<id>"`) by both save paths — the server's compose and the client-built
// encrypted zip — so the editor can show the association when the bundle is edited later.
//
// A template's `fields` drive the visual (form) editor view. Every field is bound to
// real INI keys and the INI TEXT stays the single source of truth: fields read their
// value out of it and write back with surgical line edits (see getIniValue/setIniValue),
// so switching between the form and the raw INI is lossless and comments survive.
//
// Layout: types.ts (field and template shapes), fields.ts (reading and writing a field in
// the INI), factSets.ts (the facts the agent collects), shared.ts (building blocks the
// definitions share), scripts.ts (the script languages a bundle can ship), and
// definitions/ (one file per category, concatenated below in the order the picker shows
// them).

import { type BundleTemplate } from "./types";
import { SYSTEM_HEALTH } from "./definitions/systemHealth";
import { APPLICATIONS } from "./definitions/applications";
import { SECURITY } from "./definitions/security";
import { DELIVERY } from "./definitions/delivery";
import { FLEET } from "./definitions/fleet";
import { EXTENSIBILITY } from "./definitions/extensibility";

export {
  type FieldWhen,
  type SelectOption,
  type ChoiceOption,
  type TemplateField,
  type TablePreset,
  type BundleTemplate,
  type TemplateScript,
} from "./types";
export {
  TABLE_KEY_RE,
  validTableKey,
  validTableRowKey,
  validTableRowValue,
  fieldValue,
  fieldPresent,
  fieldDefault,
  fieldVisible,
  applyFieldChange,
  tableRows,
  tableAddRow,
  tableRenameRow,
  tableSetRow,
  tableRemoveRow,
} from "./fields";
export { type FactTarget, type FactSet, FACT_SETS, factSetState, setFactSet } from "./factSets";
export { SERVICE_NAME_RE, TAG_NAME_RE } from "./shared";
export {
  type ScriptLanguageId,
  type ScriptLanguage,
  SCRIPT_LANGUAGES,
  scriptLanguageById,
  scriptLanguageOf,
  registerScript,
  registrableAt,
  registrationsOf,
} from "./scripts";

export function templateById(id: string): BundleTemplate | undefined {
  return TEMPLATES.find((t) => t.id === id);
}

/** Display order of picker groups. */
export const TEMPLATE_CATEGORIES = [
  "System health",
  "Applications & network",
  "Security & events",
  "Monitoring delivery",
  "Fleet",
  "Extensibility",
];

export const TEMPLATES: BundleTemplate[] = [
  ...SYSTEM_HEALTH,
  ...APPLICATIONS,
  ...SECURITY,
  ...DELIVERY,
  ...FLEET,
  ...EXTENSIBILITY,
];
