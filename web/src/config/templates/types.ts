import { type FactSet } from "./factSets";

/** Show a field only when another field's value matches. Declare parents BEFORE their
 *  dependents — reconciliation walks fields in order. */
export type FieldWhen = {
  field: string;
  /** Visible when the parent's value is one of these… */
  in?: string[];
  /** …or, alternatively, when the parent's value is non-empty. */
  notEmpty?: boolean;
};

export type SelectOption = { value: string; label: string };

/** One option of a `choice` field: picking it writes a coherent set of keys
 *  (section → key → value). The choice reads back as whichever option's keys all match. */
export type ChoiceOption = {
  value: string;
  label: string;
  set: Record<string, Record<string, string>>;
};

export type TemplateField =
  | {
      kind: "text";
      id: string;
      label: string;
      section: string;
      key: string;
      /** Written when the field first becomes visible or is toggled on; falls back to the
       *  value in the template's base INI. Empty input removes the key. */
      default?: string;
      /** Rendered with an on/off switch: off = key absent (the check is not defined),
       *  on = key present with its default, editable. */
      optional?: boolean;
      /** Label of the inner control when `optional` puts the field's own label on the
       *  switch (defaults to "value"). */
      valueLabel?: string;
      help?: string;
      when?: FieldWhen;
    }
  | {
      kind: "bool";
      id: string;
      label: string;
      section: string;
      key: string;
      default: boolean;
      help?: string;
      when?: FieldWhen;
    }
  | {
      kind: "select";
      id: string;
      label: string;
      section: string;
      key: string;
      options: SelectOption[];
      default: string;
      /** As for text fields: off = key absent (inherited from elsewhere), on = set here. */
      optional?: boolean;
      valueLabel?: string;
      help?: string;
      when?: FieldWhen;
    }
  | {
      kind: "choice";
      id: string;
      label: string;
      options: ChoiceOption[];
      help?: string;
      when?: FieldWhen;
    }
  | {
      /** A checklist of host fact sets. Each set is one bool key, named after the set, in
       *  the settings section of every module that can produce it: checking a set writes
       *  `<id> = true` into all of them (and enables the modules); unchecking removes the
       *  keys rather than writing false, so another bundle can still turn the set on. */
      kind: "facts";
      id: string;
      label: string;
      sets: FactSet[];
      help?: string;
      when?: FieldWhen;
    }
  | {
      /** Every `name = command` entry of a section as an editable table: rename, edit,
       *  delete rows, and add rows from a list of common presets. */
      kind: "table";
      id: string;
      label: string;
      section: string;
      presets: TablePreset[];
      help?: string;
      when?: FieldWhen;
      /** Column headings; default "Name" / "Command" (the check-table origin of this
       *  field). Other uses of a `key = value` section rename them. */
      keyLabel?: string;
      valueLabel?: string;
      /** Label of the add-row dropdown (default "Add check"). */
      addLabel?: string;
      /** Shown when the section has no entries (default "No checks yet — add one below."). */
      emptyText?: string;
      /** Entry-name rule; defaults to `validTableKey` (safe as an INI key and settings-path
       *  segment). A section whose keys are foreign identifiers — Windows service names
       *  like `MSSQL$SQLEXPRESS` — needs its own. */
      keyPattern?: RegExp;
      /** Value rule; unrestricted by default. */
      valuePattern?: RegExp;
      /** Entry names are identifiers of real things (a service), not labels: a preset whose
       *  name is already listed is not added again, instead of getting a numeric suffix. */
      uniqueKeys?: boolean;
      /** Offer "Custom…" in the add dropdown: a small form where both the entry name and
       *  its value are typed before the row is inserted. Presets only need a rename. */
      custom?: {
        keyLabel: string;
        valueLabel: string;
        keyHelp?: string;
        valueHelp?: string;
      };
    };

export type TablePreset = {
  label: string;
  /** Suggested entry name (deduplicated on insert). */
  key: string;
  value: string;
  /** Modules the check needs; enabled in [/modules] when the preset is added. */
  modules?: string[];
};

export type BundleTemplate = {
  /** Stored in bundle.toml; must match the bundle token charset [A-Za-z0-9._-]. */
  id: string;
  title: string;
  category: string;
  description: string;
  /** Carries credentials — the editor suggests saving these encrypted. */
  sensitive?: boolean;
  fields: TemplateField[];
  /** Base INI document; defaults here match the fields' defaults. */
  ini: string;
  /** Files the bundle starts with, at bundle paths under scripts/. A template with scripts
   *  is bundle-only: a host override has nowhere to put them. */
  scripts?: TemplateScript[];
};

export type TemplateScript = { path: string; content: string };
