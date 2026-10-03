import { useState } from "react";
import { TextField, ToggleButton, ToggleButtonGroup } from "@mui/material";
import { TemplateForm } from "./TemplateForm";
import { BundleTemplate } from "./templates";

type Props = {
  /** The template the document was created from, when known: offers the visual view. */
  template: BundleTemplate | undefined;
  /** The INI document — single source of truth for both views. */
  ini: string;
  onChange: (ini: string) => void;
  minRows?: number;
};

/** A configuration document edited as a template's form (Visual) or as raw INI. Both views
 *  edit the same INI text, so switching is lossless; visual is only offered while the
 *  template is known. Shared by the bundle editor and the host override editor. */
export function ConfigEditor({ template, ini, onChange, minRows = 14 }: Props) {
  const [view, setView] = useState<"form" | "ini">("form");
  const formCapable = template !== undefined && template.fields.length > 0;
  const effectiveView = formCapable && view === "form" ? "form" : "ini";
  return (
    <>
      {formCapable && (
        <ToggleButtonGroup
          size="small"
          exclusive
          value={effectiveView}
          onChange={(_, v: "form" | "ini" | null) => v !== null && setView(v)}
          sx={{ mb: 1 }}
        >
          <ToggleButton value="form">Visual</ToggleButton>
          <ToggleButton value="ini">INI</ToggleButton>
        </ToggleButtonGroup>
      )}
      {effectiveView === "form" && template ? (
        <TemplateForm template={template} ini={ini} onChange={onChange} />
      ) : (
        <TextField
          multiline
          minRows={minRows}
          fullWidth
          spellCheck={false}
          value={ini}
          onChange={(e) => onChange(e.target.value)}
          slotProps={{
            input: {
              sx: { fontFamily: "monospace", fontSize: "0.9rem", whiteSpace: "pre" },
            },
          }}
        />
      )}
    </>
  );
}
