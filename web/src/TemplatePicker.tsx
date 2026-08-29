import { useState } from "react";
import {
  Box,
  Button,
  Card,
  CardActionArea,
  CardContent,
  Chip,
  Stack,
  Tab,
  Tabs,
  Typography,
} from "@mui/material";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import { BundleTemplate, TEMPLATE_CATEGORIES, TEMPLATES } from "./templates";

type Props = {
  /** Called with the chosen template, or null to start blank. */
  onPick: (template: BundleTemplate | null) => void;
  onCancel: () => void;
};

/** First step of "New bundle": pick a single-concern template (or start blank). The
 *  template's settings are then edited in the editor's visual view. One category is
 *  shown at a time (tabs) so the action buttons stay on screen; the selection is kept
 *  when switching tabs and echoed in the "Use …" button. */
export function TemplatePicker({ onPick, onCancel }: Props) {
  const [category, setCategory] = useState(TEMPLATE_CATEGORIES[0]);
  const [selected, setSelected] = useState<BundleTemplate | null>(null);

  return (
    <Box>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
        Templates each cover one concern — checks, or one delivery mechanism — so you can
        assign a health bundle and a transport bundle to the same group independently.
      </Typography>
      <Tabs
        value={category}
        onChange={(_, v: string) => setCategory(v)}
        variant="scrollable"
        allowScrollButtonsMobile
        sx={{ borderBottom: 1, borderColor: "divider", mb: 1.5 }}
      >
        {TEMPLATE_CATEGORIES.map((cat) => (
          <Tab key={cat} label={cat} value={cat} />
        ))}
      </Tabs>
      <Stack direction="row" spacing={1} useFlexGap flexWrap="wrap">
        {TEMPLATES.filter((t) => t.category === category).map((t) => {
          const isSelected = selected?.id === t.id;
          return (
            <Card
              key={t.id}
              variant="outlined"
              sx={{
                width: "16rem",
                borderColor: isSelected ? "primary.main" : undefined,
                bgcolor: isSelected ? "action.selected" : undefined,
              }}
            >
              <CardActionArea onClick={() => setSelected(t)} sx={{ height: "100%" }}>
                <CardContent sx={{ py: 1.5 }}>
                  <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 0.5 }}>
                    {isSelected && <CheckCircleIcon color="primary" fontSize="small" />}
                    <Typography variant="subtitle2">{t.title}</Typography>
                    {t.sensitive && (
                      <Chip label="credentials" size="small" variant="outlined" />
                    )}
                  </Stack>
                  <Typography variant="caption" color="text.secondary">
                    {t.description}
                  </Typography>
                </CardContent>
              </CardActionArea>
            </Card>
          );
        })}
      </Stack>
      <Stack direction="row" spacing={1} alignItems="center" sx={{ mt: 2 }}>
        <Button
          variant="contained"
          disabled={selected === null}
          onClick={() => selected && onPick(selected)}
        >
          {selected ? `Use "${selected.title}"` : "Use template"}
        </Button>
        <Button onClick={() => onPick(null)}>Start blank</Button>
        <Button onClick={onCancel}>Cancel</Button>
      </Stack>
    </Box>
  );
}
