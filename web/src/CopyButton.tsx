import { useEffect, useState } from "react";
import { IconButton, Tooltip } from "@mui/material";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import CheckIcon from "@mui/icons-material/Check";

/** Copies `text` to the clipboard and confirms in place for a moment. The tooltip names
 *  what gets copied, so a row of these next to different values stays unambiguous. */
export function CopyButton({ text, label }: { text: string; label: string }) {
  const [copied, setCopied] = useState(false);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    if (!copied && !failed) return;
    const t = setTimeout(() => {
      setCopied(false);
      setFailed(false);
    }, 1500);
    return () => clearTimeout(t);
  }, [copied, failed]);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
    } catch {
      // Clipboard access needs a secure context and a user gesture; a self-signed
      // page opened by IP in some browsers has neither. Say so rather than pretend.
      setFailed(true);
    }
  };
  const title = copied ? "Copied" : failed ? "Copy blocked by the browser — select and copy" : label;
  return (
    <Tooltip title={title} open={copied || failed ? true : undefined}>
      <IconButton size="small" onClick={() => void copy()} aria-label={label} color={copied ? "success" : "default"}>
        {copied ? <CheckIcon fontSize="small" /> : <ContentCopyIcon fontSize="small" />}
      </IconButton>
    </Tooltip>
  );
}
