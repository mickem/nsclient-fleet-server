import { useEffect, useRef, useState } from "react";
import { Alert, Box } from "@mui/material";

/** Cloudflare's widget API, as much of it as we use. */
type TurnstileApi = {
  render: (
    el: HTMLElement,
    opts: {
      sitekey: string;
      callback: (token: string) => void;
      "expired-callback": () => void;
      "error-callback": () => void;
    },
  ) => string;
  remove: (id: string) => void;
};

declare global {
  interface Window {
    turnstile?: TurnstileApi;
  }
}

const SCRIPT_SRC = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";

/** Load the widget script once per page, and resolve when `window.turnstile` is usable.
 *  Deliberately on demand rather than a <script> in index.html: a deployment with
 *  Turnstile off should not reach out to a third party at all, let alone on every page
 *  load for a form it never shows. */
let scriptPromise: Promise<void> | null = null;
function loadScript(): Promise<void> {
  if (window.turnstile) return Promise.resolve();
  if (scriptPromise) return scriptPromise;
  scriptPromise = new Promise((resolve, reject) => {
    const el = document.createElement("script");
    el.src = SCRIPT_SRC;
    el.async = true;
    el.defer = true;
    el.onload = () => resolve();
    el.onerror = () => {
      scriptPromise = null;
      reject(new Error("failed to load the Turnstile widget"));
    };
    document.head.appendChild(el);
  });
  return scriptPromise;
}

type Props = {
  siteKey: string;
  /** Called with a fresh token, and with null whenever the previous one stops being
   *  valid — expiry or an error. The form uses null to disable its submit button, so a
   *  stale token is never what gets posted. */
  onToken: (token: string | null) => void;
};

export function Turnstile({ siteKey, onToken }: Props) {
  const hostRef = useRef<HTMLDivElement | null>(null);
  const [error, setError] = useState<string | null>(null);
  // The callbacks are re-created on every render of the parent, but the widget is rendered
  // once — so read them through a ref rather than making them a dependency, which would
  // tear the widget down and rebuild it on each keystroke in the form.
  const onTokenRef = useRef(onToken);
  onTokenRef.current = onToken;

  useEffect(() => {
    let widgetId: string | null = null;
    let cancelled = false;

    loadScript()
      .then(() => {
        if (cancelled || !hostRef.current || !window.turnstile) return;
        widgetId = window.turnstile.render(hostRef.current, {
          sitekey: siteKey,
          callback: (token) => onTokenRef.current(token),
          "expired-callback": () => onTokenRef.current(null),
          "error-callback": () => {
            onTokenRef.current(null);
            setError("The bot check could not be completed. Reload and try again.");
          },
        });
      })
      .catch((e: Error) => {
        if (!cancelled) setError(e.message);
      });

    return () => {
      cancelled = true;
      if (widgetId && window.turnstile) window.turnstile.remove(widgetId);
    };
  }, [siteKey]);

  return (
    <Box>
      <div ref={hostRef} />
      {error && (
        <Alert severity="error" sx={{ mt: 1 }}>
          {error}
        </Alert>
      )}
    </Box>
  );
}
