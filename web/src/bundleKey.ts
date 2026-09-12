import { useEffect, useState } from "react";
import { apiGet, BundleKeyView } from "./api";
import { keyFingerprintHex, recalledKey, rememberKey } from "./crypto";

/** Registered-key state plus whether this browser session holds the matching key.
 *  Shared by the bundles page (which manages the key) and the hosts page (which hands it
 *  to new agents in their install command). */
export function useBundleKey() {
  const [fingerprint, setFingerprint] = useState<string | null>(null);
  const [unlocked, setUnlocked] = useState(false);
  // Null until /api/bundle-key has answered, so callers can tell "no key" from "not
  // known yet" and avoid flashing a warning that is about to go away.
  const [loaded, setLoaded] = useState(false);

  const sync = async () => {
    const v = await apiGet<BundleKeyView>("/api/bundle-key");
    setFingerprint(v.fingerprint);
    const key = recalledKey();
    setUnlocked(
      key !== null && v.fingerprint !== null && (await keyFingerprintHex(key)) === v.fingerprint,
    );
    setLoaded(true);
  };
  useEffect(() => {
    void sync().catch(() => {});
  }, []);
  return { fingerprint, unlocked, loaded, sync, setUnlocked };
}

/** Unlock this session with a pasted key: it must be *the* registered key. Returns the
 *  problem as text, or null on success. Registering a different key is deliberately not
 *  offered here — that is a tenant-wide decision the bundles page owns. */
export async function unlockWithPastedKey(
  pasted: string,
  registeredFingerprint: string | null,
): Promise<string | null> {
  const key = pasted.trim();
  if (registeredFingerprint === null) return "This tenant has no bundle encryption key registered.";
  let fp: string;
  try {
    fp = await keyFingerprintHex(key);
  } catch (e) {
    return e instanceof Error ? e.message : String(e);
  }
  if (fp !== registeredFingerprint) {
    return `That key's fingerprint (${fp}) does not match the registered one (${registeredFingerprint}).`;
  }
  rememberKey(key);
  return null;
}
