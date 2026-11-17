import { useEffect, useState } from "react";
import { getProviderModels } from "@/services/api";

/** The models to suggest for *provider*: every chat model the stored key can
 * use, once the provider answers; *fallback* until then or if it cannot. Any
 * other id can still be typed. */
export function useProviderModels(provider: string | null | undefined, fallback: string[]): string[] {
  const [live, setLive] = useState<{ for: string; models: string[] } | null>(null);
  useEffect(() => {
    if (!provider) return;
    let stale = false;
    getProviderModels(provider)
      .then((r) => {
        if (!stale) setLive({ for: provider, models: r.models });
      })
      .catch(() => {});
    return () => {
      stale = true;
    };
  }, [provider]);
  return live && live.for === provider && live.models.length ? live.models : fallback;
}
