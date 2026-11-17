import { useEffect, useState } from "react";
import { getProviderModels } from "@/services/api";

export interface ProviderModels {
  models: string[];
  /** true when the list came from the provider itself, not the fallback. */
  live: boolean;
  loading: boolean;
}

/** The models *provider* offers: asked of the provider with this Crawler's
 * key, or with *apiKey* (one just typed into the setup form, asked after a
 * short pause in typing). *fallback* until it answers, or if it cannot. */
export function useProviderModels(
  provider: string | null | undefined,
  fallback: string[],
  apiKey = "",
): ProviderModels {
  const [live, setLive] = useState<{ for: string; models: string[] } | null>(null);
  const [loading, setLoading] = useState(false);
  const key = apiKey.trim();
  const wanted = `${provider ?? ""}\n${key}`;
  useEffect(() => {
    if (!provider) return;
    let stale = false;
    const timer = setTimeout(
      () => {
        setLoading(true);
        getProviderModels(provider, key || undefined)
          .then((r) => {
            if (!stale) setLive({ for: wanted, models: r.live ? r.models : [] });
          })
          .catch(() => {})
          .finally(() => {
            if (!stale) setLoading(false);
          });
      },
      key ? 600 : 0,
    );
    return () => {
      stale = true;
      clearTimeout(timer);
    };
  }, [provider, key, wanted]);
  const fresh = live && live.for === wanted && live.models.length ? live.models : null;
  return { models: fresh ?? fallback, live: !!fresh, loading };
}
