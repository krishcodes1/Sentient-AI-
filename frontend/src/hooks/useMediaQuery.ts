import { useEffect, useState } from "react";

/**
 * Subscribe to a CSS media query.
 *
 * @param query e.g. "(min-width: 768px)"
 * @returns boolean — whether the query currently matches
 *
 * SSR-safe: returns `false` on the first render in non-browser environments.
 */
export function useMediaQuery(query: string): boolean {
  const getMatch = () =>
    typeof window !== "undefined" && typeof window.matchMedia === "function"
      ? window.matchMedia(query).matches
      : false;

  const [matches, setMatches] = useState<boolean>(getMatch);

  useEffect(() => {
    if (typeof window === "undefined" || typeof window.matchMedia !== "function") {
      return;
    }
    const mql = window.matchMedia(query);
    const onChange = (e: MediaQueryListEvent) => setMatches(e.matches);

    // Sync initial state in case it changed between render and effect.
    setMatches(mql.matches);

    if (typeof mql.addEventListener === "function") {
      mql.addEventListener("change", onChange);
      return () => mql.removeEventListener("change", onChange);
    }
    // Older Safari fallback.
    mql.addListener(onChange);
    return () => mql.removeListener(onChange);
  }, [query]);

  return matches;
}

export default useMediaQuery;
