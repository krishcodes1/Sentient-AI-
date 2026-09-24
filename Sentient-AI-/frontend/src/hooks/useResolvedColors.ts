/**
 * useResolvedColors turns design-token names into concrete color strings by reading them back from
 * a probe element, re-resolving when the theme changes.
 *
 * Why it exists: recharts writes colors to SVG presentation attributes, which never substitute
 * var(), so Dashboard's chart needs real values.
 */

import { useEffect, useState } from "react";
import { useTheme } from "@/hooks/useTheme";

/**
 * Resolve design tokens to concrete color strings.
 *
 * recharts hands its colors to SVG as presentation attributes, which are not
 * CSS and so never substitute `var()`. Reading the custom property directly
 * does not help either: a custom property computes to its own token stream,
 * so `--chart-ok` comes back as the literal text "light-dark(#0e7490,
 * #22d3ee)". Assigning it to a real color property on a throwaway element
 * and reading *that* back is what forces the cascade to pick a side.
 *
 * Falls back to the caller's defaults wherever there is no layout engine to
 * ask (jsdom), so charts still render in tests.
 */
export function useResolvedColors<T extends Record<string, string>>(
  tokens: T,
): Record<keyof T, string> {
  const { resolved } = useTheme();
  const [colors, setColors] = useState<Record<keyof T, string>>(
    () => ({ ...tokens }) as Record<keyof T, string>,
  );

  useEffect(() => {
    const probe = document.createElement("span");
    probe.style.position = "absolute";
    probe.style.opacity = "0";
    probe.style.pointerEvents = "none";
    document.body.appendChild(probe);
    try {
      const next = {} as Record<keyof T, string>;
      for (const [name, fallback] of Object.entries(tokens)) {
        probe.style.color = "";
        probe.style.color = `var(${name}, ${fallback})`;
        const computed = getComputedStyle(probe).color;
        next[name as keyof T] = computed || fallback;
      }
      setColors(next);
    } finally {
      probe.remove();
    }
    // `resolved` is the dependency that matters: the token names are stable,
    // but what they resolve to changes the moment the theme flips.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [resolved]);

  return colors;
}
