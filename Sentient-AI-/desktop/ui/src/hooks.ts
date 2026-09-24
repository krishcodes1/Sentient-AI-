/**
 * React hooks around the bridge's event streams: subscribe to `stack://log` / `stack://phase`
 * for as long as a component is mounted, and keep a capped, batched buffer of log lines.
 *
 * Why it exists: `docker compose up --build` can print hundreds of lines a second. Re-rendering
 * once per line would make the window stutter, so lines are queued and flushed at most every
 * 50 ms, and only the last 2,000 are kept. Subscriptions are async in Tauri (`listen` returns a
 * promise), which makes cleanup easy to get wrong; `useBridgeEvent` does it once.
 */

import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import type { UnlistenFn } from "./bridge";
import { cleanLogLines } from "./format";

type Subscribe<T> = (handler: (payload: T) => void) => Promise<UnlistenFn>;

/** Call `handler` for every event from `subscribe` while mounted (and `enabled`). */
export function useBridgeEvent<T>(subscribe: Subscribe<T>, handler: (payload: T) => void, enabled = true) {
  const latest = useRef(handler);
  useLayoutEffect(() => {
    latest.current = handler;
  });

  useEffect(() => {
    if (!enabled) return undefined;
    let cancelled = false;
    let unlisten: UnlistenFn | null = null;
    subscribe((payload) => {
      if (!cancelled) latest.current(payload);
    })
      .then((fn) => {
        if (cancelled) fn();
        else unlisten = fn;
      })
      .catch(() => {
        /* No event stream (e.g. the window is closing); the status poll still works. */
      });
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, [subscribe, enabled]);
}

export const MAX_LOG_LINES = 2000;
const FLUSH_MS = 50;

/** A log buffer that batches appends and keeps the newest `max` lines. */
export function useLogBuffer(max = MAX_LOG_LINES) {
  const [lines, setLines] = useState<string[]>([]);
  const pending = useRef<string[]>([]);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const flush = useCallback(() => {
    timer.current = null;
    const batch = pending.current;
    pending.current = [];
    if (!batch.length) return;
    setLines((prev) => {
      const next = prev.concat(batch);
      return next.length > max ? next.slice(next.length - max) : next;
    });
  }, [max]);

  const append = useCallback(
    (raw: string) => {
      pending.current.push(...cleanLogLines(raw));
      if (timer.current === null) timer.current = setTimeout(flush, FLUSH_MS);
    },
    [flush],
  );

  const clear = useCallback(() => {
    pending.current = [];
    if (timer.current !== null) clearTimeout(timer.current);
    timer.current = null;
    setLines([]);
  }, []);

  useEffect(
    () => () => {
      if (timer.current !== null) clearTimeout(timer.current);
    },
    [],
  );

  return { lines, append, clear };
}

/** True when the user asked the OS for less motion. */
export function prefersReducedMotion(): boolean {
  return typeof window !== "undefined" && typeof window.matchMedia === "function"
    ? window.matchMedia("(prefers-reduced-motion: reduce)").matches
    : false;
}
