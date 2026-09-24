/**
 * useCountdown (whole seconds left until an ISO deadline, ticking once a second) and
 * formatCountdown (m:ss or h:mm:ss).
 *
 * Why it exists: Chat's approval cards and Dashboard's approval rows share them, and keeping them
 * out of Chat.tsx stops the Dashboard chunk from importing the whole chat page.
 */

import { useCallback, useSyncExternalStore } from "react";

// Shared by Chat (approval cards) and Dashboard (approval rows). Lives in
// its own module so Dashboard's chunk doesn't have to statically import the
// entire Chat page (react-markdown, remark-gfm, ...) for two tiny helpers —
// that import defeated the route-level code splitting on the default route.

function secondsUntil(target: number): number | null {
  return Number.isNaN(target) ? null : Math.max(0, Math.ceil((target - Date.now()) / 1000));
}

// Remaining whole seconds until `iso`, re-computed every second so approval
// cards can count down toward the server-side TTL instead of silently 404ing
// when the user clicks after expiry. Returns null when there is no deadline
// (or it cannot be parsed) so such cards stay fully interactive.
//
// The clock is an external, always-changing source, so it is read through
// useSyncExternalStore rather than mirrored into state by an effect: a new
// deadline is reflected in the same render that receives it, with no
// intermediate render showing the previous card's value.
export function useCountdown(iso: string | null | undefined): number | null {
  const target = iso ? new Date(iso).getTime() : NaN;
  const subscribe = useCallback(
    (onTick: () => void) => {
      // No deadline, or already past it: the value can never change again —
      // don't tick at all.
      if (Number.isNaN(target) || target <= Date.now()) return () => {};
      const id = window.setInterval(() => {
        onTick();
        if (Date.now() >= target) window.clearInterval(id);
      }, 1000);
      return () => window.clearInterval(id);
    },
    [target],
  );
  // Whole seconds are primitives, so consecutive reads within the same second
  // compare equal and React re-renders only when the label would change.
  return useSyncExternalStore(subscribe, () => secondsUntil(target));
}

// mm:ss (or h:mm:ss past an hour) for the approval countdown.
export function formatCountdown(totalSec: number): string {
  const sec = totalSec % 60;
  const min = Math.floor(totalSec / 60);
  if (min >= 60) {
    const hr = Math.floor(min / 60);
    return `${hr}:${String(min % 60).padStart(2, "0")}:${String(sec).padStart(2, "0")}`;
  }
  return `${min}:${String(sec).padStart(2, "0")}`;
}
