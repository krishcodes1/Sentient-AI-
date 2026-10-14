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

/**
 * The time left on a card in words, for "Okay to go ahead? This expires in 14 minutes.": whole
 * minutes ("14 minutes", "1 minute"), then "about 2 hours" from 90 minutes and "about 3 days" from
 * 48 hours, as the chat cards say it (cards.expires_in_text). The web card counts down live, so
 * its last minute shows seconds ("40 seconds") where a chat card says "less than a minute".
 */
export function expiresInWords(totalSec: number): string {
  const sec = Number.isFinite(totalSec) ? Math.max(0, Math.floor(totalSec)) : 0;
  if (sec < 60) return sec === 1 ? "1 second" : `${sec} seconds`;
  const min = Math.floor(sec / 60);
  if (min < 90) return min === 1 ? "1 minute" : `${min} minutes`;
  const hours = Math.round(min / 60);
  if (hours < 48) return `about ${hours} hours`;
  return `about ${Math.round(hours / 24).toLocaleString("en-US")} days`;
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
