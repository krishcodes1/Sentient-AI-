import { useEffect, useState } from "react";

// Shared by Chat (approval cards) and Dashboard (approval rows). Lives in
// its own module so Dashboard's chunk doesn't have to statically import the
// entire Chat page (react-markdown, remark-gfm, ...) for two tiny helpers —
// that import defeated the route-level code splitting on the default route.

// Remaining whole seconds until `iso`, re-computed every second so approval
// cards can count down toward the server-side TTL instead of silently 404ing
// when the user clicks after expiry. Returns null when there is no deadline
// (or it cannot be parsed) so such cards stay fully interactive.
export function useCountdown(iso: string | null | undefined): number | null {
  const target = iso ? new Date(iso).getTime() : NaN;
  const [remaining, setRemaining] = useState<number | null>(() =>
    Number.isNaN(target) ? null : Math.max(0, Math.ceil((target - Date.now()) / 1000)),
  );
  useEffect(() => {
    if (Number.isNaN(target)) {
      setRemaining(null);
      return;
    }
    const compute = () => Math.max(0, Math.ceil((target - Date.now()) / 1000));
    const first = compute();
    setRemaining(first);
    // Once expired the value can never change again — don't tick at all.
    if (first <= 0) return;
    const id = window.setInterval(() => {
      const left = compute();
      setRemaining(left);
      if (left <= 0) window.clearInterval(id);
    }, 1000);
    return () => window.clearInterval(id);
  }, [target]);
  return remaining;
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
