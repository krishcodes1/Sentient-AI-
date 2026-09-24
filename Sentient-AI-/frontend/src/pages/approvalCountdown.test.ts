import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { formatCountdown, useCountdown } from "@/pages/approvalCountdown";

/**
 * These two helpers drive the "expires in m:ss" label *and* the `expired`
 * flag that disables Approve/Deny on both the Chat card and the Dashboard
 * row. The server enforces the same TTL, so if the countdown never reaches 0
 * the buttons stay live and every late click 404s; if it reaches 0 early, a
 * still-valid approval becomes un-actionable. Both are silent in manual QA,
 * which is why they are pinned here.
 */

const FIXED_NOW = new Date("2026-08-04T12:00:00.000Z");

describe("formatCountdown", () => {
  it("renders sub-hour durations as m:ss with a zero-padded seconds field", () => {
    expect(formatCountdown(0)).toBe("0:00");
    expect(formatCountdown(9)).toBe("0:09");
    expect(formatCountdown(59)).toBe("0:59");
    expect(formatCountdown(60)).toBe("1:00");
    expect(formatCountdown(65)).toBe("1:05");
    expect(formatCountdown(599)).toBe("9:59");
  });

  it("switches to h:mm:ss once the remaining time reaches an hour", () => {
    // Without the h:mm:ss branch a 90-minute TTL reads "90:00", which is
    // indistinguishable from 90 seconds at a glance.
    expect(formatCountdown(3600)).toBe("1:00:00");
    expect(formatCountdown(3725)).toBe("1:02:05");
    expect(formatCountdown(3599)).toBe("59:59");
  });
});

describe("useCountdown", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(FIXED_NOW);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("returns null when there is no parseable deadline", () => {
    // null means "no TTL" — the caller keeps such cards fully interactive,
    // so an unparseable date must not be mistaken for an expired one.
    expect(renderHook(() => useCountdown(null)).result.current).toBeNull();
    expect(renderHook(() => useCountdown(undefined)).result.current).toBeNull();
    expect(renderHook(() => useCountdown("not a date")).result.current).toBeNull();
  });

  it("reports whole seconds remaining and ticks down once per second", () => {
    const expiresAt = new Date(FIXED_NOW.getTime() + 90_000).toISOString();
    const { result } = renderHook(() => useCountdown(expiresAt));

    expect(result.current).toBe(90);

    act(() => {
      vi.advanceTimersByTime(1000);
    });
    expect(result.current).toBe(89);

    act(() => {
      vi.advanceTimersByTime(30_000);
    });
    expect(result.current).toBe(59);
  });

  it("clamps an already-past deadline to 0 instead of going negative", () => {
    // The `expired` flag both callers derive is `remaining <= 0`; a negative
    // value would still be "expired", but formatCountdown would render it as
    // "-1:-5" if the label were ever shown.
    const expiresAt = new Date(FIXED_NOW.getTime() - 5_000).toISOString();
    const { result } = renderHook(() => useCountdown(expiresAt));

    expect(result.current).toBe(0);

    act(() => {
      vi.advanceTimersByTime(10_000);
    });
    expect(result.current).toBe(0);
  });

  it("stops ticking once it reaches zero", () => {
    const expiresAt = new Date(FIXED_NOW.getTime() + 2_000).toISOString();
    const { result } = renderHook(() => useCountdown(expiresAt));

    act(() => {
      vi.advanceTimersByTime(2_000);
    });
    expect(result.current).toBe(0);
    // The interval clears itself at zero; nothing is left to fire.
    expect(vi.getTimerCount()).toBe(0);

    act(() => {
      vi.advanceTimersByTime(60_000);
    });
    expect(result.current).toBe(0);
  });

  it("restarts the countdown when the deadline prop changes", () => {
    // Chat swaps approval cards in place as the poller reconciles the queue,
    // so a stale closure over the old target would freeze the label.
    const { result, rerender } = renderHook(
      ({ iso }: { iso: string }) => useCountdown(iso),
      { initialProps: { iso: new Date(FIXED_NOW.getTime() + 10_000).toISOString() } },
    );

    expect(result.current).toBe(10);

    rerender({ iso: new Date(FIXED_NOW.getTime() + 600_000).toISOString() });
    expect(result.current).toBe(600);
  });
});
