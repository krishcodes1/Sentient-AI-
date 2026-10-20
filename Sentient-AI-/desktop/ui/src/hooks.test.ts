/**
 * Hook tests: `useBridgeEvent` cleans up a subscription even when Tauri's `listen` promise
 * settles after the component has already gone.
 *
 * Why it exists: Subscribing is async, so a screen can unmount before `listen` hands back its
 * unlisten function. If that late function is dropped, the listener stays registered for the
 * life of the window. The component tests only see subscriptions that resolve straight away.
 */

import { renderHook, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { UnlistenFn } from "./bridge";
import { useBridgeEvent } from "./hooks";

describe("useBridgeEvent", () => {
  it("unlistens a subscription that resolves after unmount, and never delivers its events", async () => {
    let deliver!: (payload: string) => void;
    let resolveListen!: (fn: UnlistenFn) => void;
    const subscribe = vi.fn(
      (handler: (payload: string) => void) =>
        new Promise<UnlistenFn>((resolve) => {
          deliver = handler;
          resolveListen = resolve;
        }),
    );
    const handler = vi.fn();
    const unlisten = vi.fn();

    const { unmount } = renderHook(() => useBridgeEvent(subscribe, handler));
    expect(subscribe).toHaveBeenCalledTimes(1);
    unmount();

    resolveListen(unlisten);
    await waitFor(() => expect(unlisten).toHaveBeenCalledTimes(1));
    deliver("late line");
    expect(handler).not.toHaveBeenCalled();
  });
});
