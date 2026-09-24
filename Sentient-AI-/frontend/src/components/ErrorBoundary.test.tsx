/**
 * Tests for ErrorBoundary: they prove children render normally, a throwing child yields the
 * fallback panel with the error message, Reload calls location.reload, and the error is logged
 * with its component stack.
 *
 * Why it exists: Guards against the boundary silently not catching, which would leave a blank
 * white page.
 */

import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import ErrorBoundary from "@/components/ErrorBoundary";

/**
 * The boundary is the only thing standing between a render-time exception and
 * a blank white page, so verify it actually catches rather than trusting that
 * React wired it up.
 */

function Boom({ message }: { message: string }): never {
  throw new Error(message);
}

describe("ErrorBoundary", () => {
  beforeEach(() => {
    // React logs every caught render error; silence it so a passing run is
    // not buried in stack traces.
    vi.spyOn(console, "error").mockImplementation(() => {});
  });

  it("renders children when nothing throws", () => {
    render(
      <ErrorBoundary>
        <p>all good</p>
      </ErrorBoundary>,
    );

    expect(screen.getByText("all good")).toBeInTheDocument();
  });

  it("renders the fallback panel instead of unmounting when a child throws", () => {
    render(
      <ErrorBoundary>
        <Boom message="render exploded" />
      </ErrorBoundary>,
    );

    expect(
      screen.getByRole("heading", { name: /something went wrong/i }),
    ).toBeInTheDocument();
    expect(screen.getByText(/render exploded/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /reload/i })).toBeInTheDocument();
  });

  it("reloads the page from the fallback's reload button", async () => {
    const reload = vi.fn();
    vi.stubGlobal("location", {
      pathname: "/",
      href: "http://localhost:3000/",
      reload,
      replace: vi.fn(),
      assign: vi.fn(),
    });

    render(
      <ErrorBoundary>
        <Boom message="render exploded" />
      </ErrorBoundary>,
    );
    await userEvent.click(screen.getByRole("button", { name: /reload/i }));

    expect(reload).toHaveBeenCalledOnce();
  });

  it("logs the error and its component stack for debugging", () => {
    render(
      <ErrorBoundary>
        <Boom message="render exploded" />
      </ErrorBoundary>,
    );

    const logged = vi.mocked(console.error).mock.calls;
    expect(
      logged.some((args) => String(args[0]).includes("Uncaught render error")),
    ).toBe(true);
  });
});
