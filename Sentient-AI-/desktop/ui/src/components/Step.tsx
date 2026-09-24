/**
 * One numbered card of the four-step stepper: dot on the rail, title, one-line summary once
 * done, and the step's content while it is the active one.
 *
 * Why it exists: The four steps share the same states (locked, active, done), the same markup as
 * installer/page.html and the same focus rule: when a step becomes active, its heading takes
 * focus and scrolls into view, so keyboard and screen-reader users land on the new step.
 */

import { useEffect, useRef, type ReactNode } from "react";
import { prefersReducedMotion } from "../hooks";
import { CheckIcon } from "./ui";

export type StepState = "locked" | "active" | "done";

interface StepProps {
  n: number;
  title: string;
  state: StepState;
  /** One line shown under the title once the step is done. */
  summary?: string;
  /** Something next to the title, e.g. "Replace keys". */
  action?: ReactNode;
  children?: ReactNode;
}

export function Step({ n, title, state, summary, action, children }: StepProps) {
  const itemRef = useRef<HTMLLIElement>(null);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const previous = useRef<StepState | null>(null);
  const titleId = `step${n}-title`;

  useEffect(() => {
    // Only on a change to active: the first render shouldn't steal focus or scroll.
    if (state === "active" && previous.current !== null && previous.current !== "active") {
      headingRef.current?.focus({ preventScroll: true });
      itemRef.current?.scrollIntoView?.({
        behavior: prefersReducedMotion() ? "auto" : "smooth",
        block: "start",
      });
    }
    previous.current = state;
  }, [state]);

  return (
    <li
      ref={itemRef}
      className="step"
      data-state={state}
      aria-current={state === "active" ? "step" : undefined}
    >
      <div className="rail" aria-hidden="true">
        <span className="dot">
          <span className="num">{n}</span>
          <CheckIcon />
        </span>
      </div>
      <section className="card" aria-labelledby={titleId}>
        <div className="card-head">
          <div>
            <h2 id={titleId} ref={headingRef} tabIndex={-1}>
              {title}
            </h2>
            {state === "done" && summary ? <p className="summary">{summary}</p> : null}
          </div>
          {action}
        </div>
        {state === "active" ? <div className="card-body">{children}</div> : null}
      </section>
    </li>
  );
}
