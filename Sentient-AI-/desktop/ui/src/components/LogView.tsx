/**
 * Scrolling, monospaced view of Docker / install output that sticks to the bottom while new
 * lines arrive, unless the reader has scrolled up to look at something.
 *
 * Why it exists: Both the install step and the running screen show `stack://log` output; both
 * need the same "follow the tail, but don't yank me back while I'm reading" behaviour.
 */

import { useLayoutEffect, useRef } from "react";

interface LogViewProps {
  lines: string[];
  /** Accessible name, e.g. "Install output". */
  label: string;
}

const STICK_PX = 48;

export function LogView({ lines, label }: LogViewProps) {
  const ref = useRef<HTMLPreElement>(null);
  const stick = useRef(true);

  useLayoutEffect(() => {
    const node = ref.current;
    if (node && stick.current) node.scrollTop = node.scrollHeight;
  }, [lines]);

  return (
    <pre
      ref={ref}
      className="log"
      tabIndex={0}
      aria-label={label}
      onScroll={(event) => {
        const node = event.currentTarget;
        stick.current = node.scrollHeight - node.scrollTop - node.clientHeight < STICK_PX;
      }}
    >
      {lines.length ? `${lines.join("\n")}\n` : ""}
    </pre>
  );
}
