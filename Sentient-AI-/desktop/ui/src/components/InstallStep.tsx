/**
 * Step 3, "Install & start": starts the install, streams Docker's output live, shows the phase
 * and elapsed time, and ends with "Crawler AI is running" or a failure with the last lines of
 * output and a Retry button.
 *
 * Why it exists: The first install takes 5–20 minutes. People need to see that it's moving
 * (log + phase + clock), and when it fails they need the reason in front of them and a way to
 * try again without starting the whole setup over. Output arrives on `stack://log`, phases on
 * `stack://phase`; `install_status()` is polled as a safety net in case an event was missed
 * (and to pick up an install that was already running when the window opened).
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { installStatus, onStackLog, onStackPhase, startInstall, type PhaseEvent } from "../bridge";
import { formatElapsed } from "../format";
import { useBridgeEvent, useLogBuffer } from "../hooks";
import { classifyPhase, phaseLabel } from "../phase";
import { LogView } from "./LogView";
import { Button, Spinner, StatusMessage, type Message } from "./ui";

const POLL_MS = 4000;
const TAIL_LINES = 30;

interface InstallStepProps {
  /** An install already under way (or failed) when the window opened. */
  resume: PhaseEvent | null;
  onStarted: () => void;
  onNext: () => void;
}

interface Clock {
  /** Elapsed seconds Rust reported with the last phase… */
  base: number;
  /** …the moment that report arrived… */
  at: number;
  /** …and now, advanced by the ticker. */
  now: number;
}

interface Run {
  phase: PhaseEvent | null;
  clock: Clock;
}

function clockAt(elapsed: number | undefined): Clock {
  const now = Date.now();
  return { base: Number(elapsed) || 0, at: now, now };
}

export function InstallStep({ resume, onStarted, onNext }: InstallStepProps) {
  const log = useLogBuffer();
  const [started, setStarted] = useState(resume !== null);
  // Phase and clock change together, so they live in one state value.
  const [run, setRun] = useState<Run>(() => ({ phase: resume, clock: clockAt(resume?.elapsed_s) }));
  const { phase, clock } = run;
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<Message | null>(null);
  const listening = useRef(resume !== null);
  const nextRef = useRef<HTMLButtonElement>(null);
  const kind = started ? classifyPhase(phase) : "idle";

  const applyPhase = useCallback((event: PhaseEvent) => {
    setRun({ phase: event, clock: clockAt(event.elapsed_s) });
  }, []);

  useBridgeEvent(onStackLog, log.append);
  useBridgeEvent(onStackPhase, (event: PhaseEvent) => {
    // Phase changes that aren't ours (e.g. Start from the tray before this install) are ignored.
    if (listening.current) applyPhase(event);
  });

  // Tick the elapsed clock between phase events.
  useEffect(() => {
    if (kind !== "working") return undefined;
    const id = setInterval(() => setRun((r) => ({ ...r, clock: { ...r.clock, now: Date.now() } })), 1000);
    return () => clearInterval(id);
  }, [kind]);

  // Safety net for missed events.
  useEffect(() => {
    if (kind !== "working") return undefined;
    let stopped = false;
    const id = setInterval(() => {
      installStatus()
        .then((status) => {
          if (!stopped && status && classifyPhase(status) !== "idle") applyPhase(status);
        })
        .catch(() => {
          /* the next event or poll will catch up */
        });
    }, POLL_MS);
    return () => {
      stopped = true;
      clearInterval(id);
    };
  }, [kind, applyPhase]);

  useEffect(() => {
    if (kind === "healthy") nextRef.current?.focus();
  }, [kind]);

  const start = async () => {
    setMessage(null);
    setBusy(true);
    const wasListening = listening.current;
    listening.current = true;
    let ok = false;
    try {
      ok = !!(await startInstall())?.ok;
    } catch {
      ok = false;
    }
    if (!ok) {
      // Maybe an install is already running (started from elsewhere): follow it instead.
      const status = await installStatus().catch(() => null);
      const statusKind = classifyPhase(status);
      setBusy(false);
      if (status && (statusKind === "working" || statusKind === "healthy")) {
        setStarted(true);
        onStarted();
        applyPhase(status);
        return;
      }
      listening.current = wasListening;
      setMessage({ tone: "bad", text: "The install couldn’t start. Click the button to try again." });
      return;
    }
    setBusy(false);
    setStarted(true);
    onStarted();
    // Keep a phase that already arrived for this run; otherwise show "Preparing…" from 0:00.
    setRun((current) =>
      current.phase && classifyPhase(current.phase) === "working"
        ? current
        : { phase: { phase: "preparing", elapsed_s: 0 }, clock: clockAt(0) },
    );
  };

  const elapsed = clock.base + (kind === "working" ? Math.max(0, (clock.now - clock.at) / 1000) : 0);
  const failedError =
    (typeof phase?.error === "string" && phase.error.trim()) || "Something went wrong. The output above says why.";

  return (
    <>
      <ul className="facts">
        <li>The first install downloads about 3.6&nbsp;GB (database, Python and Node images plus Crawler AI’s dependencies).</li>
        <li>Expect 5–20 minutes depending on your connection. Later starts take seconds.</li>
        <li>You can do something else while it runs.</li>
      </ul>

      {!started ? (
        <div className="actions">
          <Button busy={busy} busyLabel="Starting…" onClick={() => void start()}>
            Install &amp; start Crawler AI
          </Button>
        </div>
      ) : (
        <div className="progress" data-state={kind}>
          <div className="phase">
            {kind === "working" ? <Spinner /> : null}
            <span aria-live="polite">{phaseLabel(phase)}</span>
            <span className="elapsed">
              <span className="sr-only">Elapsed time </span>
              {formatElapsed(elapsed)}
            </span>
          </div>
          <LogView lines={log.lines} label="Install output" />
        </div>
      )}

      {started && kind === "failed" ? (
        <div className="failure" role="alert">
          <p className="failure-title">The install stopped</p>
          <p>{failedError}</p>
          <p className="tail-label">Last {TAIL_LINES} lines of output:</p>
          <pre aria-label="Last lines of output">{log.lines.slice(-TAIL_LINES).join("\n")}</pre>
          <div className="actions">
            <Button busy={busy} busyLabel="Starting…" onClick={() => void start()}>
              Retry
            </Button>
          </div>
        </div>
      ) : null}

      <StatusMessage message={message} />

      {started && kind === "healthy" ? (
        <div className="actions">
          <Button ref={nextRef} onClick={onNext}>
            Next
          </Button>
        </div>
      ) : null}
    </>
  );
}
