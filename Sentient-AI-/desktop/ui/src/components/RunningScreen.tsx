/**
 * The status screen shown once Crawler AI is installed: Open Crawler AI, Start, Stop, Show logs
 * and Check for updates, plus the version and a way back into setup.
 *
 * Why it exists: After the first run the setup window becomes the app's control panel (the same
 * actions as the tray / menu-bar icon, with room to show output and update details). Status comes
 * from `stack://phase` events and `install_status()`; output from `stack://log`. The tray's
 * "Show logs" (`tray://show-logs`) opens the logs panel.
 */

import { useEffect, useState } from "react";
import {
  checkUpdates,
  installStatus,
  onStackLog,
  onShowLogs,
  onStackPhase,
  openCrawler,
  stackStart,
  stackStop,
  type AppInfo,
  type PhaseEvent,
  type UpdateInfo,
} from "../bridge";
import { errorText, httpsUrl } from "../format";
import { useBridgeEvent, useLogBuffer } from "../hooks";
import { classifyPhase, phaseLabel } from "../phase";
import type { PlatformWords } from "../platform";
import { LogView } from "./LogView";
import { Button, ExternalLink, StatusMessage, type Message } from "./ui";

type Action = "open" | "start" | "stop" | "updates";

type UpdateState = { kind: "result"; info: UpdateInfo } | { kind: "error" } | null;

interface RunningScreenProps {
  info: AppInfo | null;
  words: PlatformWords;
  onSetupAgain: () => void;
}

function statusPill(status: PhaseEvent | null): { tone: string; text: string } | null {
  switch (classifyPhase(status)) {
    case "healthy":
      return { tone: "ok", text: "Running" };
    case "stopped":
      return { tone: "neutral", text: "Stopped" };
    case "failed":
      return { tone: "bad", text: "Needs attention" };
    case "working":
      return { tone: "info", text: phaseLabel(status) };
    default:
      return null;
  }
}

export function RunningScreen({ info, words, onSetupAgain }: RunningScreenProps) {
  const log = useLogBuffer();
  const [status, setStatus] = useState<PhaseEvent | null>(null);
  const [busy, setBusy] = useState<Action | null>(null);
  const [message, setMessage] = useState<Message | null>(null);
  const [logsOpen, setLogsOpen] = useState(false);
  const [update, setUpdate] = useState<UpdateState>(null);

  useBridgeEvent(onStackLog, log.append);
  useBridgeEvent(onStackPhase, setStatus);
  useBridgeEvent(onShowLogs, () => setLogsOpen(true));

  useEffect(() => {
    let alive = true;
    installStatus()
      .then((current) => {
        // An event that already arrived is newer than this answer.
        if (alive) setStatus((existing) => existing ?? current);
      })
      .catch(() => {
        /* status unknown until the next event */
      });
    return () => {
      alive = false;
    };
  }, []);

  async function perform(action: Action, work: () => Promise<void>) {
    setBusy(action);
    try {
      await work();
    } finally {
      setBusy(null);
    }
  }

  const open = () =>
    perform("open", async () => {
      setMessage(null);
      try {
        await openCrawler();
        setMessage({ tone: "ok", text: "Opened Crawler AI." });
      } catch (error) {
        setMessage({ tone: "bad", text: `Couldn’t open Crawler AI: ${errorText(error)}` });
      }
    });

  const start = () =>
    perform("start", async () => {
      setMessage(null);
      try {
        await stackStart();
        setMessage({ tone: "ok", text: "Crawler AI is starting. It’s ready in a few seconds." });
        const current = await installStatus().catch(() => null);
        if (current && classifyPhase(current) !== "idle") setStatus(current);
      } catch (error) {
        setMessage({ tone: "bad", text: `Couldn’t start Crawler AI: ${errorText(error)}` });
      }
    });

  const stop = () =>
    perform("stop", async () => {
      setMessage(null);
      try {
        await stackStop();
        setStatus({ phase: "stopped", elapsed_s: 0 });
        setMessage({ tone: "ok", text: "Crawler AI is stopped. Your data is kept; Start brings it back." });
      } catch (error) {
        setMessage({ tone: "bad", text: `Couldn’t stop Crawler AI: ${errorText(error)}` });
      }
    });

  const check = () =>
    perform("updates", async () => {
      try {
        setUpdate({ kind: "result", info: await checkUpdates() });
      } catch {
        setUpdate({ kind: "error" });
      }
    });

  const pill = statusPill(status);
  const stackBusy = busy === "start" || busy === "stop";
  const statusError = classifyPhase(status) === "failed" && status?.error ? status.error : null;

  return (
    <>
      <h1>Crawler AI</h1>
      <p className="sub">
        Runs in {words.docker} on this {words.computer}. Closing this window keeps it running; the {words.tray} has the
        same controls.
      </p>

      <section className="card panel" aria-labelledby="run-title">
        <div className="card-head">
          <h2 id="run-title">Crawler AI is installed</h2>
          {pill ? (
            <span className="pill" data-tone={pill.tone}>
              <span className="sr-only">Status: </span>
              {pill.text}
            </span>
          ) : null}
        </div>
        {statusError ? <p className="note" data-tone="bad">{statusError}</p> : null}
        <div className="actions">
          <Button busy={busy === "open"} busyLabel="Opening…" onClick={() => void open()}>
            Open Crawler AI
          </Button>
          <Button
            variant="secondary"
            busy={busy === "start"}
            busyLabel="Starting…"
            disabled={stackBusy}
            onClick={() => void start()}
          >
            Start
          </Button>
          <Button
            variant="secondary"
            busy={busy === "stop"}
            busyLabel="Stopping…"
            disabled={stackBusy}
            onClick={() => void stop()}
          >
            Stop
          </Button>
        </div>
        <StatusMessage message={message} />
      </section>

      <section className="card panel" aria-label="Logs and updates">
        <div className="actions tools">
          <Button
            variant="ghost"
            aria-expanded={logsOpen}
            aria-controls="stack-logs"
            onClick={() => setLogsOpen((open) => !open)}
          >
            {logsOpen ? "Hide logs" : "Show logs"}
          </Button>
          <Button variant="ghost" busy={busy === "updates"} busyLabel="Checking…" onClick={() => void check()}>
            Check for updates
          </Button>
        </div>

        {update ? (
          <p className="note" role="status" data-tone={update.kind === "error" ? "bad" : update.info.newer ? "ok" : "info"}>
            {update.kind === "error" ? (
              "Couldn’t check for updates. Check your internet connection, then try again."
            ) : update.info.newer ? (
              <>
                Crawler AI {update.info.latest ?? "(a newer version)"} is available
                {info?.version ? ` (you have ${info.version})` : ""}.
                {httpsUrl(update.info.url) ? (
                  <>
                    {" "}
                    <ExternalLink href={update.info.url}>Download the update</ExternalLink>
                  </>
                ) : null}
              </>
            ) : (
              `You’re on the latest version${info?.version ? ` (${info.version})` : ""}.`
            )}
          </p>
        ) : null}

        <div id="stack-logs" hidden={!logsOpen}>
          {log.lines.length ? (
            <LogView lines={log.lines} label="Crawler AI output" />
          ) : (
            <p className="fine">No output yet. Start or stop Crawler AI to see what it prints here.</p>
          )}
        </div>
      </section>

      <p className="fine footer">
        {info?.version ? `Version ${info.version} · ` : ""}
        {words.osName}
        {" · "}
        <button type="button" className="btn-link" onClick={onSetupAgain}>
          Run setup again
        </button>
      </p>
    </>
  );
}
