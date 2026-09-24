/**
 * Step 1, "Check this computer": runs the preflight, lists what passed and what needs fixing,
 * offers to open Docker Desktop, and only lets people continue once Docker is ready.
 *
 * Why it exists: Nearly every failed install starts here (Docker missing, not running, a port
 * taken), so this step turns the preflight report into plain instructions, re-checks on demand,
 * and watches for Docker to come up after "Open Docker Desktop" so nobody has to guess when to
 * click Re-check.
 */

import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { openDockerDesktop, preflight, type Platform, type PreflightReport } from "../bridge";
import { buildRows, checkNote, type CheckRow, type CheckState } from "../checks";
import { httpsUrl } from "../format";
import { DOCKER_DESKTOP_URL, WORDS, WSL_URL } from "../platform";
import {
  Button,
  CheckIcon,
  CrossIcon,
  DashIcon,
  ExternalLink,
  InfoIcon,
  Spinner,
  StatusMessage,
  WarnIcon,
  type Message,
} from "./ui";

/** How long to keep re-checking after "Open Docker Desktop", and how often. */
const DOCKER_WATCH_MS = 3 * 60 * 1000;
const DOCKER_POLL_MS = 5000;

type DockerButton = "idle" | "opening" | "waiting" | "manual";

const STATE_WORDS: Record<CheckState, string> = {
  ok: "Passed: ",
  bad: "Needs fixing: ",
  warn: "Warning: ",
  info: "Note: ",
  skip: "Not checked yet: ",
  pending: "Checking: ",
};

function StateIcon({ state }: { state: CheckState }) {
  return (
    <span className="check-icon">
      {state === "pending" ? (
        <Spinner />
      ) : state === "ok" ? (
        <CheckIcon />
      ) : state === "bad" ? (
        <CrossIcon />
      ) : state === "warn" ? (
        <WarnIcon />
      ) : state === "info" ? (
        <InfoIcon />
      ) : (
        <DashIcon />
      )}
    </span>
  );
}

function linkLabel(id: string): string {
  if (id === "docker_installed") return "Download Docker Desktop";
  if (id === "compose_v2") return "Get the latest Docker Desktop";
  return "Learn more";
}

function Row({ row, children }: { row: Pick<CheckRow, "state" | "title" | "detail" | "fixes">; children?: ReactNode }) {
  return (
    <li className="check" data-state={row.state}>
      <StateIcon state={row.state} />
      <div className="check-body">
        <p className="check-title">
          <span className="sr-only">{STATE_WORDS[row.state]}</span>
          {row.title}
        </p>
        {row.detail ? <p className="check-detail">{row.detail}</p> : null}
        {row.fixes.map((fix, index) => {
          const href = httpsUrl(fix.url ?? fix.link?.href);
          return (
            <p className="check-fix" key={`${fix.id}-${index}`}>
              {fix.text}
              {href ? (
                <>
                  {" "}
                  <ExternalLink href={href}>{fix.link?.label || linkLabel(fix.id)}</ExternalLink>
                </>
              ) : null}
            </p>
          );
        })}
        {children}
      </div>
    </li>
  );
}

interface CheckStepProps {
  platform: Platform;
  onContinue: (report: PreflightReport) => void;
}

export function CheckStep({ platform, onContinue }: CheckStepProps) {
  const words = WORDS[platform];
  const [report, setReport] = useState<PreflightReport | null>(null);
  const [pending, setPending] = useState(true);
  const [checking, setChecking] = useState(false);
  const [failed, setFailed] = useState(false);
  const [docker, setDocker] = useState<DockerButton>("idle");
  const inFlight = useRef(false);
  const alive = useRef(true);

  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);

  /** `quiet` keeps the current rows on screen (background re-checks while Docker starts). */
  const runCheck = useCallback(async (quiet: boolean): Promise<PreflightReport | null> => {
    if (inFlight.current) return null;
    inFlight.current = true;
    setChecking(true);
    if (!quiet) {
      setPending(true);
      setReport(null);
      setFailed(false);
    }
    try {
      const result = await preflight();
      if (!alive.current) return null;
      setReport(result);
      setFailed(false);
      if (result.docker_running) setDocker("idle");
      return result;
    } catch {
      if (alive.current && !quiet) setFailed(true);
      return null;
    } finally {
      inFlight.current = false;
      if (alive.current) {
        setChecking(false);
        setPending(false);
      }
    }
  }, []);

  useEffect(() => {
    void runCheck(false);
  }, [runCheck]);

  // After "Open Docker Desktop": re-check every few seconds until Docker answers (or 3 minutes).
  useEffect(() => {
    if (docker !== "waiting") return undefined;
    let stopped = false;
    let timer: ReturnType<typeof setTimeout>;
    const until = Date.now() + DOCKER_WATCH_MS;
    const tick = async () => {
      if (stopped) return;
      const result = await runCheck(true);
      if (stopped) return;
      if (result?.docker_running || Date.now() > until) {
        setDocker("idle");
        return;
      }
      timer = setTimeout(tick, DOCKER_POLL_MS);
    };
    timer = setTimeout(tick, DOCKER_POLL_MS);
    return () => {
      stopped = true;
      clearTimeout(timer);
    };
  }, [docker, runCheck]);

  const openDocker = async () => {
    setDocker("opening");
    let opened = false;
    try {
      opened = await openDockerDesktop();
    } catch {
      opened = false;
    }
    if (alive.current) setDocker(opened ? "waiting" : "manual");
  };

  const rows = report ? buildRows(report, words) : [];
  const note: Message | null = failed
    ? { tone: "bad", text: "The check didn’t finish. Click Re-check to try again." }
    : report && !pending
      ? checkNote(report, rows)
      : null;
  const ready = !!report?.ready && !pending;

  return (
    <>
      <p className="lede">
        Crawler AI runs inside <ExternalLink href={DOCKER_DESKTOP_URL}>{words.docker}</ExternalLink> (free for
        personal use). This checks that it’s installed and running, and that there’s room to work.
      </p>
      {platform === "windows" ? (
        <p className="lede">
          On Windows, Docker Desktop needs WSL 2 (Windows Subsystem for Linux). Its installer turns WSL 2 on for you;
          restart when it asks, then open Docker Desktop once. <ExternalLink href={WSL_URL}>About WSL 2</ExternalLink>
        </p>
      ) : null}

      <ul className="checks" aria-live="polite" aria-busy={pending}>
        {pending ? (
          <Row
            row={{
              state: "pending",
              title: `Checking your ${words.computer}…`,
              detail: "Asking Docker a few questions. This can take up to 30 seconds while Docker starts.",
              fixes: [],
            }}
          />
        ) : (
          rows.map((row) => (
            <Row key={row.id} row={row}>
              {row.openDocker ? (
                <>
                  {docker === "manual" ? (
                    <p className="check-fix">
                      Crawler AI couldn’t open it for you. {words.openDockerYourself}, then click Re-check.
                    </p>
                  ) : null}
                  <Button
                    variant="secondary"
                    small
                    busy={docker === "opening"}
                    busyLabel="Opening…"
                    disabled={docker === "waiting"}
                    onClick={openDocker}
                  >
                    {docker === "waiting" ? "Waiting for Docker…" : "Open Docker Desktop"}
                  </Button>
                </>
              ) : null}
            </Row>
          ))
        )}
      </ul>

      <StatusMessage message={note} className="note" />

      <div className="actions">
        <Button variant="primary" disabled={!ready} onClick={() => report && onContinue(report)}>
          {ready && report?.env_keys_set ? "Continue to Install" : "Continue"}
        </Button>
        <Button variant="ghost" disabled={checking} onClick={() => void runCheck(false)}>
          Re-check
        </Button>
      </div>
    </>
  );
}
