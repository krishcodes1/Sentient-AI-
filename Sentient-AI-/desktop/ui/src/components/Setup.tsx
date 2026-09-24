/**
 * The four-step first-run setup: Check this computer → Security keys → Install & start → Open.
 *
 * Why it exists: It owns which step is active, the one-line summaries of finished steps, and the
 * rules for moving between them: step 1 gates on Docker being ready, keys already set skip
 * step 2, "Replace keys" reopens step 2 until the install starts, and an install already running
 * in the app (the window was closed and reopened) resumes straight into step 3.
 */

import { useEffect, useState } from "react";
import { installStatus, type PhaseEvent, type Platform, type PreflightReport } from "../bridge";
import { classifyPhase } from "../phase";
import { WORDS } from "../platform";
import { CheckStep } from "./CheckStep";
import { InstallStep } from "./InstallStep";
import { KeysStep } from "./KeysStep";
import { OpenStep } from "./OpenStep";
import { Step, type StepState } from "./Step";

type StepNo = 1 | 2 | 3 | 4;

interface SetupProps {
  platform: Platform;
  /** Crawler AI was opened: switch to the status screen. */
  onFinished: () => void;
}

export function Setup({ platform, onFinished }: SetupProps) {
  const words = WORDS[platform];
  const [active, setActive] = useState<StepNo>(1);
  const [summaries, setSummaries] = useState<Partial<Record<StepNo, string>>>({});
  const [installStarted, setInstallStarted] = useState(false);
  const [resume, setResume] = useState<PhaseEvent | null>(null);

  // Pick up an install that is already running (or failed) in the app process.
  useEffect(() => {
    let alive = true;
    installStatus()
      .then((status) => {
        if (!alive) return;
        const kind = classifyPhase(status);
        if (kind !== "working" && kind !== "failed") return;
        setResume(status);
        setInstallStarted(true);
        setSummaries({ 1: "Docker Desktop is running.", 2: "Keys saved on this computer." });
        setActive((current) => (current === 1 ? 3 : current));
      })
      .catch(() => {
        /* no status yet: start from step 1 */
      });
    return () => {
      alive = false;
    };
  }, []);

  const stateOf = (n: StepNo): StepState => (n < active ? "done" : n === active ? "active" : "locked");

  const continueFromCheck = (report: PreflightReport) => {
    const docker = `Docker Desktop is running${report.compose_version ? ` (Compose ${report.compose_version})` : ""}.`;
    if (report.env_keys_set) {
      setSummaries((s) => ({ ...s, 1: docker, 2: "Keys already set on this computer." }));
      setActive(3);
    } else {
      setSummaries((s) => ({ ...s, 1: docker }));
      setActive(2);
    }
  };

  const replaceKeys =
    active === 3 && !installStarted ? (
      <button type="button" className="btn-link" onClick={() => setActive(2)}>
        Replace keys
      </button>
    ) : null;

  return (
    <>
      <h1>{words.headline}</h1>
      <p className="sub">Four steps, all buttons. The first install takes 10–20 minutes, mostly downloading.</p>

      <ol className="stepper">
        <Step n={1} title="Check this computer" state={stateOf(1)} summary={summaries[1]}>
          <CheckStep platform={platform} onContinue={continueFromCheck} />
        </Step>
        <Step n={2} title="Security keys" state={stateOf(2)} summary={summaries[2]} action={replaceKeys}>
          <KeysStep
            words={words}
            onDone={(summary) => {
              setSummaries((s) => ({ ...s, 2: summary }));
              setActive(3);
            }}
          />
        </Step>
        <Step n={3} title="Install & start" state={stateOf(3)} summary={summaries[3]}>
          <InstallStep
            resume={resume}
            onStarted={() => setInstallStarted(true)}
            onNext={() => {
              setSummaries((s) => ({ ...s, 3: "Crawler AI is installed and running." }));
              setActive(4);
            }}
          />
        </Step>
        <Step n={4} title="Open Crawler AI" state={stateOf(4)}>
          <OpenStep words={words} onOpened={onFinished} />
        </Step>
      </ol>
    </>
  );
}
