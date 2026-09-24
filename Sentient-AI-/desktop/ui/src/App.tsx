/**
 * Root of the setup window: asks the app who it is (`app_info`) and shows either the four-step
 * setup (first run) or the running/status screen (already installed).
 *
 * Why it exists: The same window serves both jobs. `installed` decides where it opens, the
 * platform decides the wording (Docker Desktop for Mac vs Windows, the WSL 2 note), and the
 * preview banner makes it obvious when the UI runs in a plain browser against the fake bridge.
 */

import { useEffect, useState } from "react";
import { appInfo, isPreview, type AppInfo, type Platform } from "./bridge";
import { RunningScreen } from "./components/RunningScreen";
import { Setup } from "./components/Setup";
import { Brand, Spinner } from "./components/ui";
import { guessPlatform, WORDS } from "./platform";

type Screen = "loading" | "setup" | "running";

export default function App() {
  const [platform, setPlatform] = useState<Platform>(guessPlatform);
  const [info, setInfo] = useState<AppInfo | null>(null);
  const [screen, setScreen] = useState<Screen>("loading");

  useEffect(() => {
    let alive = true;
    appInfo()
      .then((result) => {
        if (!alive) return;
        setInfo(result);
        if (result.platform === "mac" || result.platform === "windows") setPlatform(result.platform);
        setScreen(result.installed ? "running" : "setup");
      })
      .catch(() => {
        // Without app info, setup is the safe place to start: every step checks for itself.
        if (alive) setScreen("setup");
      });
    return () => {
      alive = false;
    };
  }, []);

  return (
    <main className="wrap">
      <header>
        <Brand badge={screen === "running" ? "App" : "Setup"} />
      </header>

      {isPreview() ? (
        <div className="banner banner-info" role="note">
          <strong>Preview</strong>
          <span>This is the setup window in a browser, not the Crawler AI app. Every button talks to a stand-in.</span>
        </div>
      ) : null}

      {screen === "loading" ? (
        <p className="loading" role="status">
          <Spinner />
          Loading…
        </p>
      ) : null}

      {screen === "setup" ? (
        <Setup
          platform={platform}
          onFinished={() => {
            setInfo((current) => (current ? { ...current, installed: true } : current));
            setScreen("running");
          }}
        />
      ) : null}

      {screen === "running" ? (
        <RunningScreen info={info} words={WORDS[platform]} onSetupAgain={() => setScreen("setup")} />
      ) : null}
    </main>
  );
}
