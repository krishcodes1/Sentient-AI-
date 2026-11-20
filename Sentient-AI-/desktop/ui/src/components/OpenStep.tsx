/**
 * Step 4, "Open Crawler AI": one button that opens the Crawler AI window, where the in-app setup
 * wizard (owner account, AI key, Telegram, permissions) takes over.
 *
 * Why it exists: It is the hand-off from installing to using. The Crawler AI window is a
 * separate webview with no access to app commands; this step asks Rust to open it and then
 * moves the setup window to the status screen.
 */

import { useEffect, useRef, useState } from "react";
import { openCrawler } from "../bridge";
import { errorText } from "../format";
import { LOCAL_URL, type PlatformWords } from "../platform";
import { Button, StatusMessage, type Message } from "./ui";

interface OpenStepProps {
  words: PlatformWords;
  onOpened: () => void;
  /** Open Crawler AI as soon as this step shows (the native Mac setup); the button stays as the fallback. */
  auto?: boolean;
}

export function OpenStep({ words, onOpened, auto = false }: OpenStepProps) {
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<Message | null>(null);
  const opened = useRef(false);

  const open = async () => {
    setBusy(true);
    setMessage(null);
    try {
      await openCrawler();
    } catch (error) {
      setBusy(false);
      setMessage({
        tone: "bad",
        text: `Couldn’t open the Crawler AI window (${errorText(error)}). Try again, or open ${LOCAL_URL} in your browser.`,
      });
      return;
    }
    setBusy(false);
    onOpened();
  };

  useEffect(() => {
    if (!auto || opened.current) return;
    opened.current = true;
    void open();
    // Runs once, when the step first shows.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [auto]);

  return (
    <>
      <p className="lede">Crawler AI is running on this {words.computer}.</p>
      <div className="actions">
        <Button busy={busy} busyLabel="Opening…" onClick={() => void open()}>
          Open Crawler AI
        </Button>
      </div>
      <StatusMessage message={message} />
      <p className="note">The setup wizard in Crawler AI takes it from here: owner account, AI key, Telegram, permissions.</p>
      <p className="fine">
        {words.closeNote} The {words.tray} opens, starts or stops it any time.
      </p>
    </>
  );
}
