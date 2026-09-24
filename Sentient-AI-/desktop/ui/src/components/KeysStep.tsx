/**
 * Step 2, "Security keys": generate SECRET_KEY / ENCRYPTION_KEY (default) or paste your own,
 * with format checks, and a confirmation before replacing keys that already exist.
 *
 * Why it exists: The backend refuses to start without these two keys, and replacing
 * ENCRYPTION_KEY makes everything encrypted with the old one unreadable. This step makes the
 * safe path one click, explains the rules for custom keys before anything is saved, and asks
 * before overwriting. Keys go to Rust once and are cleared from the form after saving.
 */

import { useEffect, useRef, useState, type RefObject } from "react";
import { saveKeys, type KeyMode, type SaveKeysRequest, type SaveKeysResult } from "../bridge";
import { encryptionKeyProblem, secretKeyProblem } from "../keys";
import type { PlatformWords } from "../platform";
import { ConfirmDialog } from "./ConfirmDialog";
import { Button, StatusMessage, type Message } from "./ui";

const WRITE_FAILED = "Couldn’t save the keys. Try again; if it keeps failing, restart Crawler AI.";

function reasonText(reason: string | null | undefined): string {
  switch (reason) {
    case "invalid":
      return "Those keys weren’t accepted. Check the format rules under each field.";
    case "busy":
    case "install_running":
    case "build_running":
      return "An install is running. Wait for it to finish before changing keys.";
    default:
      return WRITE_FAILED;
  }
}

interface KeyFieldProps {
  id: string;
  label: string;
  hint: string;
  value: string;
  error: string;
  disabled: boolean;
  inputRef: RefObject<HTMLInputElement>;
  onChange: (value: string) => void;
}

function KeyField({ id, label, hint, value, error, disabled, inputRef, onChange }: KeyFieldProps) {
  const [shown, setShown] = useState(false);
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <div className="input-row">
        <input
          ref={inputRef}
          id={id}
          type={shown ? "text" : "password"}
          value={value}
          disabled={disabled}
          autoComplete="off"
          autoCapitalize="off"
          autoCorrect="off"
          spellCheck={false}
          aria-describedby={`${id}-hint${error ? ` ${id}-error` : ""}`}
          aria-invalid={error ? true : false}
          onChange={(event) => onChange(event.target.value)}
        />
        <Button
          variant="secondary"
          small
          aria-controls={id}
          aria-pressed={shown}
          aria-label={`${shown ? "Hide" : "Show"} ${label}`}
          disabled={disabled}
          onClick={() => setShown((s) => !s)}
        >
          {shown ? "Hide" : "Show"}
        </Button>
      </div>
      <p className="hint" id={`${id}-hint`}>
        {hint}
      </p>
      {error ? (
        <p className="field-error" id={`${id}-error`}>
          {error}
        </p>
      ) : null}
    </div>
  );
}

interface KeysStepProps {
  words: PlatformWords;
  onDone: (summary: string) => void;
}

export function KeysStep({ words, onDone }: KeysStepProps) {
  const [mode, setMode] = useState<KeyMode>("generate");
  const [secret, setSecret] = useState("");
  const [encryption, setEncryption] = useState("");
  const [errors, setErrors] = useState({ secret: "", encryption: "" });
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<Message | null>(null);
  const [outcome, setOutcome] = useState<"saved" | "kept" | null>(null);
  const [confirming, setConfirming] = useState(false);
  const secretRef = useRef<HTMLInputElement>(null);
  const encryptionRef = useRef<HTMLInputElement>(null);
  const nextRef = useRef<HTMLButtonElement>(null);
  const modeChanged = useRef(false);

  useEffect(() => {
    if (modeChanged.current && mode === "custom") secretRef.current?.focus();
  }, [mode]);

  useEffect(() => {
    if (outcome) nextRef.current?.focus();
  }, [outcome]);

  async function save(overwrite: boolean) {
    setMessage(null);
    const request: SaveKeysRequest = { mode, overwrite };
    if (mode === "custom") {
      const secretError = secretKeyProblem(secret);
      const encryptionError = encryptionKeyProblem(encryption);
      setErrors({ secret: secretError, encryption: encryptionError });
      if (secretError || encryptionError) {
        (secretError ? secretRef : encryptionRef).current?.focus();
        return;
      }
      request.secret_key = secret;
      request.encryption_key = encryption;
    }

    setBusy(true);
    let result: SaveKeysResult;
    try {
      result = await saveKeys(request);
    } catch {
      setMessage({ tone: "bad", text: WRITE_FAILED });
      return;
    } finally {
      setBusy(false);
    }

    if (result?.ok) {
      setSecret("");
      setEncryption("");
      setOutcome("saved");
      setMessage({ tone: "ok", text: "Keys saved on this computer ✓" });
      return;
    }
    if (result?.reason === "exists" && !overwrite) {
      setConfirming(true);
      return;
    }
    if (result?.reason === "invalid" && result.errors && mode === "custom") {
      // Rust's own validation disagreed with ours: show its words under the fields.
      setErrors({ secret: result.errors.secret_key ?? "", encryption: result.errors.encryption_key ?? "" });
    }
    setMessage({ tone: "bad", text: reasonText(result?.reason) });
  }

  const locked = busy || outcome !== null;

  return (
    <>
      <p className="lede">
        Two secret keys protect your install: one signs sign-ins, the other encrypts the credentials you save. They’re
        stored on this {words.computer} in <code>{words.dataDir}</code>, readable only by your user account.
      </p>

      <fieldset className="choice" disabled={locked}>
        <legend className="sr-only">How to create the keys</legend>
        <label className="option">
          <input
            type="radio"
            name="keymode"
            value="generate"
            checked={mode === "generate"}
            onChange={() => {
              modeChanged.current = true;
              setMode("generate");
            }}
          />
          <span>
            <strong>Generate for me</strong>
            <small>Recommended. Two strong random keys, created and saved on this {words.computer}.</small>
          </span>
        </label>
        <label className="option">
          <input
            type="radio"
            name="keymode"
            value="custom"
            checked={mode === "custom"}
            onChange={() => {
              modeChanged.current = true;
              setMode("custom");
            }}
          />
          <span>
            <strong>Use my own</strong>
            <small>Paste keys you already have, for example to restore an older install.</small>
          </span>
        </label>
      </fieldset>

      {mode === "custom" ? (
        <div className="fields">
          <KeyField
            id="k-secret"
            label="SECRET_KEY"
            hint="At least 32 characters with no spaces, quotes, backslashes, $ or #."
            value={secret}
            error={errors.secret}
            disabled={locked}
            inputRef={secretRef}
            onChange={(value) => {
              setSecret(value);
              if (errors.secret) setErrors((e) => ({ ...e, secret: "" }));
            }}
          />
          <KeyField
            id="k-enc"
            label="ENCRYPTION_KEY"
            hint="Base64 of exactly 32 bytes: 44 characters ending in =. Standard or URL-safe alphabet."
            value={encryption}
            error={errors.encryption}
            disabled={locked}
            inputRef={encryptionRef}
            onChange={(value) => {
              setEncryption(value);
              if (errors.encryption) setErrors((e) => ({ ...e, encryption: "" }));
            }}
          />
        </div>
      ) : null}

      <p className="fine">
        The keys never leave this {words.computer}. Crawler AI doesn’t show them again and never writes them to its log.
      </p>
      <StatusMessage message={message} />

      <div className="actions">
        {outcome ? (
          <Button
            ref={nextRef}
            onClick={() =>
              onDone(outcome === "saved" ? "Keys saved on this computer." : "Using the keys already on this computer.")
            }
          >
            Next
          </Button>
        ) : (
          <Button busy={busy} busyLabel="Saving…" onClick={() => void save(false)}>
            Save keys
          </Button>
        )}
      </div>

      <ConfirmDialog
        open={confirming}
        title="Replace the keys?"
        confirmLabel="Replace keys"
        onConfirm={() => {
          setConfirming(false);
          void save(true);
        }}
        onCancel={() => {
          setConfirming(false);
          setSecret("");
          setEncryption("");
          setOutcome("kept");
          setMessage({ tone: "info", text: "Kept your existing keys. Nothing was changed." });
        }}
      >
        <p>Keys are already saved on this {words.computer}. Replace them? A backup of the old file is kept.</p>
        <p className="warn-text">
          Anything Crawler AI already encrypted with the old key, such as saved AI keys or connector sign-ins, will need
          to be entered again.
        </p>
      </ConfirmDialog>
    </>
  );
}
