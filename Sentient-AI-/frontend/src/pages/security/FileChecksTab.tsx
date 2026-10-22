/**
 * FileChecksTab: Security ▸ "File checks". Every signed-in person sees the files Crawler has looked
 * up in VirusTotal for them (sent in web chat, Telegram or Slack, email attachments, or picked
 * here), each with what VirusTotal said, and can check a file from this device, send a file
 * VirusTotal does not know (behind its own approval card), approve or deny that card, and forget a
 * row. The owner also sees how to add the VirusTotal key while none is set.
 *
 * Why it exists: a VirusTotal lookup is the owner's key and quota at work, and an upload hands a
 * file to a third party that shares it with security companies, so people need one place that
 * shows what was checked, what was found and why something was not checked. Rules kept here:
 * "Check a file…" fingerprints the file in this browser (pages/security/fileHash.ts) and sends only
 * the SHA-256; the file's bytes leave this device only for an upload the person confirmed, and only
 * when the server has no copy of its own. Nothing is ever shown in a success colour and no text
 * says "safe" (pages/security/fileCheckFormat.ts). Every call goes through services/api.ts to
 * Crawler's own backend (the page's CSP allows nothing else).
 */

import { useCallback, useEffect, useId, useRef, useState } from "react";
import { Loader2 } from "lucide-react";
import ConfirmDialog from "@/components/ConfirmDialog";
import { ErrorAlert } from "@/components/FormFeedback";
import { errorText, panelStyle } from "@/components/formStyles";
import {
  FILE_CHECK_POLL_MS,
  displayName,
  isWaiting,
  megabytes,
  rowStatus,
  sourceLabel,
  timeAgo,
  type FileCheckTone,
} from "@/pages/security/fileCheckFormat";
import { HASH_MAX_BYTES, canHash, sha256Hex } from "@/pages/security/fileHash";
import {
  ApiError,
  checkFileHash,
  decideApproval,
  forgetFileCheck,
  listFileChecks,
  requestFileUpload,
} from "@/services/api";
import type { FileCheck, FileChecksResponse, FileChecksStatus } from "@/types";

const rowStyle = { background: "var(--claw-surface)", border: "1px solid var(--claw-border)" };
const smallButtonCls =
  "inline-flex items-center gap-1.5 px-3.5 py-2 rounded-[10px] text-xs font-semibold disabled:opacity-50";
const neutralButtonStyle = {
  minHeight: 36,
  background: "var(--claw-panel)",
  border: "1px solid var(--claw-border)",
  color: "var(--text-primary)",
};
const dangerButtonStyle = {
  minHeight: 36,
  background: "var(--claw-panel)",
  border: "1px solid var(--border-danger)",
  color: "var(--accent-danger)",
};
const primaryButtonStyle = { minHeight: 40, background: "var(--accent-primary)", color: "var(--text-on-accent)" };

// Badge colours per tone. There is no success entry on purpose: no verdict is ever drawn green.
const TONE_STYLES: Record<FileCheckTone, { background: string; border: string; color: string }> = {
  danger: { background: "var(--fill-danger)", border: "1px solid var(--border-danger)", color: "var(--accent-danger)" },
  warning: { background: "var(--fill-warning)", border: "1px solid var(--border-warning)", color: "var(--accent-warning)" },
  neutral: { background: "var(--fill-neutral)", border: "1px solid var(--claw-border)", color: "var(--text-secondary)" },
};

const PICKER_NOTE = "Only the file's fingerprint (SHA-256) is sent. The file stays on this device.";
const NO_HASH_NOTE = "This browser can't fingerprint files on this connection (it needs HTTPS).";
const TOO_LARGE_TO_HASH = "Too large to fingerprint here.";
const OWNER_NO_KEY = "Add a VirusTotal key to check files.";
const MEMBER_NOT_SET_UP = "File checks are not set up on this install.";
const OFF_NOTE = "Checking files with VirusTotal is turned off in Settings → Permissions.";
const PICK_AGAIN = "Pick the file again to send it.";

type Busy = { id: string; action: "approve" | "deny" | "forget" | "pick" };
type Picking = { name: string; phase: "hash" | "lookup" };

/** The sharing warning the confirm dialog carries before an upload card is made (S10 1.1). */
function uploadWarning(name: string): string {
  return (
    `VirusTotal will scan ${name}. VirusTotal shares files it receives with security companies, ` +
    "and its paying users can download them. Never send private documents. Crawler will ask you " +
    "to approve this as a card."
  );
}

/** A refusal in the approved upload's own result ({ok: false, error}), as a sentence; else null. */
function refusalOf(result: Record<string, unknown> | null | undefined): string | null {
  if (!result || result.ok !== false) return null;
  const text = typeof result.error === "string" ? result.error : typeof result.message === "string" ? result.message : "";
  return text.trim() || "The file was not sent to VirusTotal.";
}

/** The line under the heading: off, waiting for a key, or nothing while checks are on. */
function ServiceLine({
  service,
  isOwner,
  onOpenKeys,
}: {
  service: FileChecksStatus;
  isOwner: boolean;
  onOpenKeys?: () => void;
}) {
  const noteStyle = { color: "var(--accent-warning, var(--text-secondary))" };
  if (service.state === "off") {
    return (
      <p role="status" className="text-sm mt-3" style={noteStyle}>
        {OFF_NOTE}
      </p>
    );
  }
  if (service.state !== "blocked") return null;
  if (!isOwner) {
    return (
      <p role="status" className="text-sm mt-3" style={noteStyle}>
        {MEMBER_NOT_SET_UP}
      </p>
    );
  }
  return (
    <div className="flex items-center gap-3 flex-wrap mt-3">
      <p role="status" className="text-sm" style={noteStyle}>
        {OWNER_NO_KEY}
        {!onOpenKeys && " You can add one in Security → Service keys."}
      </p>
      {onOpenKeys && (
        <button type="button" onClick={onOpenKeys} className={smallButtonCls} style={neutralButtonStyle}>
          Open Service keys
        </button>
      )}
    </div>
  );
}

/** "VirusTotal lookups: 37 of 500 in the last 24 hours (yours: 5 of 100)". */
function UsageLine({ service }: { service: FileChecksStatus }) {
  return (
    <p className="text-xs text-right" style={{ color: "var(--text-muted)" }}>
      VirusTotal lookups: {service.lookups_last_24h} of {service.lookups_per_day} in the last 24 hours{" "}
      <span className="whitespace-nowrap">
        (yours: {service.your_lookups_last_24h} of {service.your_lookups_per_day})
      </span>
    </p>
  );
}

/** Placeholder rows while the list loads. */
function SkeletonRows() {
  return (
    <div role="status" className="space-y-2 mt-4">
      <span className="sr-only">Loading file checks…</span>
      {[0, 1, 2].map((n) => (
        <div key={n} aria-hidden className="rounded-[10px] p-3 animate-pulse" style={rowStyle}>
          <div className="h-3.5 w-40 rounded" style={{ background: "var(--claw-border)" }} />
          <div className="h-3 w-64 rounded mt-2" style={{ background: "var(--claw-border)" }} />
        </div>
      ))}
    </div>
  );
}

export default function FileChecksTab({ isOwner, onOpenKeys }: { isOwner: boolean; onOpenKeys?: () => void }) {
  const headingId = useId();
  const [data, setData] = useState<FileChecksResponse | null>(null);
  const [loadError, setLoadError] = useState("");
  const [attempt, setAttempt] = useState(0);
  const [hashOk] = useState(canHash);
  const [picking, setPicking] = useState<Picking | null>(null);
  const [pickError, setPickError] = useState("");
  const [busy, setBusy] = useState<Busy | null>(null);
  const [notes, setNotes] = useState<Record<string, string>>({});
  const [confirmRow, setConfirmRow] = useState<FileCheck | null>(null);
  // Files picked on this page, by fingerprint, so "Send to VirusTotal…" can post the bytes when the
  // server has no copy. Page session only: gone when the tab unmounts, never stored anywhere.
  const [files, setFiles] = useState<ReadonlyMap<string, File>>(() => new Map());
  const inputRef = useRef<HTMLInputElement>(null);
  // The row a "Pick the file again…" press is for; null when the picker checks a new file.
  const pickFor = useRef<FileCheck | null>(null);
  // Each read of the list takes a number; a change made here takes one too, so an older read that
  // lands late (a poll already in flight) cannot put back a row that was just forgotten or changed.
  const seq = useRef(0);
  const alive = useRef(true);

  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);

  // The first read, and each "Try again": a failure replaces the list with the error.
  useEffect(() => {
    const mine = ++seq.current;
    listFileChecks()
      .then((next) => {
        if (!alive.current || mine !== seq.current) return;
        setData(next);
        setLoadError("");
      })
      .catch((err) => {
        if (!alive.current || mine !== seq.current) return;
        setLoadError(errorText(err, "Your file checks could not be loaded."));
      });
  }, [attempt]);

  // A background read (a poll, or after a change): a failure keeps what is shown, and the next poll
  // or action reads again.
  const reload = useCallback(async () => {
    const mine = ++seq.current;
    try {
      const next = await listFileChecks();
      if (!alive.current || mine !== seq.current) return;
      setData(next);
      setLoadError("");
    } catch {
      /* keep the rows on screen */
    }
  }, []);

  // Read the list again every 10 s while a lookup is queued, a card waits or a scan runs; stop when
  // nothing is moving, and on unmount.
  const waiting = data?.checks.some((row) => isWaiting(row.state)) ?? false;
  useEffect(() => {
    if (!waiting) return;
    const timer = window.setInterval(() => void reload(), FILE_CHECK_POLL_MS);
    return () => window.clearInterval(timer);
  }, [waiting, reload]);

  const setNote = (id: string, text: string | null) =>
    setNotes((prev) => {
      if (text === null) {
        if (!(id in prev)) return prev;
        const next = { ...prev };
        delete next[id];
        return next;
      }
      return { ...prev, [id]: text };
    });

  const remember = (sha256: string, file: File) => setFiles((prev) => new Map(prev).set(sha256, file));

  /** Put a row the server just answered at the top (replacing the same file's older row). */
  const putRow = (row: FileCheck) => {
    seq.current += 1;
    setData((prev) =>
      prev && {
        ...prev,
        checks: [row, ...prev.checks.filter((c) => c.id !== row.id && c.sha256 !== row.sha256)],
      },
    );
  };

  const patchRow = (id: string, patch: Partial<FileCheck>) => {
    seq.current += 1;
    setData((prev) => prev && { ...prev, checks: prev.checks.map((c) => (c.id === id ? { ...c, ...patch } : c)) });
  };

  const checkPicked = async (file: File) => {
    setPickError("");
    if (file.size > HASH_MAX_BYTES) {
      setPickError(TOO_LARGE_TO_HASH);
      return;
    }
    const name = displayName(file.name);
    setPicking({ name, phase: "hash" });
    try {
      let sha256: string;
      try {
        sha256 = await sha256Hex(file);
      } catch {
        if (alive.current) setPickError(`${name} could not be fingerprinted in this browser.`);
        return;
      }
      if (!alive.current) return;
      remember(sha256, file);
      setPicking({ name, phase: "lookup" });
      // Only the fingerprint and what the browser already knows about the file go to the server.
      const body: Parameters<typeof checkFileHash>[0] = { sha256, size_bytes: file.size };
      if (file.name) body.name = file.name.slice(0, 255);
      if (file.type) body.media_type = file.type.slice(0, 100);
      try {
        const row = await checkFileHash(body);
        if (alive.current) putRow(row);
      } catch (err) {
        if (alive.current) setPickError(errorText(err, `${name} could not be checked. Try again.`));
      }
    } finally {
      if (alive.current) setPicking(null);
    }
  };

  /** "Pick the file again…": the picked file must be the row's file before it may be sent. */
  const pickAgain = async (row: FileCheck, file: File) => {
    const name = displayName(row.name);
    setNote(row.id, null);
    if (file.size > HASH_MAX_BYTES) {
      setNote(row.id, TOO_LARGE_TO_HASH);
      return;
    }
    setBusy({ id: row.id, action: "pick" });
    let sha256: string;
    try {
      sha256 = await sha256Hex(file);
    } catch {
      if (alive.current) setNote(row.id, `That file could not be fingerprinted in this browser.`);
      return;
    } finally {
      if (alive.current) setBusy(null);
    }
    if (!alive.current) return;
    if (sha256 !== row.sha256) {
      setNote(row.id, `That is a different file: its fingerprint does not match ${name}. Pick ${name} to send it.`);
      return;
    }
    remember(sha256, file);
    setConfirmRow(row);
  };

  const onFilePicked = (file: File | undefined) => {
    const target = pickFor.current;
    pickFor.current = null;
    if (!file) return;
    if (target) void pickAgain(target, file);
    else void checkPicked(file);
  };

  const openPicker = (target: FileCheck | null) => {
    pickFor.current = target;
    inputRef.current?.click();
  };

  /** Confirmed in the dialog: park the upload card. A failure keeps the dialog open with the reason. */
  const sendRow = async (row: FileCheck) => {
    const name = displayName(row.name);
    // The bytes go only when the server has no copy of its own (upload_needs_file).
    let file: File | undefined;
    if (row.upload_needs_file) {
      file = files.get(row.sha256);
      if (!file) throw new Error(PICK_AGAIN);
      const max = data?.service.upload_max_bytes ?? 0;
      if (max > 0 && file.size > max) {
        throw new Error(`${name} is larger than ${megabytes(max)}, too large to send to VirusTotal from here.`);
      }
    }
    try {
      const answer = await requestFileUpload(row.id, file);
      if (!alive.current) return;
      patchRow(row.id, { state: "upload_pending", action_id: answer.action_id, can_upload: false });
      setNote(row.id, null);
      setConfirmRow(null);
    } catch (err) {
      // 404: the row is gone. 409: the server's view changed (already known, needs the file,
      // switched off). Read the list again so the row shows what is true now.
      if (err instanceof ApiError && (err.status === 404 || err.status === 409)) void reload();
      throw err;
    }
  };

  const decide = async (row: FileCheck, approved: boolean) => {
    if (!row.action_id) return;
    const name = displayName(row.name);
    setBusy({ id: row.id, action: approved ? "approve" : "deny" });
    setNote(row.id, null);
    try {
      const answer = await decideApproval(row.action_id, approved);
      if (!alive.current) return;
      const refused = approved ? refusalOf(answer?.result) : null;
      if (refused) setNote(row.id, refused);
      await reload();
    } catch (err) {
      if (!alive.current) return;
      setNote(
        row.id,
        errorText(err, approved ? `Sending ${name} could not be approved. Try again.` : `The card for ${name} could not be denied. Try again.`),
      );
      // The card is gone (decided elsewhere or expired): read the list again rather than assume.
      if (err instanceof ApiError && (err.status === 404 || err.status === 409)) void reload();
    } finally {
      if (alive.current) setBusy(null);
    }
  };

  const forget = async (row: FileCheck) => {
    const name = displayName(row.name);
    setBusy({ id: row.id, action: "forget" });
    setNote(row.id, null);
    try {
      await forgetFileCheck(row.id);
      if (!alive.current) return;
      seq.current += 1;
      setData((prev) => prev && { ...prev, checks: prev.checks.filter((c) => c.id !== row.id) });
      setFiles((prev) => {
        if (!prev.has(row.sha256)) return prev;
        const next = new Map(prev);
        next.delete(row.sha256);
        return next;
      });
    } catch (err) {
      if (!alive.current) return;
      setNote(row.id, errorText(err, `${name} could not be forgotten. Try again.`));
      // 404: the server holds no such row any more. Read the list again rather than assume.
      if (err instanceof ApiError && err.status === 404) void reload();
    } finally {
      if (alive.current) setBusy(null);
    }
  };

  const service = data?.service ?? null;
  const on = service?.state === "on";
  const pickerOn = on && hashOk && picking === null;

  let body;
  if (loadError) {
    body = (
      <div className="mt-4">
        <ErrorAlert>
          {loadError}{" "}
          <button
            type="button"
            className="underline font-medium"
            onClick={() => {
              setLoadError("");
              setData(null);
              setAttempt((n) => n + 1);
            }}
          >
            Try again
          </button>
        </ErrorAlert>
      </div>
    );
  } else if (data === null || service === null) {
    body = <SkeletonRows />;
  } else {
    body = (
      <>
        <ServiceLine service={service} isOwner={isOwner} onOpenKeys={onOpenKeys} />

        <div className="flex items-center gap-3 flex-wrap mt-4">
          {/* Driven by the buttons that name it: kept out of the tab order so there is one way
              in, but still rendered (not display:none) because a detached input cannot open. */}
          <input
            ref={inputRef}
            type="file"
            tabIndex={-1}
            aria-label="File to fingerprint"
            className="sr-only"
            disabled={!on || !hashOk}
            onChange={(e) => {
              onFilePicked(e.target.files?.[0]);
              // Clearing lets the same file be picked again.
              e.target.value = "";
            }}
          />
          <button
            type="button"
            onClick={() => openPicker(null)}
            disabled={!pickerOn}
            className="inline-flex items-center justify-center gap-2 px-4 rounded-[10px] text-sm font-semibold disabled:opacity-50"
            style={primaryButtonStyle}
          >
            Check a file…
          </button>
          <p className="text-xs min-w-0 flex-1" style={{ color: "var(--text-muted)" }}>
            {PICKER_NOTE}
          </p>
        </div>
        {!hashOk && (
          <p className="text-sm mt-2" style={{ color: "var(--accent-warning, var(--text-secondary))" }}>
            {NO_HASH_NOTE}
          </p>
        )}
        {picking && (
          <p role="status" className="inline-flex items-center gap-2 text-sm mt-2" style={{ color: "var(--text-muted)" }}>
            <Loader2 className="w-4 h-4 animate-spin" aria-hidden />
            {picking.phase === "hash"
              ? `Fingerprinting ${picking.name}…`
              : `Looking up the fingerprint of ${picking.name}…`}
          </p>
        )}
        {pickError && (
          <p role="alert" className="text-sm mt-2" style={{ color: "var(--accent-danger)" }}>
            {pickError}
          </p>
        )}

        {data.checks.length === 0 ? (
          <p className="text-sm mt-5" style={{ color: "var(--text-secondary)" }}>
            No files checked yet.
            {on && " Files people send Crawler are checked automatically."}
          </p>
        ) : (
          <ul aria-label="Checked files" className="space-y-2 mt-5">
            {data.checks.map((row) => {
              const name = displayName(row.name);
              const status = rowStatus(row);
              const rowBusy = busy?.id === row.id;
              const canSend = row.can_upload && row.state === "checked";
              const needsPick = canSend && row.upload_needs_file && !files.has(row.sha256);
              const when = timeAgo(row.updated_at);
              return (
                <li key={row.id} className="rounded-[10px] p-3" style={rowStyle}>
                  <div className="flex items-start justify-between gap-3 flex-wrap">
                    <div className="min-w-0 flex-1">
                      <p className="text-sm font-semibold break-all" style={{ color: "var(--text-primary)" }}>
                        {name}
                      </p>
                      <p className="text-xs mt-0.5" style={{ color: "var(--text-muted)" }}>
                        {sourceLabel(row.source)}
                        {when && ` · ${when}`}
                      </p>
                      <p className="text-sm mt-1.5 flex flex-wrap items-center gap-x-2 gap-y-1" style={{ color: "var(--text-secondary)" }}>
                        {status.badge && (
                          <span
                            data-tone={status.badge.tone}
                            className="text-[11px] px-2 py-0.5 rounded-full font-semibold"
                            style={TONE_STYLES[status.badge.tone]}
                          >
                            {status.badge.label}
                          </span>
                        )}
                        {status.text && <span className="break-words">{status.text}</span>}
                      </p>

                      {row.state === "upload_pending" && row.action_id && (
                        <div className="flex items-center gap-2 flex-wrap mt-2">
                          <button
                            type="button"
                            onClick={() => void decide(row, true)}
                            disabled={busy !== null || !on}
                            aria-label={`Approve sending ${name}`}
                            className={smallButtonCls}
                            style={{ ...neutralButtonStyle, border: "1px solid var(--border-accent)" }}
                          >
                            {rowBusy && busy?.action === "approve" && (
                              <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden />
                            )}
                            Approve
                          </button>
                          <button
                            type="button"
                            onClick={() => void decide(row, false)}
                            disabled={busy !== null}
                            aria-label={`Deny sending ${name}`}
                            className={smallButtonCls}
                            style={neutralButtonStyle}
                          >
                            {rowBusy && busy?.action === "deny" && (
                              <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden />
                            )}
                            Deny
                          </button>
                        </div>
                      )}

                      {canSend && needsPick && (
                        <div className="flex items-center gap-2 flex-wrap mt-2">
                          <p className="text-xs" style={{ color: "var(--text-muted)" }}>
                            {PICK_AGAIN}
                          </p>
                          <button
                            type="button"
                            onClick={() => openPicker(row)}
                            disabled={busy !== null || !on || !hashOk}
                            aria-label={`Pick the file again: ${name}`}
                            className={smallButtonCls}
                            style={neutralButtonStyle}
                          >
                            {rowBusy && busy?.action === "pick" && (
                              <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden />
                            )}
                            Pick the file again…
                          </button>
                        </div>
                      )}
                      {canSend && !needsPick && (
                        <div className="mt-2">
                          <button
                            type="button"
                            onClick={() => {
                              setNote(row.id, null);
                              setConfirmRow(row);
                            }}
                            disabled={busy !== null || !on}
                            aria-label={`Send to VirusTotal: ${name}`}
                            className={smallButtonCls}
                            style={neutralButtonStyle}
                          >
                            Send to VirusTotal…
                          </button>
                        </div>
                      )}
                    </div>
                    <button
                      type="button"
                      onClick={() => void forget(row)}
                      disabled={busy !== null}
                      aria-label={`Forget ${name}`}
                      className={smallButtonCls}
                      style={dangerButtonStyle}
                    >
                      {rowBusy && busy?.action === "forget" && <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden />}
                      Forget
                    </button>
                  </div>
                  {notes[row.id] && (
                    <p role="alert" className="text-xs mt-2" style={{ color: "var(--accent-danger)" }}>
                      {notes[row.id]}
                    </p>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </>
    );
  }

  const confirmName = confirmRow ? displayName(confirmRow.name) : "";
  return (
    <section aria-labelledby={headingId} className="rounded-[14px] p-6" style={panelStyle}>
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <h2 id={headingId} className="mb-1">
          File checks
        </h2>
        {service && service.state !== "blocked" && <UsageLine service={service} />}
      </div>
      {body}
      <ConfirmDialog
        open={confirmRow !== null}
        title={`Send ${confirmName} to VirusTotal?`}
        message={uploadWarning(confirmName)}
        confirmLabel="Continue"
        danger
        onConfirm={() => (confirmRow ? sendRow(confirmRow) : undefined)}
        onCancel={() => setConfirmRow(null)}
      />
    </section>
  );
}
