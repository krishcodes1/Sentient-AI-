/**
 * ScamCheckTab: Security ▸ "Check for scams" (every signed-in user) — paste a message, email or
 * link, add up to four screenshots or photos of a QR code (button, paste or drop), and get one of
 * four fixed answers with Crawler's reasons, what to do, the links it found and how each was
 * checked. The quota line says how many checks are left today; when Google's list is not set up
 * the owner gets a button to the Service keys tab.
 *
 * Why it exists: people are sent scams by text and email and want a second opinion before they
 * click or pay. Every check goes through POST /api/security/scam-check (the browser never calls
 * an outside service), the answer is never "safe", and nothing from the checked content is ever
 * rendered as a link: hosts are shown as code text and the AI provider's own reasons as plain
 * text, so a scammer's link can't be clicked from this page.
 */

import {
  useEffect,
  useId,
  useRef,
  useState,
  type ClipboardEvent,
  type DragEvent,
  type FormEvent,
} from "react";
import {
  CircleHelp,
  ImagePlus,
  Loader2,
  Search,
  ShieldAlert,
  TriangleAlert,
  X,
  type LucideIcon,
} from "lucide-react";
import { ErrorAlert } from "@/components/FormFeedback";
import {
  errorText,
  inputCls,
  inputStyle,
  labelCls,
  panelStyle,
  primaryCls,
  primaryStyle,
  secondaryCls,
  secondaryStyle,
} from "@/components/formStyles";
import { checkScam, getScamCheckStatus } from "@/services/api";
import type { ScamCheckResult, ScamCheckStatus } from "@/types";
import {
  MAX_SCAM_IMAGES,
  MAX_SCAM_NOTE,
  MAX_SCAM_TEXT,
  SCAM_IMAGE_TYPES,
  checkedSummary,
  headlineFor,
  levelLabel,
  originLabel,
  readImage,
  sourceLabel,
  type HeadlineTone,
} from "@/pages/security/scamVerdict";

/** One picture waiting to be checked. */
interface Picture {
  /** Stable across re-renders so a removal keeps the other thumbnails' keys. */
  id: string;
  name: string;
  mediaType: string;
  dataUrl: string;
}

const CAVEAT = "No check can prove a message is safe.";
const ACCEPT = SCAM_IMAGE_TYPES.join(",");

const TONES: Record<
  HeadlineTone,
  { Icon: LucideIcon; color: string; background: string; border: string }
> = {
  danger: {
    Icon: ShieldAlert,
    color: "var(--accent-danger)",
    background: "var(--fill-danger)",
    border: "var(--border-danger)",
  },
  warning: {
    Icon: TriangleAlert,
    color: "var(--accent-warning)",
    background: "var(--fill-warning)",
    border: "var(--border-warning)",
  },
  neutral: {
    Icon: Search,
    color: "var(--text-primary)",
    background: "var(--fill-neutral)",
    border: "var(--claw-border)",
  },
  muted: {
    Icon: CircleHelp,
    color: "var(--text-muted)",
    background: "var(--fill-neutral)",
    border: "var(--claw-border)",
  },
};

const mutedText = { color: "var(--text-muted)" };
const secondaryText = { color: "var(--text-secondary)" };

function formatCount(n: number): string {
  return n.toLocaleString("en-US");
}

function pictureId(file: File): string {
  return `${file.name}-${file.lastModified}-${Math.random().toString(36).slice(2)}`;
}

/** A titled list of plain-text lines; nothing when there are none. */
function Lines({ title, lines }: { title: string; lines: string[] }) {
  if (lines.length === 0) return null;
  return (
    <div className="mt-3">
      <h4 className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>
        {title}
      </h4>
      <ul className="mt-1 list-disc pl-5 space-y-1 text-sm" style={secondaryText}>
        {lines.map((line, i) => (
          <li key={`${i}-${line}`}>{line}</li>
        ))}
      </ul>
    </div>
  );
}

/** The verdict, Crawler's reasons, the AI's own reasons, advice, links and notes. */
function ScamResult({ result, onReset }: { result: ScamCheckResult; onReset: () => void }) {
  const headingId = useId();
  const linksId = useId();
  const headline = headlineFor(result.verdict);
  const tone = TONES[headline.tone];
  const aiReasons = result.ai_reasons ?? [];
  return (
    <section
      aria-labelledby={headingId}
      className="mt-5 rounded-[12px] p-4"
      style={{ background: tone.background, border: `1px solid ${tone.border}` }}
    >
      <h3
        id={headingId}
        className="flex items-center gap-2 text-base font-semibold"
        style={{ color: tone.color }}
      >
        <tone.Icon className="w-5 h-5 shrink-0" aria-hidden />
        {headline.text}
      </h3>
      {result.verdict === "no_signs_found" && (
        <p className="mt-1 text-sm" style={secondaryText}>
          {CAVEAT}
        </p>
      )}
      <Lines title="Why" lines={result.reasons} />
      {/* The AI's reasons are filtered on the server (no links, addresses or long numbers) and
          kept apart from Crawler's own sentences; here they are plain React text, so even one
          that slipped through could never become a clickable link. */}
      <Lines title="Your AI provider also noted:" lines={aiReasons} />
      <Lines title="What to do" lines={result.advice} />
      {result.links.length > 0 && (
        <div className="mt-3">
          <h4 id={linksId} className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>
            Links
          </h4>
          {/* One row per link rather than a four-column table, so a long address wraps on a
              phone instead of squeezing the other columns. */}
          <ul aria-labelledby={linksId} className="mt-1 space-y-2">
            {result.links.map((link, i) => (
              <li
                key={`${i}-${link.shown}`}
                className="rounded-[8px] px-3 py-2 text-sm"
                style={{ background: "var(--claw-panel)", border: "1px solid var(--claw-border)" }}
              >
                {/* Code text in the body colour, never an <a> and never link-blue: the
                    address is the scammer's. */}
                <code className="block break-all" style={{ color: "var(--text-primary)" }}>
                  {link.shown}
                </code>
                <p className="mt-1 text-xs" style={secondaryText}>
                  <span className="font-semibold">{levelLabel(link.level)}</span>
                  {link.looks_like ? ` (imitates ${link.looks_like})` : ""}
                  {link.checked_by.length > 0
                    ? ` · checked by ${link.checked_by.map(sourceLabel).join(", ")}`
                    : ""}
                  {" · found in "}
                  {originLabel(link.origin)}
                </p>
              </li>
            ))}
          </ul>
        </div>
      )}
      <Lines title="Notes" lines={result.notes} />
      <p className="mt-3 text-xs" style={mutedText}>
        {checkedSummary(result.checked, result.conversation_id !== null)}
      </p>
      <button
        type="button"
        onClick={onReset}
        className={`${secondaryCls} mt-3`}
        style={secondaryStyle}
      >
        Check another
      </button>
    </section>
  );
}

export default function ScamCheckTab({
  isOwner,
  onOpenKeys,
}: {
  isOwner: boolean;
  onOpenKeys?: () => void;
}) {
  const headingId = useId();
  const textId = useId();
  const counterId = useId();
  const noteId = useId();
  const [status, setStatus] = useState<ScamCheckStatus | null>(null);
  const [loadError, setLoadError] = useState("");
  const [attempt, setAttempt] = useState(0);

  const [text, setText] = useState("");
  const [note, setNote] = useState("");
  const [pictures, setPictures] = useState<Picture[]>([]);
  const [pictureError, setPictureError] = useState("");
  const [dragging, setDragging] = useState(false);
  const [checking, setChecking] = useState(false);
  const [checkError, setCheckError] = useState("");
  const [result, setResult] = useState<ScamCheckResult | null>(null);

  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  // A check can take a minute; the person may leave the tab before it answers.
  const aliveRef = useRef(true);

  useEffect(() => {
    aliveRef.current = true;
    return () => {
      aliveRef.current = false;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    getScamCheckStatus()
      .then((data) => {
        if (cancelled) return;
        setStatus(data);
        setLoadError("");
      })
      .catch((err) => {
        if (!cancelled) setLoadError(errorText(err, "Couldn't load the scam check. Try again."));
      });
    return () => {
      cancelled = true;
    };
  }, [attempt]);

  const addFiles = async (files: File[]) => {
    if (files.length === 0) return;
    const refusals: string[] = [];
    const room = Math.max(0, MAX_SCAM_IMAGES - pictures.length);
    if (files.length > room) refusals.push(`Up to ${MAX_SCAM_IMAGES} pictures per check.`);
    const accepted: Picture[] = [];
    for (const file of files.slice(0, room)) {
      try {
        accepted.push({
          id: pictureId(file),
          name: file.name || "picture",
          mediaType: file.type,
          dataUrl: await readImage(file),
        });
      } catch (err) {
        refusals.unshift(errorText(err, "That picture could not be read."));
      }
    }
    if (!aliveRef.current) return;
    // The cap is applied again inside the update: two quick pastes both
    // read the same `pictures.length` above.
    if (accepted.length > 0) {
      setPictures((prev) => [...prev, ...accepted].slice(0, MAX_SCAM_IMAGES));
    }
    setPictureError(refusals.join(" "));
  };

  const handlePaste = (event: ClipboardEvent<HTMLTextAreaElement>) => {
    if (!status?.sees_images) return;
    const files = Array.from(event.clipboardData.files);
    if (files.length === 0) return;
    // The text half of a mixed paste still lands in the box; only the files are ours.
    void addFiles(files);
  };

  const handleDrop = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setDragging(false);
    if (checking || !status?.sees_images) return;
    void addFiles(Array.from(event.dataTransfer.files));
  };

  const removePicture = (id: string) => {
    setPictures((prev) => prev.filter((p) => p.id !== id));
    setPictureError("");
  };

  const refreshStatus = () => {
    // Only the quota line changes; a failed refresh keeps the last status.
    getScamCheckStatus()
      .then((data) => {
        if (aliveRef.current) setStatus(data);
      })
      .catch(() => undefined);
  };

  const canCheck = !checking && (text.trim() !== "" || pictures.length > 0);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!canCheck) return;
    setChecking(true);
    setCheckError("");
    setResult(null);
    try {
      // The text goes as typed: trimming could drop the invisible characters a check looks for.
      const answer = await checkScam({
        text,
        note: note.trim(),
        images: pictures.map((p) => ({ media_type: p.mediaType, data: p.dataUrl })),
      });
      if (!aliveRef.current) return;
      setResult(answer);
      refreshStatus();
    } catch (err) {
      // The text and pictures stay, so the person can try again.
      if (aliveRef.current) setCheckError(errorText(err, "The check could not be run. Try again."));
    } finally {
      if (aliveRef.current) setChecking(false);
    }
  };

  const reset = () => {
    setText("");
    setNote("");
    setPictures([]);
    setPictureError("");
    setCheckError("");
    setResult(null);
    textareaRef.current?.focus();
  };

  const heading = (
    <h2 id={headingId} className="text-lg font-semibold" style={{ color: "var(--text-primary)" }}>
      Check for scams
    </h2>
  );

  if (loadError) {
    return (
      <section aria-labelledby={headingId} className="rounded-[14px] p-4 sm:p-5" style={panelStyle}>
        {heading}
        <div className="mt-3">
          <ErrorAlert>
            {loadError}{" "}
            <button
              type="button"
              className="underline font-medium"
              onClick={() => {
                setLoadError("");
                setStatus(null);
                setAttempt((n) => n + 1);
              }}
            >
              Retry
            </button>
          </ErrorAlert>
        </div>
      </section>
    );
  }

  if (status === null) {
    return (
      <section aria-labelledby={headingId} className="rounded-[14px] p-4 sm:p-5" style={panelStyle}>
        {heading}
        <p role="status" className="mt-3 inline-flex items-center gap-2 text-sm" style={mutedText}>
          <Loader2 className="w-4 h-4 animate-spin" aria-hidden />
          Loading…
        </p>
      </section>
    );
  }

  if (status.effective !== "on") {
    return (
      <section aria-labelledby={headingId} className="rounded-[14px] p-4 sm:p-5" style={panelStyle}>
        {heading}
        <p role="status" className="mt-3 text-sm" style={secondaryText}>
          {status.reason || "Scam checks are turned off."}
        </p>
      </section>
    );
  }

  const seesImages = status.sees_images;
  const provider = status.provider ? ` (${status.provider})` : "";
  const full = pictures.length >= MAX_SCAM_IMAGES;

  return (
    <section aria-labelledby={headingId} className="rounded-[14px] p-4 sm:p-5" style={panelStyle}>
      {heading}
      <p className="mt-1 text-sm" style={secondaryText}>
        {seesImages
          ? "Paste a message, email or link you're unsure about, or add a screenshot or a photo of a QR code. "
          : "Paste a message, email or link you're unsure about. "}
        {`Crawler checks the links and the wording and asks your AI provider${provider} to look. `}
        {CAVEAT}
      </p>

      <form onSubmit={submit} className="mt-4">
        <div
          onDragOver={(e) => {
            if (!seesImages) return;
            e.preventDefault();
            if (!checking) setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={handleDrop}
        >
          <label htmlFor={textId} className={labelCls}>
            Message, email or link
          </label>
          <textarea
            id={textId}
            ref={textareaRef}
            value={text}
            onChange={(e) => setText(e.target.value)}
            onPaste={handlePaste}
            maxLength={MAX_SCAM_TEXT}
            rows={6}
            disabled={checking}
            aria-describedby={counterId}
            placeholder="Paste the message here"
            className={`${inputCls} resize-y disabled:opacity-50`}
            style={{
              ...inputStyle,
              border: `1px solid ${dragging ? "var(--accent-primary)" : "var(--claw-border)"}`,
            }}
          />
          <div className="mt-1 flex flex-wrap items-center justify-between gap-2">
            <span id={counterId} className="text-xs mono-num" style={mutedText}>
              {formatCount(text.length)} / {formatCount(MAX_SCAM_TEXT)}
            </span>
            {seesImages && (
              <>
                {/* Driven by the button beside it, as in the chat composer: kept out of
                    the tab order but rendered, because a detached input cannot be opened. */}
                <input
                  ref={fileInputRef}
                  type="file"
                  accept={ACCEPT}
                  multiple
                  tabIndex={-1}
                  aria-label="Screenshot to check"
                  className="sr-only"
                  onChange={(e) => {
                    void addFiles(Array.from(e.target.files ?? []));
                    // Clearing lets the same picture be picked again after a removal.
                    e.target.value = "";
                  }}
                />
                <button
                  type="button"
                  onClick={() => fileInputRef.current?.click()}
                  disabled={checking || full}
                  className={secondaryCls}
                  style={secondaryStyle}
                >
                  <ImagePlus className="w-4 h-4" aria-hidden />
                  Add screenshot
                </button>
              </>
            )}
          </div>
          {seesImages && pictures.length > 0 && (
            <ul aria-label="Pictures to check" className="mt-2 flex flex-wrap gap-2">
              {pictures.map((p) => (
                <li key={p.id} className="relative">
                  <img
                    src={p.dataUrl}
                    alt={p.name}
                    className="w-16 h-16 object-cover rounded-[8px]"
                    style={{ border: "1px solid var(--claw-border)" }}
                  />
                  <button
                    type="button"
                    onClick={() => removePicture(p.id)}
                    disabled={checking}
                    aria-label={`Remove ${p.name}`}
                    className="absolute -top-2 -right-2 inline-flex items-center justify-center rounded-full w-6 h-6 disabled:opacity-50"
                    style={{
                      background: "var(--claw-panel)",
                      border: "1px solid var(--claw-border)",
                      color: "var(--text-primary)",
                    }}
                  >
                    <X className="w-3.5 h-3.5" aria-hidden />
                  </button>
                </li>
              ))}
            </ul>
          )}
          {pictureError && (
            <p role="alert" className="mt-2 text-sm" style={{ color: "var(--accent-danger)" }}>
              {pictureError}
            </p>
          )}
        </div>

        {!seesImages && (
          <p className="mt-2 text-sm" style={secondaryText}>
            {`Your AI provider${provider} can't look at pictures, so paste the text or the link.`}
          </p>
        )}

        <div className="mt-3">
          <label htmlFor={noteId} className={labelCls}>
            Your note (optional)
          </label>
          <input
            id={noteId}
            type="text"
            value={note}
            onChange={(e) => setNote(e.target.value)}
            maxLength={MAX_SCAM_NOTE}
            disabled={checking}
            placeholder="Where it came from, for example a text from an unknown number"
            className={`${inputCls} disabled:opacity-50`}
            style={inputStyle}
          />
        </div>

        {status.google_list === false && (
          <p className="mt-3 flex flex-wrap items-center gap-2 text-sm" style={secondaryText}>
            <span>Links are checked against Crawler's own lists.</span>
            {isOwner && onOpenKeys && (
              <button
                type="button"
                onClick={onOpenKeys}
                className="underline font-medium"
                style={{ color: "var(--accent-primary)" }}
              >
                Add a Safe Browsing key
              </button>
            )}
          </p>
        )}

        <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
          <p className="text-xs" style={mutedText}>
            {`${formatCount(status.checks_used_today)} of ${formatCount(status.checks_per_day)} checks used today`}
          </p>
          <button type="submit" disabled={!canCheck} className={primaryCls} style={primaryStyle}>
            {checking ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" aria-hidden />
                Checking… this can take up to a minute
              </>
            ) : (
              "Check"
            )}
          </button>
        </div>
      </form>

      {checkError && (
        <div className="mt-4">
          <ErrorAlert>{checkError}</ErrorAlert>
        </div>
      )}

      {/* Always mounted, so the verdict is announced when it arrives. */}
      <div aria-live="polite">{result && <ScamResult result={result} onReset={reset} />}</div>
    </section>
  );
}
