/**
 * AppApprovals: Settings ▸ Permissions ▸ "Apps allowed for a week" — each app Crawler may act in
 * without asking, where it was allowed (this browser, another browser or Telegram) and until when,
 * each with Revoke.
 *
 * Why it exists: "Allow Calendar for 7 days" on an approval card lets desktop.act run in that app
 * with no card for a week, for requests from the browser or Telegram chat that allowed it (spec
 * 2026-09-25-weekly-app-approvals §3). This is the one place on the web that lists every one still
 * live, from anywhere, and ends one early.
 */

import { useEffect, useId, useState } from "react";
import { Loader2 } from "lucide-react";
import { formatAllowedUntil } from "@/components/appApprovalFormat";
import { ErrorAlert } from "@/components/FormFeedback";
import { errorText } from "@/components/formStyles";
import { ApiError, listAppApprovals, revokeAppApproval } from "@/services/api";
import type { AppApproval } from "@/types";

const rowStyle = { background: "var(--claw-surface)", border: "1px solid var(--claw-border)" };

/** Where the requests it covers come from. Only a web row allowed here is "this browser". */
function allowedFrom(row: AppApproval): string {
  if (row.channel === "telegram") return "Telegram";
  return row.this_device ? "this browser" : "another browser";
}

export default function AppApprovals() {
  const headingId = useId();
  const [rows, setRows] = useState<AppApproval[] | null>(null);
  const [loadError, setLoadError] = useState("");
  const [attempt, setAttempt] = useState(0);
  // One revoke at a time: every Revoke waits while one is in flight.
  const [revokingId, setRevokingId] = useState<string | null>(null);
  const [revokeError, setRevokeError] = useState<{ id: string; text: string } | null>(null);

  useEffect(() => {
    let cancelled = false;
    listAppApprovals()
      .then((list) => {
        if (cancelled) return;
        setRows(list);
        setLoadError("");
      })
      .catch((err) => {
        if (!cancelled) setLoadError(errorText(err, "The apps allowed for a week could not be loaded."));
      });
    return () => {
      cancelled = true;
    };
  }, [attempt]);

  const revoke = async (target: AppApproval) => {
    setRevokingId(target.id);
    setRevokeError(null);
    try {
      await revokeAppApproval(target.id);
      setRows((prev) => prev && prev.filter((row) => row.id !== target.id));
    } catch (err) {
      setRevokeError({
        id: target.id,
        text: errorText(err, `${target.app} could not be revoked. Try again.`),
      });
      // 404: the server holds nothing live under this id any more (the week ran out, or it was
      // revoked from Telegram). Read the list again rather than assume: a row that is truly gone
      // drops out with its error, and one that is still live stays, with the error beside it.
      if (err instanceof ApiError && err.status === 404) setAttempt((n) => n + 1);
    } finally {
      setRevokingId(null);
    }
  };

  return (
    <section
      aria-labelledby={headingId}
      className="mt-6 pt-5"
      style={{ borderTop: "1px solid var(--claw-border)" }}
    >
      <h3 id={headingId} className="text-sm font-semibold mb-1" style={{ color: "var(--text-primary)" }}>
        Apps allowed for a week
      </h3>
      <p className="text-xs mb-3" style={{ color: "var(--text-muted)" }}>
        Crawler acts in these apps without asking, only for requests from the browser or Telegram
        chat that allowed each one. Revoke one to get approval cards for it again.
      </p>

      {loadError ? (
        <ErrorAlert>
          {loadError}{" "}
          <button
            type="button"
            className="underline font-medium"
            onClick={() => {
              setLoadError("");
              setRows(null);
              setAttempt((n) => n + 1);
            }}
          >
            Try again
          </button>
        </ErrorAlert>
      ) : rows === null ? (
        <p className="text-sm" style={{ color: "var(--text-muted)" }}>
          Loading allowed apps…
        </p>
      ) : rows.length === 0 ? (
        <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
          No apps are allowed for a week. When Crawler asks to act in an app like Calendar, you can
          allow it for 7 days from the approval card.
        </p>
      ) : (
        <ul className="space-y-2">
          {rows.map((row) => (
            <li key={row.id} className="rounded-[10px] p-3" style={rowStyle}>
              <div className="flex items-center justify-between gap-3 flex-wrap">
                <div className="min-w-0">
                  <p className="text-sm font-semibold break-words" style={{ color: "var(--text-primary)" }}>
                    {row.app}
                  </p>
                  <p className="text-xs mt-0.5" style={{ color: "var(--text-muted)" }}>
                    From {allowedFrom(row)} · until {formatAllowedUntil(row.expires_at)}
                  </p>
                </div>
                {/* Two rows can name the same app (allowed from Telegram and from here), so
                    the button's name says which one it ends. */}
                <button
                  type="button"
                  onClick={() => void revoke(row)}
                  disabled={revokingId !== null}
                  aria-label={`Revoke ${row.app} (${allowedFrom(row)})`}
                  className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-[10px] text-xs font-semibold disabled:opacity-50"
                  style={{
                    minHeight: 36,
                    background: "var(--claw-panel)",
                    border: "1px solid var(--border-danger)",
                    color: "var(--accent-danger)",
                  }}
                >
                  {revokingId === row.id && <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden />}
                  Revoke
                </button>
              </div>
              {revokeError?.id === row.id && (
                <p role="alert" className="text-xs mt-2" style={{ color: "var(--accent-danger)" }}>
                  {revokeError.text}
                </p>
              )}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
