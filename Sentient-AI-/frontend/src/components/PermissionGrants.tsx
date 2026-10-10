/**
 * PermissionGrants: Settings ▸ Permissions ▸ "Accounts allowed low-risk changes" — each connected
 * account that may make low-risk changes without asking, until when, when it was last used, each
 * with Revoke.
 *
 * Why it exists: "Allow low-risk changes on <account> for 7 days" on an approval card lets that
 * account's stars, labels, drafts, private events and to-dos run with no card for a week, from
 * every chat and browser (permission tiers). This is the one place on the web that lists every
 * grant still live and ends one early; Telegram's /grants and Slack's "grants" do the same.
 */

import { useEffect, useId, useState } from "react";
import { Loader2 } from "lucide-react";
import { formatAllowedUntil } from "@/components/appApprovalFormat";
import { ErrorAlert } from "@/components/FormFeedback";
import { errorText } from "@/components/formStyles";
import { ApiError, listPermissionGrants, revokePermissionGrant } from "@/services/api";
import type { PermissionGrant } from "@/types";

const rowStyle = { background: "var(--claw-surface)", border: "1px solid var(--claw-border)" };

/** "last used Wed, Sep 30, 9:02 AM (3 changes)", or "not used yet". */
function usedText(row: PermissionGrant): string {
  if (!row.last_used_at) return "not used yet";
  const changes = row.uses === 1 ? "1 change" : `${row.uses} changes`;
  return `last used ${formatAllowedUntil(row.last_used_at)} (${changes})`;
}

export default function PermissionGrants() {
  const headingId = useId();
  const [rows, setRows] = useState<PermissionGrant[] | null>(null);
  const [loadError, setLoadError] = useState("");
  const [attempt, setAttempt] = useState(0);
  // One revoke at a time: every Revoke waits while one is in flight.
  const [revokingId, setRevokingId] = useState<string | null>(null);
  const [revokeError, setRevokeError] = useState<{ id: string; text: string } | null>(null);

  useEffect(() => {
    let cancelled = false;
    listPermissionGrants()
      .then((list) => {
        if (cancelled) return;
        setRows(Array.isArray(list) ? list : []);
        setLoadError("");
      })
      .catch((err) => {
        if (!cancelled) {
          setLoadError(errorText(err, "The accounts allowed low-risk changes could not be loaded."));
        }
      });
    return () => {
      cancelled = true;
    };
  }, [attempt]);

  const revoke = async (target: PermissionGrant) => {
    setRevokingId(target.id);
    setRevokeError(null);
    try {
      await revokePermissionGrant(target.id);
      setRows((prev) => prev && prev.filter((row) => row.id !== target.id));
    } catch (err) {
      setRevokeError({
        id: target.id,
        text: errorText(err, `${target.account} could not be revoked. Try again.`),
      });
      // 404: the server holds nothing live under this id any more (the week ran out, or it was
      // revoked from a chat). Read the list again rather than assume.
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
        Accounts allowed low-risk changes
      </h3>
      <p className="text-xs mb-3" style={{ color: "var(--text-muted)" }}>
        Crawler makes low-risk changes on these accounts (stars, labels, drafts, private events,
        to-dos) without asking, until the date shown. Sends, deletes, sharing and anything other
        people see still ask. Revoke one to get approval cards for it again.
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
          Loading allowed accounts…
        </p>
      ) : rows.length === 0 ? (
        <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
          No account has a 7-day low-risk grant. Each account still follows its permission tier, so
          changes ask first unless the tier lets them run. A card for a small change can allow its
          account for 7 days.
        </p>
      ) : (
        <ul className="space-y-2">
          {rows.map((row) => (
            <li key={row.id} className="rounded-[10px] p-3" style={rowStyle}>
              <div className="flex items-center justify-between gap-3 flex-wrap">
                <div className="min-w-0">
                  <p className="text-sm font-semibold break-words" style={{ color: "var(--text-primary)" }}>
                    {row.account}
                  </p>
                  <p className="text-xs mt-0.5" style={{ color: "var(--text-muted)" }}>
                    {row.connector_type} · until {formatAllowedUntil(row.expires_at)} · {usedText(row)}
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => void revoke(row)}
                  disabled={revokingId !== null}
                  aria-label={`Revoke low-risk changes on ${row.account}`}
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
