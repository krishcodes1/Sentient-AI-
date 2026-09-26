/**
 * WeeklyAppButton: the "Allow Calendar for 7 days" button a desktop.act approval card gets when the
 * server offers its app for a week (`weekly_app`), with the line under it saying what that does;
 * and WeeklyAllowedNote, the confirmation once the server has allowed the app.
 *
 * Why it exists: Reading one day in Calendar took six approval cards and six full-context model
 * calls (spec 2026-09-25-weekly-app-approvals). Chat's ApprovalCard and Dashboard's ApprovalRow
 * offer the same way out in the same words, so the button, its helper line and the confirmation
 * live here once, and the button never shows on a card the server did not offer it for.
 */

import { useId } from "react";
import { CalendarCheck, CalendarClock } from "lucide-react";
import { formatAllowedUntil } from "@/components/appApprovalFormat";
import type { ApprovalDecisionResponse, PendingApproval } from "@/types";

/**
 * What an approval card's buttons decide: approve or deny, plus "week" from the weekly button.
 * Cards and pages hand it on as rest arguments down to decideApproval(actionId, ...decision), so
 * Approve and Deny make the same call they always did and only the weekly button adds `remember`.
 */
export type ApprovalDecision = [approved: boolean, remember?: "week"];

/** A decision response's `weekly`: the app the weekly button allowed, and until when. */
export type WeeklyGrant = NonNullable<ApprovalDecisionResponse["weekly"]>;

/**
 * The third button, on a row of its own under Approve / Deny as on Telegram. It approves this act
 * exactly as Approve does, so the card passes its own busy and expired state in `disabled`.
 */
export default function WeeklyAppButton({
  approval,
  disabled,
  onAllow,
}: {
  approval: PendingApproval;
  disabled: boolean;
  onAllow: () => void;
}) {
  const hintId = useId();
  const app = typeof approval.weekly_app === "string" ? approval.weekly_app.trim() : "";
  if (!app) return null;
  return (
    <div className="mt-2">
      <button
        type="button"
        disabled={disabled}
        onClick={onAllow}
        aria-describedby={hintId}
        className="px-3 py-2 rounded-[8px] text-xs font-semibold disabled:opacity-50 inline-flex items-center gap-1.5"
        style={{
          minHeight: 36,
          background: "var(--fill-success)",
          border: "1px solid var(--border-success)",
          color: "var(--accent-success)",
        }}
      >
        <CalendarClock className="w-3.5 h-3.5 shrink-0" aria-hidden />
        Allow {app} for 7 days
      </button>
      <p id={hintId} className="text-xs mt-1.5" style={{ color: "var(--text-muted)" }}>
        Crawler then acts in {app} without asking, for requests from this browser, for 7 days.
        Revoke in Settings.
      </p>
    </div>
  );
}

/**
 * What the weekly button did, shown where the page shows the outcome of a decision: "Calendar is
 * allowed until Fri, Oct 2, 3:14 PM."
 */
export function WeeklyAllowedNote({
  weekly,
  className = "",
}: {
  weekly: WeeklyGrant;
  className?: string;
}) {
  return (
    <p
      role="status"
      className={`flex w-fit max-w-full items-center gap-2 px-3 py-2 rounded-[8px] text-xs ${className}`.trim()}
      style={{
        background: "var(--fill-success)",
        border: "1px solid var(--border-success)",
        color: "var(--accent-success)",
      }}
    >
      <CalendarCheck className="w-3.5 h-3.5 shrink-0" aria-hidden />
      <span>
        {weekly.app} is allowed until {formatAllowedUntil(weekly.expires_at)}.
      </span>
    </p>
  );
}
