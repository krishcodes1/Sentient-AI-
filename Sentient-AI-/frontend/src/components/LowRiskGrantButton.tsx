/**
 * LowRiskGrantButton: the "Allow low-risk changes on School Gmail for 7 days" button an approval
 * card gets when the server offers a low-risk grant for its account (`low_risk_account`), with the
 * line under it saying what that does; and LowRiskAllowedNote, the confirmation once the server
 * has made the grant.
 *
 * Why it exists: small, undoable changes (a star, a label, a draft, a private event, a to-do)
 * each asked for their own card. Permission tiers lets the owner stop that for one account for a
 * week, from the card itself, while sends, deletes, sharing and anything other people see keep
 * asking. Chat's ApprovalCard and Dashboard's ApprovalRow offer it in the same words, so the
 * button, its helper line and the confirmation live here once, and the button never shows on a
 * card the server did not offer it for (tainted, unattended or anything but low-risk).
 */

import { useId } from "react";
import { Zap, ShieldCheck } from "lucide-react";
import { formatAllowedUntil } from "@/components/appApprovalFormat";
import type { ApprovalDecisionResponse, PendingApproval } from "@/types";

/** A decision response's `low_risk`: the account the button allowed, and until when. */
export type LowRiskGrant = NonNullable<ApprovalDecisionResponse["low_risk"]>;

/**
 * The third button, on a row of its own under Approve / Deny as on Telegram. It approves this
 * change exactly as Approve does, so the card passes its own busy and expired state in `disabled`.
 */
export default function LowRiskGrantButton({
  approval,
  disabled,
  onAllow,
}: {
  approval: PendingApproval;
  disabled: boolean;
  onAllow: () => void;
}) {
  const hintId = useId();
  const account =
    typeof approval.low_risk_account === "string" ? approval.low_risk_account.trim() : "";
  if (!account) return null;
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
        <Zap className="w-3.5 h-3.5 shrink-0" aria-hidden />
        Allow low-risk changes on {account} for 7 days
      </button>
      <p id={hintId} className="text-xs mt-1.5" style={{ color: "var(--text-muted)" }}>
        Crawler then makes low-risk changes on this account without asking, for 7 days. Sends,
        deletes, sharing and anything other people see still ask. Revoke in Settings.
      </p>
    </div>
  );
}

/**
 * What the low-risk button did, shown where the page shows the outcome of a decision: "Low-risk
 * changes on School Gmail are allowed until Fri, Oct 2, 3:14 PM."
 */
export function LowRiskAllowedNote({
  grant,
  className = "",
}: {
  grant: LowRiskGrant;
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
      <ShieldCheck className="w-3.5 h-3.5 shrink-0" aria-hidden />
      <span>
        Low-risk changes on {grant.account} are allowed until{" "}
        {formatAllowedUntil(grant.expires_at)}.
      </span>
    </p>
  );
}
