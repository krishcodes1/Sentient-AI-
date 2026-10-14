/**
 * The plain parts of an approval card that Chat's ApprovalCard and Dashboard's ApprovalRow share:
 * ApprovalDetailList (every value the action will use as "Label: value" rows), ApprovalAsk ("Okay
 * to go ahead? This expires in 14 minutes.", or what to do once it ran out of time),
 * ApprovalCheckCode (the quiet "Check code 6d3b dfca 7bf8 cfc5" line) and ApprovalTechnicalDetails
 * (a closed "Technical details" disclosure with the tool id and, where the card lists values, the
 * raw arguments).
 *
 * Why it exists: the cards used to read "Tool google_workspace.send_email wants to run" over a
 * JSON dump of the arguments. The person approving is not a developer (docs/bot-message-style.md),
 * so a card now reads like the Telegram and Slack ones: the sentence, the labelled values, the
 * question, the buttons and the check code, with the developer view one click away for anyone who
 * wants it. Every value is still shown whole, line breaks kept (spec F3): nothing is clamped,
 * clipped or ellipsized.
 */

import type { CSSProperties } from "react";
import type { PendingApproval } from "@/types";
import { approvalDetails, shownArguments } from "@/pages/approvalArguments";
import { expiresInWords } from "@/pages/approvalCountdown";

const detailBox = {
  background: "var(--claw-surface)",
  border: "1px solid var(--claw-border)",
};

/** Every value the action will use, labelled in everyday words. Renders nothing for a request
 *  with no values. `boxStyle` lets a page match the box to its own surface. */
export function ApprovalDetailList({
  approval,
  className = "",
  boxStyle = detailBox,
}: {
  approval: PendingApproval;
  className?: string;
  boxStyle?: CSSProperties;
}) {
  const details = approvalDetails(approval);
  if (details.length === 0) return null;
  return (
    <dl
      aria-label="What this request will use"
      className={`grid grid-cols-[minmax(0,auto)_minmax(0,1fr)] gap-x-3 gap-y-1.5 p-2.5 rounded-[8px] text-xs ${className}`.trim()}
      style={boxStyle}
    >
      {details.map((detail, i) => (
        <div key={`${detail.label}-${i}`} className="contents">
          <dt className="font-medium" style={{ color: "var(--text-muted)" }}>
            {detail.label}
          </dt>
          {/* pre-wrap keeps every line of a long message and its indented nested lines;
              break-words wraps a long link instead of cutting it. */}
          <dd className="whitespace-pre-wrap break-words min-w-0" style={{ color: "var(--text-primary)" }}>
            {detail.value}
          </dd>
        </div>
      ))}
    </dl>
  );
}

/** "Okay to go ahead? This expires in 14 minutes." while the card can be decided, and what to do
 *  once it ran out of time. `remaining` is null when the card has no deadline. */
export function ApprovalAsk({
  remaining,
  className = "",
}: {
  remaining: number | null;
  className?: string;
}) {
  if (remaining !== null && remaining <= 0) {
    return (
      <p className={`text-xs ${className}`.trim()} style={{ color: "var(--text-muted)" }}>
        This request ran out of time, so nothing was done. Ask Crawler again if you still want it.
      </p>
    );
  }
  return (
    <p className={`text-sm ${className}`.trim()} style={{ color: "var(--text-primary)" }}>
      Okay to go ahead?
      {remaining !== null && (
        <span style={{ color: "var(--text-secondary)" }}> This expires in {expiresInWords(remaining)}.</span>
      )}
    </p>
  );
}

/** The quiet last line: the same check code the Telegram and Slack cards end with. Nothing when
 *  the server sent none. */
export function ApprovalCheckCode({
  approval,
  className = "",
}: {
  approval: PendingApproval;
  className?: string;
}) {
  const code = typeof approval.check_code === "string" ? approval.check_code.trim() : "";
  if (!code) return null;
  return (
    <p className={`text-xs ${className}`.trim()} style={{ color: "var(--text-muted)" }}>
      Check code <span className="mono-num">{code}</span>
    </p>
  );
}

/** A closed disclosure with the tool id, and the raw arguments when `showArguments` (a card that
 *  lists its values; a purchase or a browser.act step keeps its stored page out of view). The
 *  arguments are the ones the card lists (shownArguments): a desktop.act card's stored screen
 *  stays out, as it does on the chat cards. */
export function ApprovalTechnicalDetails({
  approval,
  showArguments,
  className = "",
}: {
  approval: PendingApproval;
  showArguments: boolean;
  className?: string;
}) {
  let raw = "";
  if (showArguments) {
    try {
      raw = JSON.stringify(shownArguments(approval), null, 2) ?? "";
    } catch {
      raw = "";
    }
  }
  return (
    <details className={`text-xs ${className}`.trim()}>
      <summary className="cursor-pointer select-none w-fit" style={{ color: "var(--text-muted)" }}>
        Technical details
      </summary>
      <div className="mt-1.5 space-y-1.5" style={{ color: "var(--text-secondary)" }}>
        <p>
          Tool: <span className="mono-tag break-all">{approval.tool_name}</span>
        </p>
        {raw && (
          <pre
            className="p-2 rounded-[8px] overflow-x-auto whitespace-pre-wrap break-words"
            style={{ background: "var(--claw-surface)", border: "1px solid var(--claw-border)" }}
          >
            {raw}
          </pre>
        )}
      </div>
    </details>
  );
}
