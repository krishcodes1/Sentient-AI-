/**
 * PurchaseApproval: the body of a browser.checkout approval card — the screenshot of the checkout
 * page, the merchant, amount and item lines the toolkit read from it, the masked card that will
 * pay, and the notice that Crawler can make mistakes.
 *
 * Why it exists: A purchase is approved on what the page says, not on what the model said, so the
 * card lays out the page's facts at a glance instead of dumping the model's arguments as JSON.
 * Chat's ApprovalCard and Dashboard's ApprovalRow both render it directly above Approve / Deny.
 */

import { AlertTriangle } from "lucide-react";
import ApprovalPicture from "@/components/ApprovalPicture";
import type { PendingApproval } from "@/types";
import { approvalImage, purchaseCard } from "@/pages/approvalArguments";
import { PURCHASE_NOTICE } from "@/pages/purchaseNotice";

function formatAmount(amount: string, currency: string): string {
  return currency === "USD" ? `$${amount}` : `${amount} ${currency}`;
}

const factLabel = { color: "var(--text-muted)" };
const factValue = { color: "var(--text-primary)" };

export default function PurchaseApproval({ approval }: { approval: PendingApproval }) {
  const card = purchaseCard(approval);
  const image = approvalImage(approval);
  const note = approval.arguments?.note;

  if (!card) {
    // The backend always stores `_checkout` with a checkout card; a card
    // without it cannot be judged, so say so rather than show an empty form.
    return (
      <p role="alert" className="text-xs mb-3" style={{ color: "var(--accent-danger)" }}>
        This purchase request carries no page details. Deny it and ask Crawler
        to check out again.
      </p>
    );
  }

  return (
    <div className="space-y-3 mb-3">
      {image ? (
        <ApprovalPicture approval={approval} alt={`The checkout page on ${card.host}, as Crawler sees it`} />
      ) : (
        <p className="text-xs" style={{ color: "var(--text-muted)" }}>
          No screenshot came with this request — look at the browser window
          before you approve.
        </p>
      )}

      <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs items-baseline">
        <dt style={factLabel}>Pay</dt>
        <dd className="text-base font-semibold mono-num" style={factValue}>
          {formatAmount(card.amount_usd, card.currency)}
        </dd>
        <dt style={factLabel}>To</dt>
        <dd className="font-medium break-all" style={factValue}>
          {card.host}
        </dd>
        <dt style={factLabel}>With</dt>
        <dd style={factValue}>{card.card_label || "the stored card"}</dd>
      </dl>

      {card.items.length > 0 && (
        <ul className="list-disc pl-5 text-xs space-y-0.5" style={{ color: "var(--text-secondary)" }}>
          {card.items.map((line, i) => (
            <li key={i}>{line}</li>
          ))}
        </ul>
      )}

      {typeof note === "string" && note.trim() !== "" && (
        <p className="text-xs" style={{ color: "var(--text-secondary)" }}>
          Crawler&apos;s note: {note}
        </p>
      )}

      {/* Same danger styling as the risk warning: this is the last thing
          read on the way to Approve. */}
      <div
        className="flex items-start gap-2 p-2.5 rounded-[8px]"
        style={{ background: "var(--fill-danger)", border: "1px solid var(--border-danger)" }}
      >
        <AlertTriangle
          className="w-4 h-4 mt-0.5 shrink-0"
          style={{ color: "var(--accent-danger)" }}
          aria-hidden
        />
        <div className="min-w-0">
          <div className="eyebrow" style={{ color: "var(--accent-danger)" }}>
            Before you approve
          </div>
          <p className="text-xs mt-1" style={{ color: "var(--text-secondary)" }}>
            {card.notice || PURCHASE_NOTICE}
          </p>
        </div>
      </div>
    </div>
  );
}
