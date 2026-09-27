/**
 * ApprovalPicture: the screenshot an approval card carries — the checkout page of a
 * browser.checkout card, or the page a browser.act step will run on with its target outlined in
 * red — rendered only when it is a base64 raster data URL.
 *
 * Why it exists: The owner approves a step on the page it will run on, so both kinds of browser
 * card show the same picture the same way (PurchaseApproval, and the browser.act card in Chat and
 * on the Dashboard); one component keeps the data-URL rule and the styling in one place.
 */

import type { PendingApproval } from "@/types";
import { approvalImage } from "@/pages/approvalArguments";

export default function ApprovalPicture({
  approval,
  alt,
  className = "",
}: {
  approval: PendingApproval;
  alt: string;
  className?: string;
}) {
  const image = approvalImage(approval);
  if (!image) return null;
  // Only a base64 raster data URL gets here (approvalImage), so the <img>
  // can never fetch from, or run anything for, the site.
  return (
    <img
      src={image}
      alt={alt}
      className={`w-full max-h-72 object-contain rounded-[8px] ${className}`.trim()}
      style={{ background: "var(--claw-surface)", border: "1px solid var(--claw-border)" }}
    />
  );
}
