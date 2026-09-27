/**
 * PURCHASE_NOTICE: the one sentence every purchase approval card carries, on the web as in
 * Telegram.
 *
 * Why it exists: The backend owns the wording (NOTICE in services/tools/browser/checkout) and
 * publishes it as backend/tests/fixtures/purchase_notice.txt; this copy is what the web card shows
 * when a card arrives without one, and purchaseNotice.test.ts holds the two equal so the sentence
 * cannot drift between channels.
 */

export const PURCHASE_NOTICE =
  "Crawler can make mistakes. Check the amount and the site before you approve.";
