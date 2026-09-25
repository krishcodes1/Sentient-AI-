/**
 * shownArguments: the arguments an approval card displays, without the keys the backend reserves
 * for itself.
 *
 * Why it exists: A desktop.act approval also stores the screen it was made from under "_screen"
 * (set by the backend, never by the model), which means nothing to the person approving. Chat's
 * approval cards and Dashboard's approval rows both show arguments, so they share this rule.
 */

import type { PendingApproval } from "@/types";

// Only desktop.act has reserved keys: its toolkit refuses any argument no action takes, so a key
// starting with "_" there was added by the backend. Every other tool's arguments are shown whole,
// so nothing that will run is hidden from the person approving it.
export function shownArguments(approval: PendingApproval): Record<string, unknown> {
  const args = approval.arguments ?? {};
  if (approval.tool_name !== "desktop.act") return args;
  return Object.fromEntries(Object.entries(args).filter(([key]) => !key.startsWith("_")));
}
