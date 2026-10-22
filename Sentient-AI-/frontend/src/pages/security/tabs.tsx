/**
 * The Security page's tab registry: every tab's id, label, whether only the owner sees it, and
 * how it renders, in the order the page shows them.
 *
 * Why it exists: nine skills each own one tab, and none of them edits the page shell. The list
 * lives in this component-free module (types and one constant, no component of its own) so
 * Security.tsx exports only its default component, which the react-refresh lint rule requires,
 * and the page's test can assert the order against the same list. The ids are the `?tab=` values
 * other pages link to (`/security?tab=mcp`, `/security?tab=keys`), so they never change.
 */

import type { ReactNode } from "react";
import BreachMonitorTab from "@/pages/security/BreachMonitorTab";
import FileChecksTab from "@/pages/security/FileChecksTab";
import MailAlertsTab from "@/pages/security/MailAlertsTab";
import McpReviewsTab from "@/pages/security/McpReviewsTab";
import OutgoingMessagesTab from "@/pages/security/OutgoingMessagesTab";
import ScamCheckTab from "@/pages/security/ScamCheckTab";
import ServiceKeysTab from "@/pages/security/ServiceKeysTab";
import SiteRulesTab from "@/pages/security/SiteRulesTab";
import ToolRulesTab from "@/pages/security/ToolRulesTab";

export type SecurityTabId =
  | "mail"
  | "scam-check"
  | "outgoing"
  | "files"
  | "breach"
  | "mcp"
  | "site-rules"
  | "tool-rules"
  | "keys";

/** What the page hands each tab: whether the viewer is the owner, and a way to open another
 *  tab (a "missing key" prompt opens Service keys). */
export interface SecurityTabContext {
  isOwner: boolean;
  openTab: (id: SecurityTabId) => void;
}

export interface SecurityTabSpec {
  id: SecurityTabId;
  label: string;
  /** Hidden from everyone but the owner, and never mounted for them. */
  ownerOnly: boolean;
  render: (ctx: SecurityTabContext) => ReactNode;
}

export const SECURITY_TABS: SecurityTabSpec[] = [
  // S2
  { id: "mail", label: "Mail alerts", ownerOnly: false, render: (c) => <MailAlertsTab isOwner={c.isOwner} /> },
  // S3
  {
    id: "scam-check",
    label: "Check for scams",
    ownerOnly: false,
    render: (c) => <ScamCheckTab isOwner={c.isOwner} onOpenKeys={() => c.openTab("keys")} />,
  },
  // S1
  {
    id: "outgoing",
    label: "Outgoing messages",
    ownerOnly: false,
    render: (c) => <OutgoingMessagesTab isOwner={c.isOwner} />,
  },
  // S10
  {
    id: "files",
    label: "File checks",
    ownerOnly: false,
    render: (c) => <FileChecksTab isOwner={c.isOwner} onOpenKeys={() => c.openTab("keys")} />,
  },
  // S6
  {
    id: "breach",
    label: "Breach monitor",
    ownerOnly: false,
    render: (c) => <BreachMonitorTab isOwner={c.isOwner} onOpenKeys={() => c.openTab("keys")} />,
  },
  // S5
  { id: "mcp", label: "MCP reviews", ownerOnly: false, render: () => <McpReviewsTab /> },
  // S7
  { id: "site-rules", label: "Site rules", ownerOnly: true, render: () => <SiteRulesTab /> },
  // S9
  { id: "tool-rules", label: "Tool rules", ownerOnly: true, render: () => <ToolRulesTab /> },
  // S4
  { id: "keys", label: "Service keys", ownerOnly: true, render: () => <ServiceKeysTab /> },
];
