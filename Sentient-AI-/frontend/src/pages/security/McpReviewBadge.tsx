/**
 * McpReviewBadge: the chip on an MCP connector's card (Connectors page) that says how many of that
 * server's tools wait for the owner's review, with a link to Security ▸ MCP reviews.
 *
 * Why it exists: when an MCP server changes what a tool says it does, or adds a tool, Crawler stops
 * offering that tool to the AI until the owner approves the exact new version. The Connectors page
 * is where people look at their servers, so the hold is pointed out there too. The chip only ever
 * shows a count: the changed text itself is shown on the Security page, beside its diff. It says
 * nothing when nothing waits, when holding is switched off, or when the server is older and has no
 * MCP reviews (404), so it never adds noise or an error to the card.
 */

import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ShieldAlert } from "lucide-react";
import { getMcpReviews } from "@/services/api";

export default function McpReviewBadge({ connectorId }: { connectorId: string }) {
  // null until the answer arrives; stays null on any failure, so the card shows nothing.
  const [waiting, setWaiting] = useState<number | null>(null);

  useEffect(() => {
    let cancelled = false;
    getMcpReviews(connectorId)
      .then((list) => {
        if (cancelled) return;
        // Held tools are offered as they are while holding is off, so a count would be wrong.
        if (!list.pinning_enabled) return;
        const server = list.servers.find((row) => row.connector_id === connectorId);
        setWaiting(server ? server.needs_review_count : 0);
      })
      .catch(() => {
        // A 404 (an older server, or not this user's MCP connector) or any other failure: the
        // card already reports the connection's own health, so the chip stays silent.
      });
    return () => {
      cancelled = true;
    };
  }, [connectorId]);

  if (!waiting) return null;

  return (
    <p
      className="mt-2 inline-flex flex-wrap items-center gap-1.5 px-2.5 py-1 rounded-[8px] text-xs font-medium"
      style={{
        background: "var(--fill-warning)",
        border: "1px solid var(--border-warning)",
        color: "var(--accent-warning)",
      }}
    >
      <ShieldAlert className="w-3.5 h-3.5 shrink-0" aria-hidden />
      <span>
        {waiting} {waiting === 1 ? "tool needs" : "tools need"} your review
      </span>
      <Link to="/security?tab=mcp" className="underline font-semibold">
        Review
      </Link>
    </p>
  );
}
