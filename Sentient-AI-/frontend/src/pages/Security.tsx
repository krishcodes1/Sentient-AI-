/**
 * The Security page (/security): one tab per security check Crawler runs for you, chosen with
 * `?tab=<id>` so other pages and messages can link straight to one (`/security?tab=mcp`). Every
 * signed-in person sees their own mail alerts, scam checks, outgoing-message checks, file checks,
 * breach monitor and MCP reviews; only the owner also sees site rules, tool rules and service keys.
 *
 * Why it exists: the security checks share one place to look and one place to configure, and
 * each skill owns only its tab. The tab list is pages/security/tabs.tsx, so this file holds only
 * the shell: who is viewing (getMe, once), which tabs they may see, which one is open, and a
 * tablist that scrolls inside itself so nine labels never widen a phone screen. A member never
 * mounts an owner-only tab, so its owner-only requests are never made.
 */

import { useCallback, useEffect, useRef, useState, type KeyboardEvent } from "react";
import { useSearchParams } from "react-router-dom";
import { Loader2 } from "lucide-react";
import { getMe } from "@/services/api";
import { ErrorAlert } from "@/components/FormFeedback";
import { errorText, panelStyle, secondaryCls, secondaryStyle } from "@/components/formStyles";
import { SECURITY_TABS, type SecurityTabId } from "@/pages/security/tabs";

type Viewer =
  | { state: "loading" }
  | { state: "error"; message: string }
  | { state: "ready"; isOwner: boolean };

const PANEL_ID = "security-tabpanel";
const tabElementId = (id: SecurityTabId) => `security-tab-${id}`;

export default function Security() {
  const [viewer, setViewer] = useState<Viewer>({ state: "loading" });
  const [attempt, setAttempt] = useState(0);
  const [params, setParams] = useSearchParams();
  const tabButtons = useRef(new Map<SecurityTabId, HTMLButtonElement>());

  useEffect(() => {
    let cancelled = false;
    getMe()
      .then((user) => {
        if (!cancelled) setViewer({ state: "ready", isOwner: user.is_admin === true });
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setViewer({ state: "error", message: errorText(err, "Your account could not be loaded.") });
        }
      });
    return () => {
      cancelled = true;
    };
  }, [attempt]);

  const isOwner = viewer.state === "ready" && viewer.isOwner;
  // No tab at all until the viewer is known: an owner-only tab must never mount for a member,
  // not even for the moment before getMe answers.
  const visible = viewer.state === "ready" ? SECURITY_TABS.filter((tab) => isOwner || !tab.ownerOnly) : [];
  const requested = params.get("tab");
  const active = visible.find((tab) => tab.id === requested) ?? visible[0];
  const activeId = active?.id;

  const openTab = useCallback(
    (id: SecurityTabId) => {
      setParams(
        (previous) => {
          const next = new URLSearchParams(previous);
          next.set("tab", id);
          return next;
        },
        // Switching tabs is not a new page: Back leaves the Security page instead of walking
        // back through every tab that was looked at.
        { replace: true },
      );
    },
    [setParams],
  );

  // The tablist scrolls sideways on a narrow screen, so bring the open tab into view (also when
  // ?tab= opened one past the edge). An optional call: jsdom has no scrollIntoView.
  useEffect(() => {
    if (!activeId) return;
    tabButtons.current.get(activeId)?.scrollIntoView?.({ block: "nearest", inline: "nearest" });
  }, [activeId]);

  // Arrow keys, Home and End move between tabs, as a tablist does everywhere else.
  function onTabKey(event: KeyboardEvent<HTMLDivElement>) {
    const index = visible.findIndex((tab) => tab.id === activeId);
    if (index < 0) return;
    let next = -1;
    if (event.key === "ArrowRight") next = (index + 1) % visible.length;
    else if (event.key === "ArrowLeft") next = (index - 1 + visible.length) % visible.length;
    else if (event.key === "Home") next = 0;
    else if (event.key === "End") next = visible.length - 1;
    if (next < 0) return;
    event.preventDefault();
    const id = visible[next].id;
    openTab(id);
    tabButtons.current.get(id)?.focus();
  }

  return (
    <div className="space-y-6">
      <div>
        <div className="eyebrow mb-2">Protection</div>
        <h1 style={{ color: "var(--text-primary)" }}>Security</h1>
        <p className="text-sm mt-1.5 max-w-2xl" style={{ color: "var(--text-secondary)" }}>
          What Crawler checks for you: email and messages that look like scams, who outgoing
          messages go to, files, breached addresses, and MCP tools that changed. Anything a check
          suggests doing still waits for your approval.
        </p>
      </div>

      {viewer.state === "loading" && (
        <p role="status" className="inline-flex items-center gap-2 text-sm" style={{ color: "var(--text-muted)" }}>
          <Loader2 className="w-4 h-4 animate-spin" aria-hidden />
          Loading…
        </p>
      )}

      {viewer.state === "error" && (
        <div>
          <ErrorAlert>{viewer.message}</ErrorAlert>
          <button
            type="button"
            className={secondaryCls}
            style={secondaryStyle}
            onClick={() => {
              setViewer({ state: "loading" });
              setAttempt((n) => n + 1);
            }}
          >
            Retry
          </button>
        </div>
      )}

      {active && (
        <div className="space-y-4">
          <div
            role="tablist"
            aria-label="Security sections"
            className="flex overflow-x-auto whitespace-nowrap gap-1 p-1 rounded-[12px]"
            style={{ border: "1px solid var(--claw-border)", backgroundColor: "var(--claw-surface)" }}
            onKeyDown={onTabKey}
          >
            {visible.map((tab) => {
              const selected = tab.id === activeId;
              return (
                <button
                  key={tab.id}
                  ref={(element) => {
                    if (element) tabButtons.current.set(tab.id, element);
                    else tabButtons.current.delete(tab.id);
                  }}
                  type="button"
                  role="tab"
                  id={tabElementId(tab.id)}
                  aria-selected={selected}
                  aria-controls={PANEL_ID}
                  tabIndex={selected ? 0 : -1}
                  onClick={() => openTab(tab.id)}
                  className="shrink-0 px-3.5 rounded-[9px] text-sm transition-colors"
                  style={{
                    minHeight: 44,
                    // backgroundColor, not the `background` shorthand: jsdom cannot re-parse a
                    // shorthand holding a var() when it computes an accessible name.
                    backgroundColor: selected ? "var(--claw-surface-active)" : "transparent",
                    border: `1px solid ${selected ? "var(--claw-border)" : "transparent"}`,
                    color: selected ? "var(--text-primary)" : "var(--text-secondary)",
                    fontWeight: selected ? 500 : 400,
                  }}
                >
                  {tab.label}
                </button>
              );
            })}
          </div>

          <div
            key={active.id}
            role="tabpanel"
            id={PANEL_ID}
            aria-labelledby={tabElementId(active.id)}
            className="p-5 rounded-[14px]"
            style={panelStyle}
          >
            {active.render({ isOwner, openTab })}
          </div>
        </div>
      )}
    </div>
  );
}
