/**
 * TabBar: a horizontal tablist that scrolls inside itself on a narrow screen, with arrow keys,
 * Home and End moving between tabs.
 *
 * Why it exists: the Security and Settings pages both split long pages into tabs, and two copies
 * of the keyboard handling and scroll-into-view would drift apart.
 */

import { useEffect, useRef, type KeyboardEvent } from "react";

export interface TabBarProps<T extends string> {
  tabs: readonly { id: T; label: string }[];
  activeId: T | undefined;
  onSelect: (id: T) => void;
  /** The tablist's accessible name. */
  label: string;
  /** The id of the tabpanel every tab controls. */
  panelId: string;
  /** The DOM id of a tab's button, for the panel's aria-labelledby. */
  tabId: (id: T) => string;
}

export default function TabBar<T extends string>({ tabs, activeId, onSelect, label, panelId, tabId }: TabBarProps<T>) {
  const buttons = useRef(new Map<T, HTMLButtonElement>());

  // Bring the open tab into view (also when ?tab= opened one past the edge). An optional call:
  // jsdom has no scrollIntoView.
  useEffect(() => {
    if (activeId) buttons.current.get(activeId)?.scrollIntoView?.({ block: "nearest", inline: "nearest" });
  }, [activeId]);

  function onKey(event: KeyboardEvent<HTMLDivElement>) {
    const index = tabs.findIndex((tab) => tab.id === activeId);
    if (index < 0) return;
    let next = -1;
    if (event.key === "ArrowRight") next = (index + 1) % tabs.length;
    else if (event.key === "ArrowLeft") next = (index - 1 + tabs.length) % tabs.length;
    else if (event.key === "Home") next = 0;
    else if (event.key === "End") next = tabs.length - 1;
    if (next < 0) return;
    event.preventDefault();
    onSelect(tabs[next].id);
    buttons.current.get(tabs[next].id)?.focus();
  }

  return (
    <div
      role="tablist"
      aria-label={label}
      className="flex overflow-x-auto whitespace-nowrap gap-1 p-1 rounded-[12px]"
      style={{ border: "1px solid var(--claw-border)", backgroundColor: "var(--claw-surface)" }}
      onKeyDown={onKey}
    >
      {tabs.map((tab) => {
        const selected = tab.id === activeId;
        return (
          <button
            key={tab.id}
            ref={(element) => {
              if (element) buttons.current.set(tab.id, element);
              else buttons.current.delete(tab.id);
            }}
            type="button"
            role="tab"
            id={tabId(tab.id)}
            aria-selected={selected}
            aria-controls={panelId}
            tabIndex={selected ? 0 : -1}
            onClick={() => onSelect(tab.id)}
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
  );
}
