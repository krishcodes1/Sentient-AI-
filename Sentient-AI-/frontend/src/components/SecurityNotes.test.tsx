/**
 * Tests for SecurityNotes: they prove it renders nothing for a card without notes, shows each note
 * in the server's order with its severity's styling (danger, warning, muted) under a "Security
 * notes" label, and shows a note's text as plain text, never as markup.
 *
 * Why it exists: the notes are what a call check noticed about the action the owner is about to
 * approve; a note that is not shown, shown out of order, or rendered as HTML (it can quote an
 * address someone else wrote) would mislead the person deciding.
 */

import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import SecurityNotes from "@/components/SecurityNotes";
import type { SecurityNote } from "@/types";

const NOTES: SecurityNote[] = [
  { kind: "link_dangerous", severity: "high", text: "Google Safe Browsing lists evil.example." },
  { kind: "recipient_first_time", severity: "warn", text: "First time Crawler sends to ann@example.com." },
  { kind: "recipients_resolved", severity: "info", text: "This reply goes to: ann@example.com." },
];

describe("SecurityNotes", () => {
  it.each([undefined, null, []])("renders nothing without notes (%j)", (notes) => {
    const { container } = render(<SecurityNotes notes={notes} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("shows each note with its severity styling in order", () => {
    render(<SecurityNotes notes={NOTES} />);
    const section = screen.getByRole("region", { name: "Security notes" });
    expect(within(section).getByText("Security notes")).toBeInTheDocument();
    const rows = within(section).getAllByRole("listitem");
    expect(rows.map((row) => row.textContent)).toEqual(NOTES.map((n) => n.text));
    expect(rows.map((row) => row.getAttribute("data-severity"))).toEqual(["high", "warn", "info"]);
    expect(rows[0]).toHaveStyle({ background: "var(--fill-danger)" });
    expect(rows[1]).toHaveStyle({ background: "var(--fill-warning)" });
    // An unknown severity reads as a warning, never as information.
    const odd = [{ kind: "x", severity: "severe", text: "Odd." }] as unknown as SecurityNote[];
    render(<SecurityNotes notes={odd} />);
    expect(screen.getByText("Odd.").closest("li")).toHaveAttribute("data-severity", "warn");
  });

  it("renders note text as plain text, never markup", () => {
    const text = '<img src=x onerror="alert(1)"> <b>bold</b> **stars**';
    const { container } = render(<SecurityNotes notes={[{ kind: "k", severity: "warn", text }]} />);
    expect(screen.getByText(text)).toBeInTheDocument();
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("b")).toBeNull();
  });
});
