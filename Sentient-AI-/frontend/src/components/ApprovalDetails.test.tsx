/**
 * Tests for the plain parts of a web approval card: ApprovalDetailList shows every value as a
 * labelled row, whole and with its line breaks (the server's `details`, or the arguments labelled
 * here for an older server); ApprovalAsk says "Okay to go ahead?" with the time left, or what to
 * do once the card ran out of time; ApprovalCheckCode is the quiet "Check code ..." line; and
 * ApprovalTechnicalDetails keeps the tool id and raw arguments in a closed disclosure.
 *
 * Why it exists: the card used to read "Tool google_workspace.send_email wants to run" over a JSON
 * dump. The person approving is not a developer (docs/bot-message-style.md), and they must still
 * see every value they approve, nothing cut (spec F3).
 */

import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import {
  ApprovalAsk,
  ApprovalCheckCode,
  ApprovalDetailList,
  ApprovalTechnicalDetails,
} from "@/components/ApprovalDetails";
import type { PendingApproval } from "@/types";

const BODY = "Hi Priya,\nare we still on for noon?\n\n" + "More words. ".repeat(400).trim();

const EMAIL: PendingApproval = {
  action_id: "a1",
  tool_name: "google_workspace.send_email",
  reason: "Send an email to priya@acme.com from your Gmail",
  arguments: { to: "priya@acme.com", subject: "Friday lunch", body: BODY },
  details: [
    { label: "To", value: "priya@acme.com" },
    { label: "Subject", value: "Friday lunch" },
    { label: "Message", value: BODY },
  ],
  check_code: "6d3b dfca 7bf8 cfc5",
  expires_at: "2099-01-01T00:00:00Z",
};

describe("ApprovalDetailList", () => {
  it("lists every value with its label, whole, line breaks kept", () => {
    render(<ApprovalDetailList approval={EMAIL} />);
    const list = document.querySelector('dl[aria-label="What this request will use"]') as HTMLElement;
    expect(within(list).getByText("To")).toBeInTheDocument();
    expect(within(list).getByText("priya@acme.com")).toBeInTheDocument();
    const message = within(list).getByText((_, el) => el?.tagName === "DD" && el.textContent === BODY);
    // Nothing clamps, clips or ellipsizes the value: pre-wrap shows every line.
    expect(message.className).toContain("whitespace-pre-wrap");
    expect(message.className).not.toMatch(/truncate|line-clamp|overflow-hidden/);
    expect(document.body.textContent).not.toContain("google_workspace");
    expect(document.body.textContent).not.toContain("{");
  });

  it("labels the arguments itself when an older server sent no details", () => {
    const old: PendingApproval = {
      ...EMAIL,
      details: undefined,
      arguments: { message_id: "m-1", permanent: false, labels: ["Work", "Later"] },
    };
    render(<ApprovalDetailList approval={old} />);
    expect(screen.getByText("Message ID")).toBeInTheDocument();
    expect(screen.getByText("m-1")).toBeInTheDocument();
    expect(screen.getByText("Permanent")).toBeInTheDocument();
    expect(screen.getByText("No")).toBeInTheDocument();
    expect(screen.getByText((_, el) => el?.tagName === "DD" && el.textContent === "Work\nLater")).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/[{}"]/);
  });

  it("renders nothing for a request with no values", () => {
    const { container } = render(<ApprovalDetailList approval={{ ...EMAIL, details: [], arguments: {} }} />);
    expect(container).toBeEmptyDOMElement();
  });
});

describe("ApprovalAsk", () => {
  it("asks with the time left in words", () => {
    render(<ApprovalAsk remaining={14 * 60 + 5} />);
    expect(screen.getByText(/Okay to go ahead\?/).textContent).toBe(
      "Okay to go ahead? This expires in 14 minutes.",
    );
  });

  it("just asks when the card has no deadline", () => {
    render(<ApprovalAsk remaining={null} />);
    expect(screen.getByText(/Okay to go ahead\?/).textContent).toBe("Okay to go ahead?");
  });

  it("says plainly what to do once the card ran out of time", () => {
    render(<ApprovalAsk remaining={0} />);
    expect(
      screen.getByText("This request ran out of time, so nothing was done. Ask Crawler again if you still want it."),
    ).toBeInTheDocument();
    expect(screen.queryByText(/Okay to go ahead/)).not.toBeInTheDocument();
  });
});

describe("ApprovalCheckCode", () => {
  it("shows the same check code the chat cards end with", () => {
    render(<ApprovalCheckCode approval={EMAIL} />);
    expect(screen.getByText(/Check code/).textContent).toBe("Check code 6d3b dfca 7bf8 cfc5");
  });

  it.each([undefined, null, "", "   "])("shows nothing when the server sent no code (%s)", (check_code) => {
    const { container } = render(<ApprovalCheckCode approval={{ ...EMAIL, check_code }} />);
    expect(container).toBeEmptyDOMElement();
  });
});

describe("ApprovalTechnicalDetails", () => {
  it("keeps the tool id and raw arguments in a closed disclosure", () => {
    render(<ApprovalTechnicalDetails approval={EMAIL} showArguments />);
    const disclosure = screen.getByText("Technical details").closest("details") as HTMLDetailsElement;
    expect(disclosure.open).toBe(false);
    expect(within(disclosure).getByText("google_workspace.send_email")).toBeInTheDocument();
    expect(disclosure.querySelector("pre")?.textContent).toBe(JSON.stringify(EMAIL.arguments, null, 2));
  });

  it("leaves a desktop.act card's stored screen out of the raw arguments", () => {
    const act: PendingApproval = {
      ...EMAIL,
      tool_name: "desktop.act",
      arguments: { action: "click", ref: "e12", _screen: { app: "Calendar", outline: "4be1c2" } },
    };
    render(<ApprovalTechnicalDetails approval={act} showArguments />);
    const raw = document.querySelector("pre")?.textContent ?? "";
    expect(raw).toContain('"ref": "e12"');
    expect(raw).not.toContain("_screen");
  });

  it("shows only the tool id when the card keeps its arguments out of view", () => {
    render(<ApprovalTechnicalDetails approval={{ ...EMAIL, tool_name: "browser.act" }} showArguments={false} />);
    expect(screen.getByText("browser.act")).toBeInTheDocument();
    expect(document.querySelector("pre")).toBeNull();
  });
});
