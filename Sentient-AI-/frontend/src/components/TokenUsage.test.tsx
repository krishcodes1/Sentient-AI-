import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ConversationTokenTotal, MessageTokenCaption } from "@/components/TokenUsage";
import { formatCost } from "@/components/usageFormat";
import type { Message } from "@/types";

function message(overrides: Partial<Message> = {}): Message {
  return {
    id: "m1",
    conversation_id: "c1",
    role: "assistant",
    content: "hi",
    created_at: "2026-09-23T12:00:00Z",
    ...overrides,
  };
}

describe("MessageTokenCaption", () => {
  it("shows input and output counts with thousands separators", () => {
    render(
      <MessageTokenCaption
        message={message({ input_tokens: 1234, output_tokens: 56, llm_model: "gemini-2.5-flash" })}
      />,
    );
    const caption = screen.getByText(/1,234 in · 56 out/);
    expect(caption).toHaveAttribute("title", "Tokens used for this reply on gemini-2.5-flash");
    // Themed through the muted token, never a fixed color.
    expect(caption.getAttribute("style")).toContain("var(--text-muted)");
  });

  it("notes the cached share of the prompt when there is one", () => {
    render(
      <MessageTokenCaption
        message={message({ input_tokens: 12000, output_tokens: 80, cache_read_tokens: 10240 })}
      />,
    );
    expect(screen.getByText(/12,000 in · 80 out \(10,240 cached\)/)).toBeInTheDocument();
  });

  it("leaves the caption unchanged when nothing was cached", () => {
    render(
      <MessageTokenCaption
        message={message({ input_tokens: 500, output_tokens: 9, cache_read_tokens: 0 })}
      />,
    );
    const caption = screen.getByText(/500 in · 9 out/);
    expect(caption.textContent).not.toContain("cached");
  });

  it("renders nothing when the turn reported no usage", () => {
    // Null is "never found out" — a 0 in · 0 out caption would misstate it.
    const { container } = render(
      <MessageTokenCaption message={message({ input_tokens: null, output_tokens: null })} />,
    );
    expect(container).toBeEmptyDOMElement();
  });

  it("renders nothing on user turns and failed bubbles", () => {
    const { container } = render(
      <>
        <MessageTokenCaption
          message={message({ role: "user", input_tokens: 5, output_tokens: 1 })}
        />
        <MessageTokenCaption
          message={message({ error: true, input_tokens: 5, output_tokens: 1 })}
        />
      </>,
    );
    expect(container).toBeEmptyDOMElement();
  });
});

describe("ConversationTokenTotal", () => {
  it("sums every assistant turn that reported usage", () => {
    render(
      <ConversationTokenTotal
        messages={[
          message({ id: "u", role: "user" }),
          message({ id: "a1", input_tokens: 1000, output_tokens: 20 }),
          message({ id: "a2", input_tokens: null, output_tokens: null }),
          message({ id: "a3", input_tokens: 2000, output_tokens: 34 }),
        ]}
      />,
    );
    const total = screen.getByText(/3,054 tokens/);
    expect(total).toHaveAttribute("title", "3,000 in · 54 out across 2 replies");
  });

  it("is absent for a thread with no counted turns", () => {
    const { container } = render(
      <ConversationTokenTotal messages={[message({ role: "user" })]} />,
    );
    expect(container).toBeEmptyDOMElement();
  });
});

describe("formatCost", () => {
  it("never rounds a real sub-cent cost down to free", () => {
    expect(formatCost(0.0004)).toBe("<$0.01");
    expect(formatCost(0)).toBe("$0.00");
    expect(formatCost(1.234)).toBe("$1.23");
    expect(formatCost(null)).toBe("unknown");
  });
});
