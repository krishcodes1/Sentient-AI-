import type { Message } from "@/types";

// Fixed locale: token counts are read side by side with the Telegram /usage
// reply and the API, and a thousands separator that changed with the
// browser's locale would make the same number look different in each.
const tokenFormat = new Intl.NumberFormat("en-US");

export function formatTokens(n: number): string {
  return tokenFormat.format(n);
}

/**
 * An estimated USD amount. Sub-cent spend is common (a short chat on a
 * flash-tier model costs fractions of a cent), and "$0.00" would read as
 * free, so it is shown as "<$0.01" instead.
 */
export function formatCost(cost: number | null): string {
  if (cost === null) return "unknown";
  if (cost === 0) return "$0.00";
  if (cost < 0.01) return "<$0.01";
  return `$${cost.toFixed(2)}`;
}

/** True when the turn reported usage at all — null is "never found out". */
export function hasUsage(message: Pick<Message, "input_tokens" | "output_tokens">): boolean {
  return message.input_tokens != null || message.output_tokens != null;
}

export function conversationTotals(messages: Message[]): {
  input: number;
  output: number;
  turns: number;
} {
  let input = 0;
  let output = 0;
  let turns = 0;
  for (const m of messages) {
    if (m.role !== "assistant" || !hasUsage(m)) continue;
    input += m.input_tokens ?? 0;
    output += m.output_tokens ?? 0;
    turns += 1;
  }
  return { input, output, turns };
}
