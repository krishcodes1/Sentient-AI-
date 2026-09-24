import type { Message } from "@/types";
import { conversationTotals, formatTokens, hasUsage } from "@/components/usageFormat";

/**
 * "1,234 in · 56 out" under an assistant reply, plus " (1,024 cached)" when
 * part of the prompt came from the provider's cache — "in" is the whole
 * prompt, and cached input bills at a fraction of the rate, so without the
 * note a big warm-cache prompt reads as a big bill. Renders nothing when
 * the turn reported no counts — a caption of "0 in · 0 out" would present
 * an unknown as a measurement.
 */
export function MessageTokenCaption({ message }: { message: Message }) {
  if (message.role !== "assistant" || message.error || !hasUsage(message)) {
    return null;
  }
  const input = message.input_tokens ?? 0;
  const output = message.output_tokens ?? 0;
  const cached = message.cache_read_tokens ?? 0;
  const model = message.llm_model ? ` on ${message.llm_model}` : "";
  return (
    <span
      className="mono-tag block mt-1"
      style={{ color: "var(--text-muted)" }}
      title={`Tokens used for this reply${model}`}
    >
      <span className="sr-only">Tokens used: </span>
      {formatTokens(input)} in · {formatTokens(output)} out
      {cached > 0 && ` (${formatTokens(cached)} cached)`}
    </span>
  );
}

/** Running total for the open thread, summed from the loaded messages so it
 *  moves the moment a streamed reply is saved. */
export function ConversationTokenTotal({ messages }: { messages: Message[] }) {
  const { input, output, turns } = conversationTotals(messages);
  if (turns === 0) return null;
  return (
    <span
      className="mono-tag shrink-0 whitespace-nowrap"
      style={{ color: "var(--text-muted)" }}
      title={`${formatTokens(input)} in · ${formatTokens(output)} out across ${turns} ${
        turns === 1 ? "reply" : "replies"
      }`}
    >
      <span className="sr-only">Conversation total: </span>
      {formatTokens(input + output)} tokens
    </span>
  );
}
