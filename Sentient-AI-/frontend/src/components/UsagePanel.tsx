import type { ModelUsage, UsageSummary, UsageWindow } from "@/types";
import { formatCost, formatTokens } from "@/components/usageFormat";

const WINDOWS: { key: keyof UsageSummary["windows"]; label: string }[] = [
  { key: "today", label: "Today" },
  { key: "last_7_days", label: "Last 7 days" },
  { key: "last_30_days", label: "Last 30 days" },
  { key: "all_time", label: "All time" },
];

function costLine(window: UsageWindow): string {
  if (window.turns === 0) return "est. $0.00";
  if (window.estimated_cost_usd === null) return "est. cost unknown";
  const base = `est. ${formatCost(window.estimated_cost_usd)}`;
  // Partial: some turns were on a model with no known price, so the figure
  // is a floor, and saying so is the difference between an estimate and a
  // misleading one.
  return window.unpriced_turns > 0
    ? `${base} + ${window.unpriced_turns} unpriced`
    : base;
}

function modelLabel(row: ModelUsage): { name: string; detail: string } {
  if (!row.model) {
    return { name: "Model not recorded", detail: "earlier replies" };
  }
  return { name: row.model, detail: row.provider ?? "" };
}

function WindowTile({ label, window }: { label: string; window: UsageWindow }) {
  return (
    <div
      className="rounded-[10px] p-3 min-w-0"
      style={{
        background: "var(--claw-surface)",
        border: "1px solid var(--claw-border)",
      }}
    >
      <div className="eyebrow">{label}</div>
      <p
        className="mono-num text-lg font-semibold mt-1.5 break-words"
        style={{ color: "var(--text-primary)" }}
      >
        {formatTokens(window.total_tokens)}
        <span
          className="inline-block text-xs font-normal ml-1"
          style={{ color: "var(--text-muted)" }}
        >
          tokens
        </span>
      </p>
      <p className="text-xs mt-1 break-words" style={{ color: "var(--text-muted)" }}>
        {formatTokens(window.input_tokens)} in · {formatTokens(window.output_tokens)} out
      </p>
      <p className="text-xs mt-0.5 break-words" style={{ color: "var(--text-secondary)" }}>
        {costLine(window)}
      </p>
    </div>
  );
}

/**
 * Token usage across time windows plus a per-model breakdown. Every dollar
 * figure is labelled an estimate: it is list price times tokens, and the
 * provider's invoice is the real number.
 */
export default function UsagePanel({
  usage,
  loading,
}: {
  usage: UsageSummary | null;
  loading: boolean;
}) {
  const empty = usage !== null && usage.windows.all_time.turns === 0;
  return (
    <section
      aria-labelledby="usage-heading"
      className="rounded-[14px] p-5"
      style={{
        background: "var(--claw-panel)",
        border: "1px solid var(--claw-border)",
        boxShadow: "var(--shadow-card)",
      }}
    >
      <div className="eyebrow mb-1">Token usage</div>
      <h2 id="usage-heading" className="mb-4">
        Tokens &amp; estimated cost
      </h2>

      {loading && !usage && (
        <p role="status" className="text-sm" style={{ color: "var(--text-muted)" }}>
          Loading...
        </p>
      )}
      {!loading && !usage && (
        <p className="text-sm" style={{ color: "var(--text-muted)" }}>
          Usage could not be loaded.
        </p>
      )}
      {empty && (
        <p className="text-sm" style={{ color: "var(--text-muted)" }}>
          No token usage recorded yet. Counts appear after the assistant's
          next reply.
        </p>
      )}

      {usage && !empty && (
        <>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            {WINDOWS.map(({ key, label }) => (
              <WindowTile key={key} label={label} window={usage.windows[key]} />
            ))}
          </div>

          {usage.by_model.length > 0 && (
            // The table scrolls inside its own box on narrow screens; the
            // page itself never scrolls sideways.
            <div className="mt-5 overflow-x-auto">
              <table className="w-full min-w-[480px] text-sm">
                <caption className="sr-only">
                  All-time token usage by model, heaviest first. Costs are
                  estimates.
                </caption>
                <thead>
                  <tr style={{ borderBottom: "1px solid var(--border-subtle)" }}>
                    <th className="py-2 pr-3 text-left eyebrow">Model</th>
                    <th className="py-2 px-3 text-right eyebrow">Replies</th>
                    <th className="py-2 px-3 text-right eyebrow">Input</th>
                    <th className="py-2 px-3 text-right eyebrow">Output</th>
                    <th className="py-2 pl-3 text-right eyebrow">Est. cost</th>
                  </tr>
                </thead>
                <tbody>
                  {usage.by_model.map((row) => {
                    const { name, detail } = modelLabel(row);
                    return (
                      <tr
                        key={`${row.provider ?? ""}/${row.model ?? ""}`}
                        style={{ borderBottom: "1px solid var(--border-subtle)" }}
                      >
                        <td className="py-2 pr-3 min-w-0">
                          <span
                            className="mono-tag block truncate"
                            style={{ color: "var(--text-primary)" }}
                          >
                            {name}
                          </span>
                          {detail && (
                            <span className="text-xs" style={{ color: "var(--text-muted)" }}>
                              {detail}
                            </span>
                          )}
                        </td>
                        <td className="py-2 px-3 text-right mono-num">{formatTokens(row.turns)}</td>
                        <td className="py-2 px-3 text-right mono-num">
                          {formatTokens(row.input_tokens)}
                        </td>
                        <td className="py-2 px-3 text-right mono-num">
                          {formatTokens(row.output_tokens)}
                        </td>
                        <td className="py-2 pl-3 text-right mono-num">
                          {formatCost(row.estimated_cost_usd)}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}

          <p className="text-xs mt-4" style={{ color: "var(--text-muted)" }}>
            {usage.pricing_note}
          </p>
        </>
      )}
    </section>
  );
}
