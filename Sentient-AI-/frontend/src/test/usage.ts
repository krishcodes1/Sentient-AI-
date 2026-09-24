import type { UsageSummary, UsageWindow } from "@/types";

/**
 * A realistic GET /usage/summary body: a priced week, a partly priced
 * month and an all-time window whose every turn predates model tracking,
 * so each honesty rule in the UI has something to act on.
 */
export function usageWindow(overrides: Partial<UsageWindow> = {}): UsageWindow {
  return {
    input_tokens: 0,
    output_tokens: 0,
    total_tokens: 0,
    turns: 0,
    estimated_cost_usd: 0,
    unpriced_turns: 0,
    ...overrides,
  };
}

export function usageSummary(overrides: Partial<UsageSummary> = {}): UsageSummary {
  return {
    windows: {
      today: usageWindow({
        input_tokens: 1234,
        output_tokens: 56,
        total_tokens: 1290,
        turns: 1,
        estimated_cost_usd: 0.0005102,
      }),
      last_7_days: usageWindow({
        input_tokens: 20000,
        output_tokens: 1500,
        total_tokens: 21500,
        turns: 6,
        estimated_cost_usd: 0.25,
      }),
      last_30_days: usageWindow({
        input_tokens: 90000,
        output_tokens: 9000,
        total_tokens: 99000,
        turns: 20,
        estimated_cost_usd: 1.5,
        unpriced_turns: 3,
      }),
      all_time: usageWindow({
        input_tokens: 120000,
        output_tokens: 10000,
        total_tokens: 130000,
        turns: 30,
        estimated_cost_usd: null,
        unpriced_turns: 30,
      }),
    },
    by_model: [
      {
        provider: "gemini",
        model: "gemini-2.5-flash",
        input_tokens: 100000,
        output_tokens: 9000,
        total_tokens: 109000,
        turns: 25,
        estimated_cost_usd: 0.0525,
      },
      {
        provider: null,
        model: null,
        input_tokens: 20000,
        output_tokens: 1000,
        total_tokens: 21000,
        turns: 5,
        estimated_cost_usd: null,
      },
    ],
    currency: "USD",
    pricing_note: "Estimated from list prices as of 2026-09-23.",
    ...overrides,
  };
}
