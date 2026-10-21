/**
 * Tests for ScamCheckTab (Security ▸ "Check for scams", every signed-in user): they prove the tab
 * shows the server's reason and no form when the check is off, that Check waits for text or a
 * picture and is locked while a check runs, that the pasted text and a picked screenshot go to the
 * server as a data URL and the verdict, reasons and advice come back, that links and the AI
 * provider's own reasons are plain text with no anchor anywhere, that a too-big or fifth picture is
 * refused in the browser with no request, that the picture controls are hidden when the provider
 * is blind, that only the owner gets the "Add a Safe Browsing key" button, that a 429's sentence is
 * shown with the text kept for a retry, that "no signs found" is never called safe, and that
 * "Check another" starts clean.
 *
 * Why it exists: this tab is where someone decides whether to trust a message. A clickable
 * scammer link, a verdict that sounds like "safe", an owner-only control shown to a member, or a
 * failed check that threw away what was pasted would each make the check do harm.
 */

import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ScamCheckResult, ScamCheckStatus } from "@/types";

vi.mock("@/services/api", () => {
  class ApiError extends Error {
    status: number;
    constructor(message: string, status: number) {
      super(message);
      this.status = status;
      this.name = "ApiError";
    }
  }
  return {
    ApiError,
    checkScam: vi.fn(),
    getScamCheckStatus: vi.fn(),
  };
});

import ScamCheckTab from "@/pages/security/ScamCheckTab";
import { MAX_SCAM_IMAGE_BYTES, MAX_SCAM_IMAGES } from "@/pages/security/scamVerdict";
import { ApiError, checkScam, getScamCheckStatus } from "@/services/api";

function status(overrides: Partial<ScamCheckStatus> = {}): ScamCheckStatus {
  return {
    effective: "on",
    reason: "",
    provider: "anthropic",
    sees_images: true,
    google_list: true,
    file_reputation: null,
    checks_per_day: 30,
    checks_used_today: 3,
    ...overrides,
  };
}

function answer(overrides: Partial<ScamCheckResult> = {}): ScamCheckResult {
  return {
    verdict: "likely_scam",
    headline: "Likely a scam",
    reasons: [
      "The link usps-redelivery-fee.top imitates usps.com but isn't it.",
      "It asks for a small fee to release a delivery.",
    ],
    ai_reasons: [],
    advice: [
      "Don't click links or scan QR codes in it.",
      "Don't pay or send card details from the message. Real companies and agencies don't ask for gift cards, crypto or wire transfers.",
    ],
    links: [],
    notes: [],
    qr: { present: false, readable: false },
    checked: { text_chars: 64, images: 1, links: 1, ai: true },
    conversation_id: "c-1",
    usage: { input_tokens: 3120, output_tokens: 180 },
    provider: "anthropic",
    model: "claude-test",
    cached: false,
    ...overrides,
  };
}

const PASTED = "Your package is on hold. Pay the 1.99 fee: https://usps-redelivery-fee.top/pay";

/** Four bytes of PNG header: enough for FileReader to produce a data URL. */
function pngFile(name = "shot.png") {
  return new File([Uint8Array.from([137, 80, 78, 71])], name, { type: "image/png" });
}

const box = () => screen.getByRole("textbox", { name: "Message, email or link" });
const checkButton = () => screen.getByRole("button", { name: /^Check$|^Checking/ });
const pictureInput = () => screen.getByLabelText("Screenshot to check");

async function renderTab(props: { isOwner?: boolean; onOpenKeys?: () => void } = {}) {
  const view = render(<ScamCheckTab isOwner={props.isOwner ?? false} onOpenKeys={props.onOpenKeys} />);
  await screen.findByRole("heading", { name: "Check for scams" });
  await waitFor(() => expect(screen.queryByText("Loading…")).not.toBeInTheDocument());
  return view;
}

afterEach(() => {
  vi.mocked(checkScam).mockReset();
  vi.mocked(getScamCheckStatus).mockReset();
});

describe("ScamCheckTab", () => {
  it("shows the reason and no form when scam checks are off", async () => {
    vi.mocked(getScamCheckStatus).mockResolvedValue(
      status({ effective: "off", reason: "The owner has turned off scam checks." }),
    );
    await renderTab({ isOwner: true, onOpenKeys: vi.fn() });

    expect(screen.getByText("The owner has turned off scam checks.")).toBeInTheDocument();
    expect(screen.queryByRole("textbox")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Check" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Add screenshot/ })).not.toBeInTheDocument();
  });

  it("shows the blocked reason and no form when scam checks are blocked", async () => {
    vi.mocked(getScamCheckStatus).mockResolvedValue(
      status({ effective: "blocked", reason: "Scam checks need an AI provider that is set up." }),
    );
    await renderTab();

    expect(screen.getByText("Scam checks need an AI provider that is set up.")).toBeInTheDocument();
    expect(screen.queryByRole("textbox")).not.toBeInTheDocument();
  });

  it("a failed status load shows the server's sentence with Retry, and Retry loads the form", async () => {
    vi.mocked(getScamCheckStatus)
      .mockRejectedValueOnce(new ApiError("The server is still starting.", 503))
      .mockResolvedValueOnce(status());
    const user = userEvent.setup();
    render(<ScamCheckTab isOwner={false} />);

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("The server is still starting.");
    await user.click(within(alert).getByRole("button", { name: "Retry" }));

    expect(await screen.findByRole("textbox", { name: "Message, email or link" })).toBeInTheDocument();
    expect(getScamCheckStatus).toHaveBeenCalledTimes(2);
  });

  it("keeps Check disabled until there is text or a picture and while a check runs", async () => {
    vi.mocked(getScamCheckStatus).mockResolvedValue(status());
    let finish: (value: ScamCheckResult) => void = () => {};
    vi.mocked(checkScam).mockImplementation(
      () => new Promise<ScamCheckResult>((resolve) => (finish = resolve)),
    );
    const user = userEvent.setup();
    await renderTab();

    expect(checkButton()).toBeDisabled();
    await user.type(box(), "   ");
    expect(checkButton()).toBeDisabled();
    await user.clear(box());

    // A picture on its own is enough.
    await user.upload(pictureInput(), pngFile());
    await screen.findByRole("img", { name: "shot.png" });
    expect(checkButton()).toBeEnabled();
    await user.click(screen.getByRole("button", { name: "Remove shot.png" }));
    expect(checkButton()).toBeDisabled();

    await user.type(box(), "is this real?");
    expect(checkButton()).toBeEnabled();
    await user.click(checkButton());

    const running = screen.getByRole("button", { name: "Checking… this can take up to a minute" });
    expect(running).toBeDisabled();
    expect(box()).toBeDisabled();
    expect(screen.getByRole("button", { name: /Add screenshot/ })).toBeDisabled();
    expect(checkScam).toHaveBeenCalledTimes(1);

    await act(async () => finish(answer()));
    expect(await screen.findByRole("heading", { name: "Likely a scam" })).toBeInTheDocument();
    expect(checkButton()).toHaveTextContent(/^Check$/);
  });

  it("sends the pasted text and the picked screenshot as a data URL and shows the verdict, reasons and advice", async () => {
    vi.mocked(getScamCheckStatus).mockResolvedValue(status());
    vi.mocked(checkScam).mockResolvedValue(answer());
    const user = userEvent.setup();
    await renderTab();

    await user.click(box());
    await user.paste(PASTED);
    await user.upload(pictureInput(), pngFile("text-message.png"));
    await screen.findByRole("img", { name: "text-message.png" });
    await user.click(checkButton());

    expect(checkScam).toHaveBeenCalledWith({
      text: PASTED,
      note: "",
      images: [{ media_type: "image/png", data: "data:image/png;base64,iVBORw==" }],
    });
    const heading = await screen.findByRole("heading", { name: "Likely a scam" });
    const result = heading.closest("section")!;
    expect(within(result).getByRole("heading", { name: "Why" })).toBeInTheDocument();
    expect(
      within(result).getByText("The link usps-redelivery-fee.top imitates usps.com but isn't it."),
    ).toBeInTheDocument();
    expect(within(result).getByText("It asks for a small fee to release a delivery.")).toBeInTheDocument();
    expect(within(result).getByRole("heading", { name: "What to do" })).toBeInTheDocument();
    expect(within(result).getByText("Don't click links or scan QR codes in it.")).toBeInTheDocument();
    expect(
      within(result).getByText('Checked: the text, 1 picture, 1 link. Saved in your "Scam checks" chat.'),
    ).toBeInTheDocument();
    // What was pasted stays in the box until "Check another".
    expect(box()).toHaveValue(PASTED);
  });

  it("sends the person's own note with the text", async () => {
    vi.mocked(getScamCheckStatus).mockResolvedValue(status());
    vi.mocked(checkScam).mockResolvedValue(answer());
    const user = userEvent.setup();
    await renderTab();

    await user.type(box(), "Pay now or lose your account");
    await user.type(screen.getByRole("textbox", { name: "Your note (optional)" }), "  from an unknown number ");
    await user.click(checkButton());

    expect(checkScam).toHaveBeenCalledWith({
      text: "Pay now or lose your account",
      note: "from an unknown number",
      images: [],
    });
  });

  it("refreshes the quota line after a check", async () => {
    vi.mocked(getScamCheckStatus)
      .mockResolvedValueOnce(status({ checks_used_today: 3 }))
      .mockResolvedValueOnce(status({ checks_used_today: 4 }));
    vi.mocked(checkScam).mockResolvedValue(answer());
    const user = userEvent.setup();
    await renderTab();

    expect(screen.getByText("3 of 30 checks used today")).toBeInTheDocument();
    await user.type(box(), "Pay now");
    await user.click(checkButton());

    expect(await screen.findByText("4 of 30 checks used today")).toBeInTheDocument();
    expect(getScamCheckStatus).toHaveBeenCalledTimes(2);
  });

  it("shows links as code text and never renders an anchor for them", async () => {
    vi.mocked(getScamCheckStatus).mockResolvedValue(status());
    vi.mocked(checkScam).mockResolvedValue(
      answer({
        links: [
          {
            shown: "https://xn--pypal-4ve.com/login",
            host: "xn--pypal-4ve.com",
            looks_like: "paypal.com",
            level: "malicious",
            checked_by: ["local", "safe_browsing"],
            origin: "text",
          },
          {
            shown: "http://203.0.113.9/pay",
            host: "203.0.113.9",
            looks_like: "",
            level: "suspicious",
            checked_by: ["local"],
            origin: "qr",
          },
        ],
      }),
    );
    const user = userEvent.setup();
    const { container } = await renderTab();

    await user.type(box(), "Confirm your account at https://xn--pypal-4ve.com/login");
    await user.click(checkButton());

    const list = await screen.findByRole("list", { name: "Links" });
    const rows = within(list).getAllByRole("listitem");
    expect(rows).toHaveLength(2);

    const code = within(rows[0]).getByText("https://xn--pypal-4ve.com/login");
    expect(code.tagName).toBe("CODE");
    expect(code.closest("a")).toBeNull();
    expect(rows[0]).toHaveTextContent(
      "known bad (imitates paypal.com) · checked by Crawler's lists, Google Safe Browsing · found in the text",
    );

    expect(within(rows[1]).getByText("http://203.0.113.9/pay").tagName).toBe("CODE");
    expect(rows[1]).toHaveTextContent("look-alike or risky · checked by Crawler's lists · found in a QR code");

    expect(container.querySelector("a")).toBeNull();
    expect(screen.queryAllByRole("link")).toHaveLength(0);
  });

  it("an AI reason holding https://x.example renders no anchor", async () => {
    vi.mocked(getScamCheckStatus).mockResolvedValue(status());
    vi.mocked(checkScam).mockResolvedValue(
      answer({ ai_reasons: ["The page at https://x.example asks for a [login](https://x.example)."] }),
    );
    const user = userEvent.setup();
    const { container } = await renderTab();

    await user.type(box(), "Log in here");
    await user.click(checkButton());

    const heading = await screen.findByRole("heading", { name: "Your AI provider also noted:" });
    const list = heading.parentElement!;
    // Shown exactly as sent, Markdown and all: plain text, not rendered markup.
    expect(
      within(list).getByText("The page at https://x.example asks for a [login](https://x.example)."),
    ).toBeInTheDocument();
    expect(container.querySelector("a")).toBeNull();
    expect(screen.queryAllByRole("link")).toHaveLength(0);
    // Kept apart from Crawler's own reasons.
    const why = screen.getByRole("heading", { name: "Why" }).parentElement!;
    expect(within(why).queryByText(/x\.example/)).not.toBeInTheDocument();
  });

  it("refuses a picture over 4 MB or a fifth picture with a plain line and makes no request", async () => {
    vi.mocked(getScamCheckStatus).mockResolvedValue(status());
    const user = userEvent.setup();
    await renderTab();

    const big = pngFile("huge.png");
    Object.defineProperty(big, "size", { value: MAX_SCAM_IMAGE_BYTES + 1 });
    await user.upload(pictureInput(), big);
    expect(await screen.findByRole("alert")).toHaveTextContent("huge.png is larger than 4 MB.");
    expect(screen.queryByRole("img")).not.toBeInTheDocument();

    await user.upload(
      pictureInput(),
      Array.from({ length: MAX_SCAM_IMAGES + 1 }, (_, i) => pngFile(`shot-${i}.png`)),
    );
    await waitFor(() => expect(screen.getAllByRole("img")).toHaveLength(MAX_SCAM_IMAGES));
    expect(screen.getByRole("alert")).toHaveTextContent(`Up to ${MAX_SCAM_IMAGES} pictures per check.`);
    expect(screen.queryByRole("img", { name: "shot-4.png" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Add screenshot/ })).toBeDisabled();
    expect(checkScam).not.toHaveBeenCalled();
  });

  it("hides the picture picker and explains when the AI provider cannot see pictures", async () => {
    vi.mocked(getScamCheckStatus).mockResolvedValue(status({ provider: "deepseek", sees_images: false }));
    await renderTab();

    expect(screen.queryByRole("button", { name: /Add screenshot/ })).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Screenshot to check")).not.toBeInTheDocument();
    expect(
      screen.getByText("Your AI provider (deepseek) can't look at pictures, so paste the text or the link."),
    ).toBeInTheDocument();
    expect(box()).toBeEnabled();
  });

  it("shows the own-lists line, and the Add key button only for the owner, when Google's list is not set up", async () => {
    vi.mocked(getScamCheckStatus).mockResolvedValue(status({ google_list: false }));
    const onOpenKeys = vi.fn();
    const user = userEvent.setup();
    const owner = await renderTab({ isOwner: true, onOpenKeys });

    expect(screen.getByText("Links are checked against Crawler's own lists.")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Add a Safe Browsing key" }));
    expect(onOpenKeys).toHaveBeenCalledTimes(1);
    owner.unmount();

    await renderTab({ isOwner: false, onOpenKeys: vi.fn() });
    expect(screen.getByText("Links are checked against Crawler's own lists.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Add a Safe Browsing key" })).not.toBeInTheDocument();
  });

  it("says nothing about Google's list when it is set up or the link check cannot say", async () => {
    vi.mocked(getScamCheckStatus).mockResolvedValue(status({ google_list: null }));
    const first = await renderTab({ isOwner: true, onOpenKeys: vi.fn() });
    expect(screen.queryByText("Links are checked against Crawler's own lists.")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Add a Safe Browsing key" })).not.toBeInTheDocument();
    first.unmount();

    vi.mocked(getScamCheckStatus).mockResolvedValue(status({ google_list: true }));
    await renderTab({ isOwner: true, onOpenKeys: vi.fn() });
    expect(screen.queryByRole("button", { name: "Add a Safe Browsing key" })).not.toBeInTheDocument();
  });

  it("shows the server's 429 sentence in an alert and keeps the text for a retry", async () => {
    vi.mocked(getScamCheckStatus).mockResolvedValue(status({ checks_used_today: 30 }));
    vi.mocked(checkScam)
      .mockRejectedValueOnce(
        new ApiError("You've used today's 30 scam checks. You can check again in 3 hours.", 429),
      )
      .mockResolvedValueOnce(answer());
    const user = userEvent.setup();
    await renderTab();

    await user.type(box(), "Claim your refund now");
    await user.upload(pictureInput(), pngFile());
    await screen.findByRole("img", { name: "shot.png" });
    await user.click(checkButton());

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "You've used today's 30 scam checks. You can check again in 3 hours.",
    );
    expect(box()).toHaveValue("Claim your refund now");
    expect(screen.getByRole("img", { name: "shot.png" })).toBeInTheDocument();
    expect(checkButton()).toBeEnabled();
    expect(screen.queryByRole("heading", { name: "Likely a scam" })).not.toBeInTheDocument();

    // The retry sends the same thing and clears the alert.
    await user.click(checkButton());
    expect(await screen.findByRole("heading", { name: "Likely a scam" })).toBeInTheDocument();
    expect(vi.mocked(checkScam).mock.calls[1][0]).toEqual(vi.mocked(checkScam).mock.calls[0][0]);
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it('labels no_signs_found as "No signs of a scam found" with the caveat, never as safe', async () => {
    vi.mocked(getScamCheckStatus).mockResolvedValue(status());
    vi.mocked(checkScam).mockResolvedValue(
      answer({
        verdict: "no_signs_found",
        // Whatever the server's headline says, the page uses its own fixed one.
        headline: "Safe",
        reasons: [],
        advice: [
          "No check can prove a message is safe. If it asks for money, a password or a code, check with the sender another way first.",
        ],
        checked: { text_chars: 20, images: 0, links: 0, ai: true },
      }),
    );
    const user = userEvent.setup();
    await renderTab();

    await user.type(box(), "See you at 6 tonight");
    await user.click(checkButton());

    const heading = await screen.findByRole("heading", { name: "No signs of a scam found" });
    expect(heading).not.toHaveTextContent(/safe/i);
    const result = heading.closest("section")!;
    expect(within(result).getByText("No check can prove a message is safe.")).toBeInTheDocument();
    expect(within(result).queryByText(/^safe$/i)).not.toBeInTheDocument();
    expect(within(result).queryByRole("heading", { name: "Why" })).not.toBeInTheDocument();
  });

  it("Check another clears the result and the pictures", async () => {
    vi.mocked(getScamCheckStatus).mockResolvedValue(status());
    vi.mocked(checkScam).mockResolvedValue(answer({ notes: ["The picture was read by your AI provider (anthropic)."] }));
    const user = userEvent.setup();
    await renderTab();

    await user.type(box(), "Your account is locked");
    await user.type(screen.getByRole("textbox", { name: "Your note (optional)" }), "email");
    await user.upload(pictureInput(), pngFile());
    await screen.findByRole("img", { name: "shot.png" });
    await user.click(checkButton());
    expect(await screen.findByText("The picture was read by your AI provider (anthropic).")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Check another" }));

    expect(screen.queryByRole("heading", { name: "Likely a scam" })).not.toBeInTheDocument();
    expect(screen.queryByRole("img")).not.toBeInTheDocument();
    expect(box()).toHaveValue("");
    expect(screen.getByRole("textbox", { name: "Your note (optional)" })).toHaveValue("");
    expect(checkButton()).toBeDisabled();
    expect(box()).toHaveFocus();
  });
});
