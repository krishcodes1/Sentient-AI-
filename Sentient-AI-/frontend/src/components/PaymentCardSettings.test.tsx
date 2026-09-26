/**
 * Tests for PaymentCardSettings: they prove the stored card is shown masked with empty entry
 * fields, the form posts the entered values exactly once and clears them, a slip is caught before
 * anything is sent, a 422 is shown inline with the form kept, an install without a vault (the
 * list's `available: false`, or a 409 on save) shows the server's reason instead of the form, and
 * Delete asks first.
 *
 * Why it exists: Guards against the number ever being rendered back, sent twice or kept in the
 * form after a save, and against offering a form on an install that cannot store a card (the
 * container's GET /vault/items is a 200 with `available: false`, never a 409).
 */

import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { VaultItemView } from "@/types";

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
    getVaultItems: vi.fn(async () => ({ items: [], available: true, reason: "" })),
    saveVaultCard: vi.fn(),
    deleteVaultItem: vi.fn(),
  };
});

import PaymentCardSettings from "@/components/PaymentCardSettings";
import { ApiError, deleteVaultItem, getVaultItems, saveVaultCard } from "@/services/api";

/** GET /vault/items as the server answers it on a Mac or PC. */
function vaultItems(items: VaultItemView[] = []) {
  return { items, available: true, reason: "" };
}

const STORED: VaultItemView = {
  id: "v1",
  kind: "card",
  label: "Personal card",
  origins: [],
  masked: "Visa ····4242",
  brand: "Visa",
  last4: "4242",
  created_at: "2026-09-25T00:00:00Z",
  last_used_at: null,
};

const CONTAINER_REASON = "The card vault is not available in this environment (container).";

async function fillForm() {
  fireEvent.change(await screen.findByLabelText("Card number"), {
    target: { value: "4242 4242 4242 4242" },
  });
  fireEvent.change(screen.getByLabelText("Expiry (MM/YY)"), { target: { value: "12/30" } });
  fireEvent.change(screen.getByLabelText("CVC"), { target: { value: "123" } });
  fireEvent.change(screen.getByLabelText("Name on card"), { target: { value: "Ada Lovelace" } });
}

describe("PaymentCardSettings", () => {
  beforeEach(() => {
    vi.mocked(getVaultItems).mockResolvedValue(vaultItems());
  });

  it("shows the stored card masked, with empty entry fields and never a number", async () => {
    vi.mocked(getVaultItems).mockResolvedValue(vaultItems([STORED]));
    render(<PaymentCardSettings />);

    expect(await screen.findByText("Visa ····4242")).toBeInTheDocument();
    expect(screen.getByText(/Personal card/)).toBeInTheDocument();
    expect(screen.getByLabelText("Card number")).toHaveValue("");
    expect(screen.getByLabelText("CVC")).toHaveValue("");
    // Only the last four digits are anywhere on the page.
    expect(document.body.textContent).not.toMatch(/\d{5,}/);
    expect(screen.getByRole("button", { name: "Replace card" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Delete" })).toBeInTheDocument();
  });

  it("offers to add a card when none is stored", async () => {
    render(<PaymentCardSettings />);
    expect(await screen.findByText(/no card is stored/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save card" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Delete" })).not.toBeInTheDocument();
  });

  it("posts the entered card once, clears the fields and shows the masked result", async () => {
    vi.mocked(saveVaultCard).mockResolvedValue(STORED);
    render(<PaymentCardSettings />);
    await fillForm();
    // The brand hint comes from the leading digit, before anything is sent.
    expect(screen.getByText("Visa")).toBeInTheDocument();
    expect(saveVaultCard).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole("button", { name: "Save card" }));

    expect(await screen.findByText("Saved Visa ····4242.")).toBeInTheDocument();
    expect(saveVaultCard).toHaveBeenCalledTimes(1);
    expect(saveVaultCard).toHaveBeenCalledWith({
      number: "4242424242424242",
      exp_month: 12,
      exp_year: 2030,
      cvc: "123",
      name: "Ada Lovelace",
    });
    expect(screen.getByLabelText("Card number")).toHaveValue("");
    expect(screen.getByLabelText("Expiry (MM/YY)")).toHaveValue("");
    expect(screen.getByLabelText("CVC")).toHaveValue("");
    expect(screen.getByLabelText("Name on card")).toHaveValue("");
    expect(screen.getByText("Visa ····4242")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Replace card" })).toBeInTheDocument();
  });

  it("catches a slip before the card leaves the page", async () => {
    render(<PaymentCardSettings />);
    await fillForm();
    fireEvent.change(screen.getByLabelText("Expiry (MM/YY)"), { target: { value: "13/30" } });
    fireEvent.click(screen.getByRole("button", { name: "Save card" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Enter the expiry as MM/YY.");
    expect(saveVaultCard).not.toHaveBeenCalled();
    // What was typed stays, so it can be corrected.
    expect(screen.getByLabelText("Card number")).toHaveValue("4242 4242 4242 4242");
  });

  it("shows the server's 422 and keeps the form", async () => {
    vi.mocked(saveVaultCard).mockRejectedValue(new ApiError("That card number is not valid.", 422));
    render(<PaymentCardSettings />);
    await fillForm();
    fireEvent.click(screen.getByRole("button", { name: "Save card" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("That card number is not valid.");
    expect(screen.getByLabelText("Card number")).toBeInTheDocument();
  });

  it("shows the server's 409 reason instead of the form on an install without a vault", async () => {
    vi.mocked(saveVaultCard).mockRejectedValue(new ApiError(CONTAINER_REASON, 409));
    render(<PaymentCardSettings />);
    await fillForm();
    fireEvent.click(screen.getByRole("button", { name: "Save card" }));

    expect(await screen.findByText(CONTAINER_REASON)).toBeInTheDocument();
    expect(screen.queryByLabelText("Card number")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Save card" })).not.toBeInTheDocument();
  });

  it("shows the list's reason instead of the form on a container install", async () => {
    // Exactly what GET /vault/items answers with no key store (a 200, not a
    // 409): tests/test_vault_api.py::test_list_reports_why_the_vault_is_unavailable.
    vi.mocked(getVaultItems).mockResolvedValue({ items: [], available: false, reason: CONTAINER_REASON });
    render(<PaymentCardSettings />);

    expect(await screen.findByText(CONTAINER_REASON)).toBeInTheDocument();
    expect(screen.queryByLabelText("Card number")).not.toBeInTheDocument();
    expect(screen.queryByText(/no card is stored/i)).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /save card|replace card/i })).not.toBeInTheDocument();
  });

  it("falls back to a plain sentence when the list says unavailable without a reason", async () => {
    vi.mocked(getVaultItems).mockResolvedValue({ items: [], available: false, reason: "" });
    render(<PaymentCardSettings />);

    expect(
      await screen.findByText(
        "Cards can't be stored in a container install. Install Crawler on your Mac or PC to buy things.",
      ),
    ).toBeInTheDocument();
    expect(screen.queryByLabelText("Card number")).not.toBeInTheDocument();
  });

  it("names a card stored from this form once, not as its own label", async () => {
    // The form sends no label, so the server names the card by its masked
    // text (services/vault/service.py put_card); the line under it must
    // not repeat that.
    vi.mocked(getVaultItems).mockResolvedValue(vaultItems([{ ...STORED, label: STORED.masked }]));
    render(<PaymentCardSettings />);

    await screen.findByRole("button", { name: "Replace card" });
    expect(screen.getAllByText(/Visa ····4242/)).toHaveLength(1);
    expect(screen.getByText("not used yet")).toBeInTheDocument();
  });

  it("reports any other load failure with a retry", async () => {
    vi.mocked(getVaultItems)
      .mockRejectedValueOnce(new Error("Request failed: Bad Gateway"))
      .mockResolvedValueOnce(vaultItems([STORED]));
    render(<PaymentCardSettings />);

    expect(await screen.findByRole("alert")).toHaveTextContent("Request failed: Bad Gateway");
    fireEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(await screen.findByText("Visa ····4242")).toBeInTheDocument();
  });

  it("deletes the stored card after confirmation", async () => {
    vi.mocked(getVaultItems).mockResolvedValue(vaultItems([STORED]));
    vi.mocked(deleteVaultItem).mockResolvedValue(undefined);
    render(<PaymentCardSettings />);

    fireEvent.click(await screen.findByRole("button", { name: "Delete" }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: "Delete card" }));

    await waitFor(() => expect(deleteVaultItem).toHaveBeenCalledWith("v1"));
    expect(await screen.findByText("Card deleted.")).toBeInTheDocument();
    expect(screen.queryByText("Visa ····4242")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save card" })).toBeInTheDocument();
  });
});
