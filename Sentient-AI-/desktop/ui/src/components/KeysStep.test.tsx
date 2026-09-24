/**
 * Step 2 tests: generate is one click, custom keys are validated before anything is sent, and
 * existing keys are only replaced after an explicit confirmation.
 *
 * Why it exists: A bad key stops the backend from booting, and a silently replaced
 * ENCRYPTION_KEY loses every saved credential. These are the two ways this step can hurt people.
 */

import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { WORDS } from "../platform";
import { installBridge, mocked } from "../test/bridge";
import { KeysStep } from "./KeysStep";

vi.mock("../bridge");

const GOOD_SECRET = "k7Hq2vXr9LmP4tZs8WnB3cYd6FgJ1aQe";
const GOOD_ENC = "q83vASNFZ4mrze8BI0VniavN7wEjRWeJq83vASNFZ4k=";

beforeEach(() => {
  installBridge();
});

function renderStep() {
  const onDone = vi.fn();
  render(<KeysStep words={WORDS.mac} onDone={onDone} />);
  return onDone;
}

describe("KeysStep", () => {
  it("generates keys by default and moves on with Next", async () => {
    const user = userEvent.setup();
    const onDone = renderStep();
    expect(screen.getByRole("radio", { name: /Generate for me/ })).toBeChecked();
    await user.click(screen.getByRole("button", { name: "Save keys" }));
    expect(mocked.saveKeys).toHaveBeenCalledWith({ mode: "generate", overwrite: false });
    expect(await screen.findByText("Keys saved on this computer ✓")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Next" }));
    expect(onDone).toHaveBeenCalledWith("Keys saved on this computer.");
  });

  it("validates custom keys before sending anything", async () => {
    const user = userEvent.setup();
    renderStep();
    await user.click(screen.getByRole("radio", { name: /Use my own/ }));
    const secret = screen.getByLabelText("SECRET_KEY");
    const enc = screen.getByLabelText("ENCRYPTION_KEY");
    expect(secret).toHaveFocus();
    expect(secret).toHaveAttribute("type", "password");

    await user.type(secret, "too-short");
    await user.type(enc, btoa("sixteen bytes!!!"));
    await user.click(screen.getByRole("button", { name: "Save keys" }));
    expect(screen.getByText("SECRET_KEY must be at least 32 characters (this one has 9).")).toBeInTheDocument();
    expect(screen.getByText("ENCRYPTION_KEY must decode to exactly 32 bytes (this one decodes to 16).")).toBeInTheDocument();
    expect(secret).toHaveAttribute("aria-invalid", "true");
    expect(secret).toHaveFocus();
    expect(mocked.saveKeys).not.toHaveBeenCalled();

    await user.clear(secret);
    await user.type(secret, GOOD_SECRET);
    await user.clear(enc);
    await user.type(enc, "not/base64!");
    await user.click(screen.getByRole("button", { name: "Save keys" }));
    expect(screen.getByText(/ENCRYPTION_KEY must be base64 text/)).toBeInTheDocument();
    expect(mocked.saveKeys).not.toHaveBeenCalled();

    await user.clear(enc);
    await user.type(enc, GOOD_ENC);
    await user.click(screen.getByRole("button", { name: "Save keys" }));
    expect(mocked.saveKeys).toHaveBeenCalledWith({
      mode: "custom",
      secret_key: GOOD_SECRET,
      encryption_key: GOOD_ENC,
      overwrite: false,
    });
    expect(await screen.findByText("Keys saved on this computer ✓")).toBeInTheDocument();
  });

  it("clears pasted keys from the form once saved", async () => {
    const user = userEvent.setup();
    renderStep();
    await user.click(screen.getByRole("radio", { name: /Use my own/ }));
    await user.type(screen.getByLabelText("SECRET_KEY"), GOOD_SECRET);
    await user.type(screen.getByLabelText("ENCRYPTION_KEY"), GOOD_ENC);
    await user.click(screen.getByRole("button", { name: "Save keys" }));
    await screen.findByText("Keys saved on this computer ✓");
    expect(screen.getByLabelText("SECRET_KEY")).toHaveValue("");
    expect(screen.getByLabelText("ENCRYPTION_KEY")).toHaveValue("");
  });

  it("toggles a key between hidden and shown", async () => {
    const user = userEvent.setup();
    renderStep();
    await user.click(screen.getByRole("radio", { name: /Use my own/ }));
    const toggle = screen.getByRole("button", { name: "Show SECRET_KEY" });
    await user.click(toggle);
    expect(screen.getByLabelText("SECRET_KEY")).toHaveAttribute("type", "text");
    expect(screen.getByRole("button", { name: "Hide SECRET_KEY" })).toHaveAttribute("aria-pressed", "true");
  });

  it("asks before replacing existing keys and overwrites only on Replace", async () => {
    const user = userEvent.setup();
    mocked.saveKeys.mockResolvedValueOnce({ ok: false, reason: "exists" }).mockResolvedValueOnce({ ok: true });
    renderStep();
    await user.click(screen.getByRole("button", { name: "Save keys" }));

    const dialog = await screen.findByRole("dialog", { name: "Replace the keys?" });
    expect(within(dialog).getByText(/will need to be entered again/)).toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: "Cancel" })).toHaveFocus();
    expect(mocked.saveKeys).toHaveBeenCalledTimes(1);

    await user.click(within(dialog).getByRole("button", { name: "Replace keys" }));
    expect(mocked.saveKeys).toHaveBeenCalledTimes(2);
    expect(mocked.saveKeys).toHaveBeenLastCalledWith({ mode: "generate", overwrite: true });
    expect(await screen.findByText("Keys saved on this computer ✓")).toBeInTheDocument();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("keeps the existing keys when the overwrite is cancelled", async () => {
    const user = userEvent.setup();
    mocked.saveKeys.mockResolvedValueOnce({ ok: false, reason: "exists" });
    const onDone = renderStep();
    await user.click(screen.getByRole("button", { name: "Save keys" }));
    const dialog = await screen.findByRole("dialog", { name: "Replace the keys?" });
    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));

    expect(mocked.saveKeys).toHaveBeenCalledTimes(1);
    expect(await screen.findByText("Kept your existing keys. Nothing was changed.")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Next" }));
    expect(onDone).toHaveBeenCalledWith("Using the keys already on this computer.");
  });

  it("explains a failed save and lets people try again", async () => {
    const user = userEvent.setup();
    mocked.saveKeys.mockRejectedValueOnce("permission denied").mockResolvedValueOnce({ ok: true });
    renderStep();
    await user.click(screen.getByRole("button", { name: "Save keys" }));
    expect(
      await screen.findByText("Couldn’t save the keys. Try again; if it keeps failing, restart Crawler AI."),
    ).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Save keys" }));
    expect(await screen.findByText("Keys saved on this computer ✓")).toBeInTheDocument();
  });

  it("shows Rust's own field errors when it rejects custom keys", async () => {
    const user = userEvent.setup();
    mocked.saveKeys.mockResolvedValueOnce({
      ok: false,
      reason: "invalid",
      errors: { encryption_key: "ENCRYPTION_KEY is the example value from .env.example." },
    });
    renderStep();
    await user.click(screen.getByRole("radio", { name: /Use my own/ }));
    await user.type(screen.getByLabelText("SECRET_KEY"), GOOD_SECRET);
    await user.type(screen.getByLabelText("ENCRYPTION_KEY"), GOOD_ENC);
    await user.click(screen.getByRole("button", { name: "Save keys" }));
    expect(await screen.findByText("ENCRYPTION_KEY is the example value from .env.example.")).toBeInTheDocument();
    expect(screen.getByLabelText("ENCRYPTION_KEY")).toHaveAttribute("aria-invalid", "true");
    expect(
      screen.getByText("Those keys weren’t accepted. Check the format rules under each field."),
    ).toBeInTheDocument();
  });

  it("maps Rust's reasons to specific messages", async () => {
    const user = userEvent.setup();
    mocked.saveKeys.mockResolvedValueOnce({ ok: false, reason: "install_running" });
    renderStep();
    await user.click(screen.getByRole("button", { name: "Save keys" }));
    expect(
      await screen.findByText("An install is running. Wait for it to finish before changing keys."),
    ).toBeInTheDocument();
  });
});
