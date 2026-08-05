import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import ConfirmDialog from "@/components/ConfirmDialog";

/**
 * ConfirmDialog is the last gate in front of irreversible actions (deleting a
 * conversation, deleting the account). Two failure modes matter more than the
 * happy path: a second click while the first request is still in flight would
 * execute the destructive action twice, and a rejected confirm that closed the
 * dialog would tell the user "done" when nothing happened.
 */

/** A promise whose settlement the test controls, to hold a confirm in flight. */
function deferred<T = void>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  // Attach a no-op catch so a rejection the component handles later does not
  // trip vitest's unhandled-rejection guard first.
  promise.catch(() => {});
  return { promise, resolve, reject };
}

const TITLE = "Delete conversation?";
const MESSAGE = "This cannot be undone.";

function renderDialog(
  overrides: Partial<React.ComponentProps<typeof ConfirmDialog>> = {},
) {
  const onConfirm = vi.fn();
  const onCancel = vi.fn();
  const props: React.ComponentProps<typeof ConfirmDialog> = {
    open: true,
    title: TITLE,
    message: MESSAGE,
    confirmLabel: "Delete",
    cancelLabel: "Keep",
    onConfirm,
    onCancel,
    ...overrides,
  };
  const utils = render(<ConfirmDialog {...props} />);
  return { ...utils, onConfirm: props.onConfirm, onCancel: props.onCancel };
}

const confirmButton = () => screen.getByRole("button", { name: "Delete" });
const cancelButton = () => screen.getByRole("button", { name: "Keep" });

describe("ConfirmDialog", () => {
  it("renders nothing at all while closed", () => {
    renderDialog({ open: false });

    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(screen.queryByText(TITLE)).not.toBeInTheDocument();
  });

  it("shows the title, message and both labels when open", () => {
    renderDialog({ danger: true });

    const dialog = screen.getByRole("dialog");
    expect(dialog).toHaveAttribute("aria-modal", "true");
    expect(dialog).toHaveAttribute("aria-label", TITLE);
    expect(screen.getByText(MESSAGE)).toBeInTheDocument();
    expect(confirmButton()).toBeEnabled();
    expect(cancelButton()).toBeEnabled();
  });

  it("runs only onCancel when the cancel button is clicked", async () => {
    const user = userEvent.setup();
    const { onConfirm, onCancel } = renderDialog();

    await user.click(cancelButton());

    expect(onCancel).toHaveBeenCalledOnce();
    expect(onConfirm).not.toHaveBeenCalled();
  });

  it("runs onConfirm when the confirm button is clicked", async () => {
    const user = userEvent.setup();
    const { onConfirm, onCancel } = renderDialog();

    await user.click(confirmButton());

    expect(onConfirm).toHaveBeenCalledOnce();
    expect(onCancel).not.toHaveBeenCalled();
  });

  it("executes a destructive confirm once even on a double click", async () => {
    const user = userEvent.setup();
    const gate = deferred();
    const onConfirm = vi.fn(() => gate.promise);
    renderDialog({ onConfirm });

    await user.click(confirmButton());
    await user.click(confirmButton());

    expect(onConfirm).toHaveBeenCalledOnce();
    await act(async () => {
      gate.resolve();
    });
  });

  it("disables cancel as well while a confirm is in flight", async () => {
    const user = userEvent.setup();
    const gate = deferred();
    renderDialog({ onConfirm: () => gate.promise });

    await user.click(confirmButton());

    expect(confirmButton()).toBeDisabled();
    expect(cancelButton()).toBeDisabled();
    await act(async () => {
      gate.resolve();
    });
  });

  it("stays disabled after a successful confirm so the parent can close it", async () => {
    // Nothing resets `pending` on success — the owning page unmounts the
    // dialog instead. If it were reset here, the window between resolution
    // and unmount would accept a second delete.
    const user = userEvent.setup();
    const { onConfirm } = renderDialog({
      onConfirm: vi.fn().mockResolvedValue(undefined),
    });

    await user.click(confirmButton());

    expect(onConfirm).toHaveBeenCalledOnce();
    expect(confirmButton()).toBeDisabled();
    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });

  it("surfaces a failed confirm inline and keeps the dialog open for a retry", async () => {
    const user = userEvent.setup();
    const onConfirm = vi
      .fn()
      .mockRejectedValueOnce(new Error("Conversation is locked"))
      .mockResolvedValueOnce(undefined);
    const { onCancel } = renderDialog({ onConfirm });

    await user.click(confirmButton());

    expect(await screen.findByText("Conversation is locked")).toBeInTheDocument();
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(onCancel).not.toHaveBeenCalled();
    // The failure must re-arm the button, not strand the user on a dead modal.
    expect(confirmButton()).toBeEnabled();

    await user.click(confirmButton());
    expect(onConfirm).toHaveBeenCalledTimes(2);
  });

  it("falls back to a generic sentence when the failure carries no message", async () => {
    const user = userEvent.setup();
    renderDialog({ onConfirm: vi.fn().mockRejectedValue(new Error("")) });

    await user.click(confirmButton());

    expect(await screen.findByText("Something went wrong.")).toBeInTheDocument();
  });

  it("cancels on a backdrop click and on Escape", async () => {
    const user = userEvent.setup();
    const { onCancel, rerender } = renderDialog();

    await user.click(screen.getByRole("dialog"));
    expect(onCancel).toHaveBeenCalledOnce();

    rerender(
      <ConfirmDialog
        open
        title={TITLE}
        message={MESSAGE}
        confirmLabel="Delete"
        cancelLabel="Keep"
        onConfirm={vi.fn()}
        onCancel={onCancel}
      />,
    );
    await user.keyboard("{Escape}");
    expect(onCancel).toHaveBeenCalledTimes(2);
  });

  it("ignores the backdrop and Escape while a confirm is in flight", async () => {
    // Dismissing mid-request would leave the user with no idea whether the
    // delete went through.
    const user = userEvent.setup();
    const gate = deferred();
    const { onCancel } = renderDialog({ onConfirm: () => gate.promise });

    await user.click(confirmButton());
    await user.click(screen.getByRole("dialog"));
    await user.keyboard("{Escape}");

    expect(onCancel).not.toHaveBeenCalled();
    await act(async () => {
      gate.resolve();
    });
  });

  it("does not cancel when the click lands inside the dialog panel", async () => {
    const user = userEvent.setup();
    const { onCancel } = renderDialog();

    await user.click(screen.getByText(MESSAGE));

    expect(onCancel).not.toHaveBeenCalled();
  });

  it("clears a stale error when the dialog is closed and reopened", async () => {
    const user = userEvent.setup();
    const onCancel = vi.fn();
    const onConfirm = vi.fn().mockRejectedValue(new Error("Conversation is locked"));
    const props = {
      title: TITLE,
      message: MESSAGE,
      confirmLabel: "Delete",
      cancelLabel: "Keep",
      onConfirm,
      onCancel,
    };
    const { rerender } = render(<ConfirmDialog open {...props} />);

    await user.click(confirmButton());
    expect(await screen.findByText("Conversation is locked")).toBeInTheDocument();

    rerender(<ConfirmDialog open={false} {...props} />);
    rerender(<ConfirmDialog open {...props} />);

    expect(screen.queryByText("Conversation is locked")).not.toBeInTheDocument();
    expect(confirmButton()).toBeEnabled();
  });
});
