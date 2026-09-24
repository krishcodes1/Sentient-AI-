import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import ChatComposer, { MAX_IMAGES } from "@/components/ChatComposer";

/**
 * The composer is a textarea that sends on Enter, which puts two behaviours
 * in direct tension: a message must go on Enter, and a multi-line message
 * must still be possible. Both are covered here, along with the IME case
 * where Enter commits a candidate rather than finishing a sentence, and the
 * attachment flow — a picked image can always be taken back before it goes.
 */

function renderComposer(
  overrides: Omit<
    Partial<React.ComponentProps<typeof ChatComposer>>,
    "onSend" | "onStop"
  > = {},
) {
  const onSend = vi.fn<(content: string, images: string[]) => void>();
  const onStop = vi.fn<() => void>();
  render(
    <ChatComposer
      disabled={false}
      sending={false}
      placeholder="Ask Crawler AI anything..."
      {...overrides}
      onSend={onSend}
      onStop={onStop}
    />,
  );
  return { onSend, onStop };
}

const box = () => screen.getByRole("textbox", { name: "Message" });
const fileInput = () => screen.getByLabelText("Image file");

/** The bordered area that accepts drops — the composer's outer field. */
const dropZone = () => box().closest("form")!.firstElementChild as HTMLElement;

/** Four bytes of PNG header: enough for FileReader to produce a data URL. */
function pngFile(name = "shot.png") {
  return new File([Uint8Array.from([137, 80, 78, 71])], name, {
    type: "image/png",
  });
}

describe("ChatComposer", () => {
  it("sends on Enter and clears the box", async () => {
    const user = userEvent.setup();
    const { onSend } = renderComposer();

    await user.type(box(), "hello there");
    await user.keyboard("{Enter}");

    expect(onSend).toHaveBeenCalledWith("hello there", []);
    expect(box()).toHaveValue("");
  });

  it("inserts a newline on Shift+Enter and sends nothing", async () => {
    const user = userEvent.setup();
    const { onSend } = renderComposer();

    await user.type(box(), "first line");
    await user.keyboard("{Shift>}{Enter}{/Shift}");
    await user.type(box(), "second line");

    expect(onSend).not.toHaveBeenCalled();
    expect(box()).toHaveValue("first line\nsecond line");

    await user.keyboard("{Enter}");
    expect(onSend).toHaveBeenCalledWith("first line\nsecond line", []);
  });

  it("does not send when Enter is committing an IME candidate", async () => {
    const user = userEvent.setup();
    const { onSend } = renderComposer();

    await user.type(box(), "にほんご");

    // userEvent cannot drive a composition, so the keydown is delivered the
    // way an IME does: Enter, with isComposing set.
    const event = new KeyboardEvent("keydown", {
      key: "Enter",
      bubbles: true,
      cancelable: true,
    });
    Object.defineProperty(event, "isComposing", { value: true });
    fireEvent(box(), event);

    expect(onSend).not.toHaveBeenCalled();
    expect(box()).toHaveValue("にほんご");
  });

  it("ignores Enter on an empty box", async () => {
    const user = userEvent.setup();
    const { onSend } = renderComposer();

    await user.click(box());
    await user.keyboard("{Enter}");
    await user.type(box(), "   ");
    await user.keyboard("{Enter}");

    expect(onSend).not.toHaveBeenCalled();
  });

  it("will not send while a turn is already streaming", async () => {
    const user = userEvent.setup();
    const { onSend } = renderComposer({ sending: true });

    await user.type(box(), "second question");
    await user.keyboard("{Enter}");

    expect(onSend).not.toHaveBeenCalled();
  });

  it("swaps Send for Stop while streaming", async () => {
    const user = userEvent.setup();
    const { onStop } = renderComposer({ sending: true });

    expect(
      screen.queryByRole("button", { name: "Send message" }),
    ).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Stop generating" }));

    expect(onStop).toHaveBeenCalledOnce();
  });

  it("attaches an image, shows it, and lets it be removed before sending", async () => {
    const user = userEvent.setup();
    const { onSend } = renderComposer();

    await user.upload(fileInput(), pngFile("diagram.png"));

    const thumb = await screen.findByAltText("diagram.png");
    expect(thumb).toHaveAttribute("src", expect.stringContaining("data:image/png"));

    await user.click(screen.getByRole("button", { name: "Remove diagram.png" }));
    expect(screen.queryByAltText("diagram.png")).not.toBeInTheDocument();

    await user.type(box(), "no picture after all");
    await user.keyboard("{Enter}");

    expect(onSend).toHaveBeenCalledWith("no picture after all", []);
  });

  it("sends an attachment as a data URL alongside the text", async () => {
    const user = userEvent.setup();
    const { onSend } = renderComposer();

    await user.upload(fileInput(), pngFile());
    await screen.findByAltText("shot.png");

    await user.type(box(), "what is this");
    await user.keyboard("{Enter}");

    expect(onSend).toHaveBeenCalledOnce();
    const [content, images] = onSend.mock.calls[0];
    expect(content).toBe("what is this");
    expect(images).toHaveLength(1);
    expect(images[0]).toMatch(/^data:image\/png/);
  });

  it("sends an image on its own, with no text", async () => {
    const user = userEvent.setup();
    const { onSend } = renderComposer();

    await user.upload(fileInput(), pngFile());
    await screen.findByAltText("shot.png");

    await user.click(screen.getByRole("button", { name: "Send message" }));

    expect(onSend).toHaveBeenCalledOnce();
    expect(onSend.mock.calls[0][0]).toBe("");
    expect(onSend.mock.calls[0][1]).toHaveLength(1);
  });

  it("accepts an image dropped onto the composer", async () => {
    renderComposer();

    fireEvent.drop(dropZone(), {
      dataTransfer: { files: [pngFile("dropped.png")], types: ["Files"] },
    });

    expect(await screen.findByAltText("dropped.png")).toBeInTheDocument();
  });

  it("refuses a dropped non-image with a readable reason", async () => {
    renderComposer();

    fireEvent.drop(dropZone(), {
      dataTransfer: {
        files: [new File(["#!/bin/sh"], "run.sh", { type: "application/x-sh" })],
        types: ["Files"],
      },
    });

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Only image files can be attached.",
    );
    expect(screen.queryByAltText("run.sh")).not.toBeInTheDocument();
  });

  it("caps the number of attachments and says so", async () => {
    const user = userEvent.setup();
    renderComposer();

    await user.upload(
      fileInput(),
      Array.from({ length: MAX_IMAGES + 1 }, (_, i) => pngFile(`shot-${i}.png`)),
    );

    await waitFor(() =>
      expect(screen.getAllByRole("listitem")).toHaveLength(MAX_IMAGES),
    );
    expect(screen.getByRole("alert")).toHaveTextContent(
      `Up to ${MAX_IMAGES} images per message.`,
    );
  });

  it("disables everything when there is no conversation to send to", () => {
    renderComposer({ disabled: true });

    expect(box()).toBeDisabled();
    expect(screen.getByRole("button", { name: "Attach image" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Send message" })).toBeDisabled();
  });
});
