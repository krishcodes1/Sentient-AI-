/**
 * Tests for FileChecksTab (Security ▸ File checks): each checked file is listed with its source, its
 * verdict badge and counts, never "safe" and never in a success colour; the owner is pointed to the
 * Service keys tab while no key is set and other people are told checks are not set up; "Check a
 * file…" fingerprints the file in the browser and posts only the fingerprint; a browser that cannot
 * fingerprint says why; an unknown file can be sent to VirusTotal only through the sharing warning
 * and an approval card (with its bytes only when the server has no copy); the card's Approve and
 * Deny work from the row; waiting rows are polled until nothing is moving; Forget removes only its
 * row; a failed load can be retried.
 *
 * Why it exists: this tab is where a person learns what VirusTotal said about their files and where
 * a file is handed to a third party. Calling a file safe, leaking a picked file's bytes on a plain
 * check, or skipping the sharing warning would each break a promise the page makes.
 */

import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { FileCheck, FileChecksResponse, FileChecksStatus } from "@/types";

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
    listFileChecks: vi.fn(),
    checkFileHash: vi.fn(),
    requestFileUpload: vi.fn(),
    forgetFileCheck: vi.fn(),
    decideApproval: vi.fn(),
  };
});

import FileChecksTab from "@/pages/security/FileChecksTab";
import { HASH_MAX_BYTES } from "@/pages/security/fileHash";
import {
  ApiError,
  checkFileHash,
  decideApproval,
  forgetFileCheck,
  listFileChecks,
  requestFileUpload,
} from "@/services/api";

const MINUTE = 60_000;
const ago = (ms: number) => new Date(Date.now() - ms).toISOString();

// SHA-256 of the text "hello setup", worked out with Node's crypto.createHash("sha256").
const HELLO_SETUP_SHA = "74c6342f890743d8920c9634309dd11677fbc0e6a50e656761f2d25a2e9acd75";
const SHARING_WARNING =
  "VirusTotal shares files it receives with security companies, and its paying users can download them. Never send private documents.";

function service(overrides: Partial<FileChecksStatus> = {}): FileChecksStatus {
  return {
    state: "on",
    reason: null,
    lookups_last_24h: 37,
    lookups_per_day: 500,
    your_lookups_last_24h: 5,
    your_lookups_per_day: 100,
    upload_max_bytes: 20 * 1024 * 1024,
    ...overrides,
  };
}

function check(overrides: Partial<FileCheck>): FileCheck {
  return {
    id: "c1",
    sha256: "1".repeat(64),
    name: "notes.pdf",
    source: "web",
    size_bytes: 2048,
    state: "checked",
    verdict: "no_detections",
    flagged_by: 0,
    engines: 68,
    threat_label: null,
    summary: "VirusTotal: none of 68 security vendors flag this file. That is not a guarantee it is safe.",
    reason: null,
    can_upload: false,
    upload_needs_file: false,
    action_id: null,
    checked_at: ago(26 * 60 * MINUTE),
    updated_at: ago(26 * 60 * MINUTE),
    ...overrides,
  };
}

function answer(checks: FileCheck[], overrides: Partial<FileChecksStatus> = {}): FileChecksResponse {
  return { service: service(overrides), checks };
}

const MALICIOUS = check({
  id: "c-mal",
  sha256: "2".repeat(64),
  name: "invoice.pdf.exe",
  source: "telegram",
  verdict: "malicious",
  flagged_by: 41,
  engines: 72,
  threat_label: "trojan.emotet",
  summary: "VirusTotal: 41 of 72 security vendors flag this file as malicious (trojan.emotet).",
  updated_at: ago(2 * MINUTE),
});
const SUSPICIOUS = check({
  id: "c-sus",
  sha256: "3".repeat(64),
  name: "report.docm",
  source: "gmail",
  verdict: "suspicious",
  flagged_by: 2,
  engines: 70,
  updated_at: ago(61 * MINUTE),
});
const UNKNOWN = check({
  id: "c-unk",
  sha256: "4".repeat(64),
  name: "setup.exe",
  source: "page",
  verdict: "unknown",
  flagged_by: null,
  engines: null,
  summary: "VirusTotal has no record of this file, so it could not be judged. New files often are unknown.",
  can_upload: true,
  upload_needs_file: false,
  updated_at: ago(10_000),
});
const QUEUED = check({
  id: "c-q",
  sha256: "5".repeat(64),
  name: "photos.zip",
  state: "queued",
  verdict: null,
  flagged_by: null,
  engines: null,
  reason: "minute_limit",
  summary: "Not checked yet: VirusTotal's per-minute lookup limit was reached; Crawler will check it shortly.",
  updated_at: ago(5 * MINUTE),
});
const CLEAN = check({ id: "c-clean", name: "notes.pdf" });
const TOO_BIG = check({
  id: "c-big",
  sha256: "6".repeat(64),
  name: "big.iso",
  source: "outlook",
  state: "not_checked",
  verdict: null,
  flagged_by: null,
  engines: null,
  reason: "too_large",
  summary: "Not checked: it is larger than 25 MB, too large to fingerprint.",
  updated_at: ago(3 * 60 * MINUTE),
});

/** The list item for the file called `name`. */
function row(name: string): HTMLElement {
  const item = screen.getByText(name).closest("li");
  if (!item) throw new Error(`no row for ${name}`);
  return item as HTMLElement;
}

function fileInput(): HTMLInputElement {
  return screen.getByLabelText("File to fingerprint") as HTMLInputElement;
}

beforeEach(() => {
  vi.mocked(listFileChecks).mockResolvedValue(answer([]));
  vi.mocked(checkFileHash).mockReset();
  vi.mocked(requestFileUpload).mockReset();
  vi.mocked(forgetFileCheck).mockReset();
  vi.mocked(decideApproval).mockReset();
});

afterEach(() => {
  vi.useRealTimers();
});

describe("FileChecksTab", () => {
  it("lists each check with its verdict label and counts and never says safe", async () => {
    vi.mocked(listFileChecks).mockResolvedValue(answer([MALICIOUS, SUSPICIOUS, UNKNOWN, QUEUED, CLEAN, TOO_BIG]));
    render(<FileChecksTab isOwner />);

    expect(screen.getByRole("region", { name: "File checks" })).toBeInTheDocument();
    expect(screen.getByText("Loading file checks…")).toBeInTheDocument();
    await screen.findByText("invoice.pdf.exe");

    expect(screen.getByText(/VirusTotal lookups: 37 of 500 in the last 24 hours/)).toHaveTextContent(
      "VirusTotal lookups: 37 of 500 in the last 24 hours (yours: 5 of 100)",
    );
    const items = within(screen.getByRole("list", { name: "Checked files" })).getAllByRole("listitem");
    expect(items).toHaveLength(6);

    const mal = row("invoice.pdf.exe");
    expect(mal).toHaveTextContent("Telegram · 2 min ago");
    expect(within(mal).getByText("Flagged as malicious")).toHaveAttribute("data-tone", "danger");
    expect(mal).toHaveTextContent("41 of 72 · trojan.emotet");

    const sus = row("report.docm");
    expect(sus).toHaveTextContent("Email (Gmail) · 1 h ago");
    expect(within(sus).getByText("Some detections")).toHaveAttribute("data-tone", "warning");
    expect(sus).toHaveTextContent("2 of 70");

    const unk = row("setup.exe");
    expect(unk).toHaveTextContent("This page · just now");
    expect(within(unk).getByText("Unknown to VirusTotal")).toHaveAttribute("data-tone", "neutral");
    expect(within(unk).getByRole("button", { name: "Send to VirusTotal: setup.exe" })).toBeEnabled();

    expect(row("photos.zip")).toHaveTextContent(
      "Checking… (VirusTotal's per-minute lookup limit was reached; Crawler will check it shortly)",
    );
    const clean = row("notes.pdf");
    expect(clean).toHaveTextContent("Web chat · yesterday");
    expect(within(clean).getByText("No detections")).toHaveAttribute("data-tone", "neutral");
    expect(clean).toHaveTextContent("0 of 68 (not a guarantee)");
    expect(row("big.iso")).toHaveTextContent(
      "Email (Outlook) · 3 h agoNot checked: it is larger than 25 MB, too large to fingerprint",
    );

    // Only an unknown file can be sent; every row can be forgotten.
    expect(screen.getAllByRole("button", { name: /^Send to VirusTotal/ })).toHaveLength(1);
    expect(screen.getAllByRole("button", { name: /^Forget / })).toHaveLength(6);

    // Never "safe", never a success colour, never a reason code.
    expect(document.body.textContent).not.toMatch(/\bsafe\b/i);
    expect(document.body.textContent).not.toMatch(/minute_limit|too_large/);
    expect(document.querySelectorAll('[style*="success"]')).toHaveLength(0);
    expect(listFileChecks).toHaveBeenCalledTimes(1);
  });

  it("the owner sees the add-a-key prompt while blocked and other people see not set up", async () => {
    vi.mocked(listFileChecks).mockResolvedValue(
      answer([UNKNOWN], { state: "blocked", reason: "Add your VirusTotal API key in Security → Service keys." }),
    );
    const onOpenKeys = vi.fn();
    const { unmount } = render(<FileChecksTab isOwner onOpenKeys={onOpenKeys} />);

    expect(await screen.findByText("Add a VirusTotal key to check files.")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Open Service keys" }));
    expect(onOpenKeys).toHaveBeenCalledTimes(1);
    // The history is still listed; actions that would reach VirusTotal are not offered.
    expect(row("setup.exe")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Check a file…" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Send to VirusTotal: setup.exe" })).toBeDisabled();
    expect(screen.queryByText(/VirusTotal lookups:/)).not.toBeInTheDocument();
    unmount();

    render(<FileChecksTab isOwner={false} onOpenKeys={onOpenKeys} />);
    expect(await screen.findByText("File checks are not set up on this install.")).toBeInTheDocument();
    expect(screen.queryByText("Add a VirusTotal key to check files.")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Open Service keys" })).not.toBeInTheDocument();
    expect(row("setup.exe")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Check a file…" })).toBeDisabled();
  });

  it("without a way to open the keys tab the owner is told where to add the key", async () => {
    vi.mocked(listFileChecks).mockResolvedValue(answer([], { state: "blocked" }));
    render(<FileChecksTab isOwner />);

    expect(await screen.findByText(/^Add a VirusTotal key to check files\./)).toHaveTextContent(
      "Add a VirusTotal key to check files. You can add one in Security → Service keys.",
    );
    expect(screen.queryByRole("button", { name: "Open Service keys" })).not.toBeInTheDocument();
    expect(screen.getByText("No files checked yet.")).toBeInTheDocument();
  });

  it("says checks are turned off in Settings and offers no picker while off", async () => {
    vi.mocked(listFileChecks).mockResolvedValue(answer([UNKNOWN], { state: "off" }));
    render(<FileChecksTab isOwner />);

    expect(
      await screen.findByText("Checking files with VirusTotal is turned off in Settings → Permissions."),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Check a file…" })).toBeDisabled();
    expect(fileInput()).toBeDisabled();
    expect(screen.getByRole("button", { name: "Send to VirusTotal: setup.exe" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Forget setup.exe" })).toBeEnabled();
  });

  it("an empty list says files people send are checked automatically", async () => {
    render(<FileChecksTab isOwner={false} />);

    expect(
      await screen.findByText("No files checked yet. Files people send Crawler are checked automatically."),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Check a file…" })).toBeEnabled();
    expect(
      screen.getByText("Only the file's fingerprint (SHA-256) is sent. The file stays on this device."),
    ).toBeInTheDocument();
  });

  it("checking a file hashes it in the browser and posts only the fingerprint", async () => {
    const user = userEvent.setup();
    const digest = vi
      .spyOn(globalThis.crypto.subtle, "digest")
      .mockResolvedValue(new Uint8Array(32).fill(0xab).buffer as ArrayBuffer);
    const fingerprint = "ab".repeat(32);
    const picked = check({
      id: "c-new",
      sha256: fingerprint,
      name: "setup.exe",
      source: "page",
      verdict: "malicious",
      flagged_by: 3,
      engines: 70,
      updated_at: new Date().toISOString(),
    });
    vi.mocked(checkFileHash).mockResolvedValue(picked);
    vi.mocked(listFileChecks).mockResolvedValue(answer([CLEAN]));
    render(<FileChecksTab isOwner />);
    await screen.findByText("notes.pdf");

    const file = new File(["MZ fake program"], "setup.exe", { type: "application/x-msdownload" });
    await user.upload(fileInput(), file);

    await waitFor(() => expect(row("setup.exe")).toHaveTextContent("Flagged as malicious"));
    expect(digest).toHaveBeenCalledTimes(1);
    expect(digest.mock.calls[0][0]).toBe("SHA-256");
    expect(vi.mocked(checkFileHash).mock.calls).toEqual([
      [{ sha256: fingerprint, name: "setup.exe", size_bytes: file.size, media_type: "application/x-msdownload" }],
    ]);
    // Only plain values went to the server: no File, Blob or bytes.
    const body = vi.mocked(checkFileHash).mock.calls[0][0] as Record<string, unknown>;
    expect(Object.values(body).every((value) => typeof value === "string" || typeof value === "number")).toBe(true);
    expect(requestFileUpload).not.toHaveBeenCalled();
    // The new row goes to the top, above the older one.
    expect(screen.getAllByRole("listitem").map((item) => item.querySelector("p")?.textContent)).toEqual([
      "setup.exe",
      "notes.pdf",
    ]);
    expect(screen.queryByText(/Fingerprinting/)).not.toBeInTheDocument();
  });

  it("shows the server's sentence when a check is refused", async () => {
    const user = userEvent.setup();
    vi.mocked(checkFileHash).mockRejectedValue(
      new ApiError("Checking files with VirusTotal is turned off in Settings → Permissions.", 409),
    );
    render(<FileChecksTab isOwner />);
    await screen.findByText(/No files checked yet/);

    await user.upload(fileInput(), new File(["hello setup"], "setup.exe"));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Checking files with VirusTotal is turned off in Settings → Permissions.",
    );
    // A file without a type sends no media_type.
    expect(vi.mocked(checkFileHash).mock.calls[0][0]).toEqual({
      sha256: HELLO_SETUP_SHA,
      name: "setup.exe",
      size_bytes: 11,
    });
  });

  it("a file too large to fingerprint is refused before it is read", async () => {
    const user = userEvent.setup();
    const digest = vi.spyOn(globalThis.crypto.subtle, "digest");
    render(<FileChecksTab isOwner />);
    await screen.findByText(/No files checked yet/);

    const huge = new File(["x"], "disk.iso");
    Object.defineProperty(huge, "size", { value: HASH_MAX_BYTES + 1 });
    await user.upload(fileInput(), huge);

    expect(await screen.findByRole("alert")).toHaveTextContent("Too large to fingerprint here.");
    expect(digest).not.toHaveBeenCalled();
    expect(checkFileHash).not.toHaveBeenCalled();
  });

  it("a browser without crypto.subtle cannot pick a file and says why", async () => {
    vi.stubGlobal("crypto", {});
    vi.mocked(listFileChecks).mockResolvedValue(answer([CLEAN]));
    render(<FileChecksTab isOwner />);

    expect(
      await screen.findByText("This browser can't fingerprint files on this connection (it needs HTTPS)."),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Check a file…" })).toBeDisabled();
    expect(fileInput()).toBeDisabled();
    // The history is still shown.
    expect(row("notes.pdf")).toBeInTheDocument();
  });

  it("an unknown file offers Send to VirusTotal with the sharing warning and parks a card", async () => {
    vi.mocked(listFileChecks).mockResolvedValue(answer([UNKNOWN]));
    vi.mocked(requestFileUpload).mockResolvedValue({
      action_id: "act-9",
      expires_at: new Date(Date.now() + 60 * MINUTE).toISOString(),
      state: "upload_pending",
      reason: "Waiting for your approval.",
    });
    render(<FileChecksTab isOwner />);

    fireEvent.click(await screen.findByRole("button", { name: "Send to VirusTotal: setup.exe" }));
    const dialog = screen.getByRole("dialog", { name: "Send setup.exe to VirusTotal?" });
    expect(dialog).toHaveAccessibleDescription(
      `VirusTotal will scan setup.exe. ${SHARING_WARNING} Crawler will ask you to approve this as a card.`,
    );
    expect(requestFileUpload).not.toHaveBeenCalled();

    fireEvent.click(within(dialog).getByRole("button", { name: "Continue" }));

    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    // The server already has a copy (upload_needs_file is false), so no bytes are sent.
    expect(vi.mocked(requestFileUpload).mock.calls).toEqual([["c-unk", undefined]]);
    const item = row("setup.exe");
    expect(item).toHaveTextContent("Waiting for your approval");
    expect(within(item).getByRole("button", { name: "Approve sending setup.exe" })).toBeEnabled();
    expect(within(item).getByRole("button", { name: "Deny sending setup.exe" })).toBeEnabled();
    expect(within(item).queryByRole("button", { name: /^Send to VirusTotal/ })).not.toBeInTheDocument();
  });

  it("cancelling the warning sends nothing", async () => {
    vi.mocked(listFileChecks).mockResolvedValue(answer([UNKNOWN]));
    render(<FileChecksTab isOwner />);

    fireEvent.click(await screen.findByRole("button", { name: "Send to VirusTotal: setup.exe" }));
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Cancel" }));

    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(requestFileUpload).not.toHaveBeenCalled();
    expect(row("setup.exe")).toHaveTextContent("Unknown to VirusTotal");
  });

  it("a refused upload request keeps the dialog open with the reason and reads the list again", async () => {
    vi.mocked(listFileChecks)
      .mockResolvedValueOnce(answer([UNKNOWN]))
      .mockResolvedValueOnce(answer([{ ...UNKNOWN, upload_needs_file: true }]));
    vi.mocked(requestFileUpload).mockRejectedValue(
      new ApiError("Crawler no longer has this file. Pick it on this page to send it.", 409),
    );
    render(<FileChecksTab isOwner />);

    fireEvent.click(await screen.findByRole("button", { name: "Send to VirusTotal: setup.exe" }));
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Continue" }));

    expect(await within(screen.getByRole("dialog")).findByRole("alert")).toHaveTextContent(
      "Crawler no longer has this file. Pick it on this page to send it.",
    );
    await waitFor(() => expect(listFileChecks).toHaveBeenCalledTimes(2));
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Cancel" }));
    expect(await screen.findByText("Pick the file again to send it.")).toBeInTheDocument();
  });

  it("a file picked on this page is sent with its bytes when the server has no copy", async () => {
    const user = userEvent.setup();
    vi.mocked(checkFileHash).mockResolvedValue(
      check({
        id: "c-page",
        sha256: HELLO_SETUP_SHA,
        name: "setup.exe",
        source: "page",
        verdict: "unknown",
        flagged_by: null,
        engines: null,
        can_upload: true,
        upload_needs_file: true,
        updated_at: new Date().toISOString(),
      }),
    );
    vi.mocked(requestFileUpload).mockResolvedValue({
      action_id: "act-3",
      expires_at: new Date(Date.now() + 60 * MINUTE).toISOString(),
      state: "upload_pending",
      reason: "Waiting for your approval.",
    });
    render(<FileChecksTab isOwner />);
    await screen.findByText(/No files checked yet/);

    const file = new File(["hello setup"], "setup.exe", { type: "application/x-msdownload" });
    await user.upload(fileInput(), file);
    // The browser still holds the file, so it does not ask for it again.
    await user.click(await screen.findByRole("button", { name: "Send to VirusTotal: setup.exe" }));
    expect(screen.queryByText("Pick the file again to send it.")).not.toBeInTheDocument();
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Continue" }));

    await waitFor(() => expect(row("setup.exe")).toHaveTextContent("Waiting for your approval"));
    expect(requestFileUpload).toHaveBeenCalledTimes(1);
    expect(vi.mocked(requestFileUpload).mock.calls[0][0]).toBe("c-page");
    expect(vi.mocked(requestFileUpload).mock.calls[0][1]).toBe(file);
  });

  it("a picked file's bytes stay on this device when the server already has a copy", async () => {
    const user = userEvent.setup();
    vi.mocked(checkFileHash).mockResolvedValue(
      check({
        id: "c-held",
        sha256: HELLO_SETUP_SHA,
        name: "setup.exe",
        source: "page",
        verdict: "unknown",
        flagged_by: null,
        engines: null,
        can_upload: true,
        upload_needs_file: false,
        updated_at: new Date().toISOString(),
      }),
    );
    vi.mocked(requestFileUpload).mockResolvedValue({
      action_id: "act-7",
      expires_at: new Date(Date.now() + 60 * MINUTE).toISOString(),
      state: "upload_pending",
      reason: "Waiting for your approval.",
    });
    render(<FileChecksTab isOwner />);
    await screen.findByText(/No files checked yet/);

    await user.upload(fileInput(), new File(["hello setup"], "setup.exe"));
    await user.click(await screen.findByRole("button", { name: "Send to VirusTotal: setup.exe" }));
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Continue" }));

    await waitFor(() => expect(row("setup.exe")).toHaveTextContent("Waiting for your approval"));
    expect(vi.mocked(requestFileUpload).mock.calls).toEqual([["c-held", undefined]]);
  });

  it("a picked file larger than the upload limit is not posted", async () => {
    const user = userEvent.setup();
    vi.mocked(listFileChecks).mockResolvedValue(answer([], { upload_max_bytes: 1024 * 1024 }));
    vi.mocked(checkFileHash).mockResolvedValue(
      check({
        id: "c-large",
        sha256: HELLO_SETUP_SHA,
        name: "setup.exe",
        source: "page",
        verdict: "unknown",
        flagged_by: null,
        engines: null,
        can_upload: true,
        upload_needs_file: true,
        updated_at: new Date().toISOString(),
      }),
    );
    render(<FileChecksTab isOwner />);
    await screen.findByText(/No files checked yet/);

    const large = new File(["hello setup"], "setup.exe");
    Object.defineProperty(large, "size", { value: 2 * 1024 * 1024 });
    await user.upload(fileInput(), large);
    await user.click(await screen.findByRole("button", { name: "Send to VirusTotal: setup.exe" }));
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Continue" }));

    expect(await within(screen.getByRole("dialog")).findByRole("alert")).toHaveTextContent(
      "setup.exe is larger than 1 MB, too large to send to VirusTotal from here.",
    );
    expect(requestFileUpload).not.toHaveBeenCalled();
  });

  it("send asks to pick the file again when the server has no copy", async () => {
    const user = userEvent.setup();
    const needsFile = check({
      id: "c-need",
      sha256: HELLO_SETUP_SHA,
      name: "setup.exe",
      source: "web",
      verdict: "unknown",
      flagged_by: null,
      engines: null,
      can_upload: true,
      upload_needs_file: true,
    });
    vi.mocked(listFileChecks).mockResolvedValue(answer([needsFile]));
    vi.mocked(requestFileUpload).mockResolvedValue({
      action_id: "act-4",
      expires_at: new Date(Date.now() + 60 * MINUTE).toISOString(),
      state: "upload_pending",
      reason: "Waiting for your approval.",
    });
    render(<FileChecksTab isOwner />);

    const item = await screen.findByText("setup.exe").then(() => row("setup.exe"));
    expect(item).toHaveTextContent("Pick the file again to send it.");
    expect(within(item).queryByRole("button", { name: /^Send to VirusTotal/ })).not.toBeInTheDocument();

    // A different file is refused by its fingerprint and nothing is sent.
    await user.click(within(item).getByRole("button", { name: "Pick the file again: setup.exe" }));
    await user.upload(fileInput(), new File(["something else"], "setup.exe"));
    expect(await within(row("setup.exe")).findByRole("alert")).toHaveTextContent(
      "That is a different file: its fingerprint does not match setup.exe. Pick setup.exe to send it.",
    );
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();

    // The same file opens the warning, and its bytes go with the request.
    await user.click(within(row("setup.exe")).getByRole("button", { name: "Pick the file again: setup.exe" }));
    const same = new File(["hello setup"], "setup.exe");
    await user.upload(fileInput(), same);
    const dialog = await screen.findByRole("dialog", { name: "Send setup.exe to VirusTotal?" });
    await user.click(within(dialog).getByRole("button", { name: "Continue" }));

    await waitFor(() => expect(row("setup.exe")).toHaveTextContent("Waiting for your approval"));
    expect(vi.mocked(requestFileUpload).mock.calls).toEqual([["c-need", same]]);
    expect(checkFileHash).not.toHaveBeenCalled();
  });

  it("approve and deny on a waiting row call decideApproval and reload", async () => {
    const waitingA = check({
      ...UNKNOWN,
      state: "upload_pending",
      can_upload: false,
      action_id: "act-1",
    });
    const waitingB = check({
      id: "c-b",
      sha256: "7".repeat(64),
      name: "tool.msi",
      verdict: "unknown",
      flagged_by: null,
      engines: null,
      state: "upload_pending",
      action_id: "act-2",
    });
    vi.mocked(listFileChecks)
      .mockResolvedValueOnce(answer([waitingA, waitingB]))
      .mockResolvedValueOnce(answer([{ ...waitingA, state: "analysing", action_id: null }, waitingB]))
      .mockResolvedValueOnce(
        answer([{ ...waitingA, state: "analysing", action_id: null }, { ...waitingB, state: "checked", action_id: null, can_upload: true }]),
      );
    vi.mocked(decideApproval).mockResolvedValue({ action_id: "act-1", approved: true, result: { ok: true } });
    render(<FileChecksTab isOwner />);

    fireEvent.click(await screen.findByRole("button", { name: "Approve sending setup.exe" }));
    await waitFor(() => expect(row("setup.exe")).toHaveTextContent("Scanning on VirusTotal…"));
    expect(vi.mocked(decideApproval).mock.calls).toEqual([["act-1", true]]);
    expect(listFileChecks).toHaveBeenCalledTimes(2);

    fireEvent.click(screen.getByRole("button", { name: "Deny sending tool.msi" }));
    await waitFor(() => expect(row("tool.msi")).toHaveTextContent("Unknown to VirusTotal"));
    expect(vi.mocked(decideApproval).mock.calls).toEqual([
      ["act-1", true],
      ["act-2", false],
    ]);
    expect(listFileChecks).toHaveBeenCalledTimes(3);
  });

  it("an approved upload that refuses to send says why on its row", async () => {
    const waiting = check({ ...UNKNOWN, state: "upload_pending", can_upload: false, action_id: "act-5" });
    vi.mocked(listFileChecks)
      .mockResolvedValueOnce(answer([waiting]))
      .mockResolvedValueOnce(answer([{ ...waiting, state: "checked", action_id: null, can_upload: true }]));
    vi.mocked(decideApproval).mockResolvedValue({
      action_id: "act-5",
      approved: true,
      result: {
        ok: false,
        error:
          "Crawler no longer has this file (it was kept in memory only, and the server restarted or 60 minutes passed). Nothing was sent.",
      },
    });
    render(<FileChecksTab isOwner />);

    fireEvent.click(await screen.findByRole("button", { name: "Approve sending setup.exe" }));

    expect(await within(row("setup.exe")).findByRole("alert")).toHaveTextContent(
      "Crawler no longer has this file (it was kept in memory only, and the server restarted or 60 minutes passed). Nothing was sent.",
    );
    expect(row("setup.exe")).toHaveTextContent("Unknown to VirusTotal");
  });

  it("a failed decision keeps the row with the reason", async () => {
    const waiting = check({ ...UNKNOWN, state: "upload_pending", can_upload: false, action_id: "act-6" });
    vi.mocked(listFileChecks).mockResolvedValue(answer([waiting]));
    vi.mocked(decideApproval).mockRejectedValue(new ApiError("Request failed: Internal Server Error", 500));
    render(<FileChecksTab isOwner />);

    fireEvent.click(await screen.findByRole("button", { name: "Deny sending setup.exe" }));

    expect(await within(row("setup.exe")).findByRole("alert")).toHaveTextContent(
      "Request failed: Internal Server Error",
    );
    expect(row("setup.exe")).toHaveTextContent("Waiting for your approval");
    expect(listFileChecks).toHaveBeenCalledTimes(1);
  });

  it("rows that are still checking are polled and polling stops when none are", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    vi.mocked(listFileChecks)
      .mockResolvedValueOnce(answer([QUEUED, CLEAN]))
      .mockResolvedValueOnce(answer([QUEUED, CLEAN]))
      .mockResolvedValue(answer([{ ...QUEUED, state: "checked", verdict: "no_detections", engines: 70, flagged_by: 0 }, CLEAN]));
    render(<FileChecksTab isOwner />);
    await screen.findByText("photos.zip");
    expect(listFileChecks).toHaveBeenCalledTimes(1);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(9_000);
    });
    expect(listFileChecks).toHaveBeenCalledTimes(1);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1_000);
    });
    expect(listFileChecks).toHaveBeenCalledTimes(2);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(10_000);
    });
    expect(listFileChecks).toHaveBeenCalledTimes(3);
    expect(row("photos.zip")).toHaveTextContent("No detections");

    // Nothing is moving any more: no further reads.
    await act(async () => {
      await vi.advanceTimersByTimeAsync(60_000);
    });
    expect(listFileChecks).toHaveBeenCalledTimes(3);
  });

  it("polling stops when the tab is closed", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    vi.mocked(listFileChecks).mockResolvedValue(answer([QUEUED]));
    const { unmount } = render(<FileChecksTab isOwner />);
    await screen.findByText("photos.zip");

    unmount();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(60_000);
    });
    expect(listFileChecks).toHaveBeenCalledTimes(1);
  });

  it("does not poll when nothing is waiting", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    vi.mocked(listFileChecks).mockResolvedValue(answer([CLEAN, MALICIOUS, TOO_BIG]));
    render(<FileChecksTab isOwner />);
    await screen.findByText("notes.pdf");

    await act(async () => {
      await vi.advanceTimersByTimeAsync(60_000);
    });
    expect(listFileChecks).toHaveBeenCalledTimes(1);
  });

  it("forget removes only its row and a failed forget keeps it with the reason", async () => {
    vi.mocked(listFileChecks).mockResolvedValue(answer([MALICIOUS, CLEAN]));
    vi.mocked(forgetFileCheck)
      .mockResolvedValueOnce(undefined)
      .mockRejectedValueOnce(new ApiError("Request failed: Internal Server Error", 500));
    render(<FileChecksTab isOwner />);

    fireEvent.click(await screen.findByRole("button", { name: "Forget invoice.pdf.exe" }));
    await waitFor(() => expect(screen.queryByText("invoice.pdf.exe")).not.toBeInTheDocument());
    expect(vi.mocked(forgetFileCheck).mock.calls).toEqual([["c-mal"]]);
    expect(row("notes.pdf")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Forget notes.pdf" }));
    const alert = await within(row("notes.pdf")).findByRole("alert");
    expect(alert).toHaveTextContent("Request failed: Internal Server Error");
    expect(vi.mocked(forgetFileCheck).mock.calls).toEqual([["c-mal"], ["c-clean"]]);
    expect(listFileChecks).toHaveBeenCalledTimes(1);
  });

  it("a forget the server no longer knows reads the list again", async () => {
    vi.mocked(listFileChecks)
      .mockResolvedValueOnce(answer([MALICIOUS, CLEAN]))
      .mockResolvedValueOnce(answer([CLEAN]));
    vi.mocked(forgetFileCheck).mockRejectedValue(new ApiError("No such file check.", 404));
    render(<FileChecksTab isOwner />);

    fireEvent.click(await screen.findByRole("button", { name: "Forget invoice.pdf.exe" }));

    await waitFor(() => expect(screen.queryByText("invoice.pdf.exe")).not.toBeInTheDocument());
    expect(listFileChecks).toHaveBeenCalledTimes(2);
    expect(row("notes.pdf")).toBeInTheDocument();
  });

  it("a failed load can be retried", async () => {
    vi.mocked(listFileChecks)
      .mockRejectedValueOnce(new Error("Request failed: Bad Gateway"))
      .mockResolvedValueOnce(answer([CLEAN]));
    render(<FileChecksTab isOwner />);

    expect(await screen.findByRole("alert")).toHaveTextContent("Request failed: Bad Gateway");
    expect(screen.queryByRole("button", { name: "Check a file…" })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Try again" }));

    expect(await screen.findByText("notes.pdf")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(listFileChecks).toHaveBeenCalledTimes(2);
  });

  it("shows a hidden-direction trick in a file name instead of obeying it", async () => {
    vi.mocked(listFileChecks).mockResolvedValue(
      answer([{ ...MALICIOUS, name: "invoice‮fdp.exe" }]),
    );
    render(<FileChecksTab isOwner />);

    expect(await screen.findByText("invoice�fdp.exe")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Forget invoice�fdp.exe" })).toBeInTheDocument();
  });
});
