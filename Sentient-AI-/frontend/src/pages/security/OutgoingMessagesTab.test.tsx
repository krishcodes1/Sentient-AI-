/**
 * Tests for OutgoingMessagesTab (Security ▸ Outgoing messages): they prove the tab says how many
 * addresses and domains Crawler remembers (counts only, as fingerprints) and that the checks being
 * off still leaves hidden characters removed, that Forget asks first and reports how many entries
 * went (or the server's reason, keeping the counts), that the owner adds a domain trimmed and
 * lower-cased and sees the server's reason for a refusal beside the form, that Remove asks first and
 * removes only its own row, that the sign-in domain cannot be removed, that a member sees the list
 * without any control, that the limit replaces the form, and that a failed load can be retried.
 *
 * Why it exists: "first time Crawler sends here" and "outside your organisation" on every approval
 * card rest on what this tab shows and edits. A history wiped without asking, a refusal the owner
 * never saw, a domain sent the way it was typed, or a member offered controls the server refuses
 * would each make those card notes wrong or the tab untrustworthy.
 */

import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { OrganisationDomain, OutboundSettings } from "@/types";

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
    getOutboundSettings: vi.fn(),
    forgetKnownRecipients: vi.fn(),
    addOrganisationDomain: vi.fn(),
    removeOrganisationDomain: vi.fn(),
  };
});

import OutgoingMessagesTab from "@/pages/security/OutgoingMessagesTab";
import {
  ApiError,
  addOrganisationDomain,
  forgetKnownRecipients,
  getOutboundSettings,
  removeOrganisationDomain,
} from "@/services/api";

const SINCE = "2026-10-14T09:12:00Z";
/** The day as the tab prints it, in whatever locale and time zone the test runs. */
const SINCE_DAY = new Date(SINCE).toLocaleDateString(undefined, {
  day: "numeric",
  month: "short",
  year: "numeric",
});

function domainRow(overrides: Partial<OrganisationDomain>): OrganisationDomain {
  return { id: "d1", domain: "acme.co.uk", added_at: "2026-10-14T09:20:00Z", ...overrides };
}

const ACME_UK = domainRow({});
const NORTHWIND = domainRow({ id: "d2", domain: "northwind.com" });

function settings(overrides: Partial<OutboundSettings> = {}): OutboundSettings {
  return {
    enabled: true,
    known: { addresses: 37, domains: 12, since: SINCE },
    own_domains: ["acme.com"],
    organisation_domains: [ACME_UK],
    can_edit_domains: true,
    domain_limit: 50,
    ...overrides,
  };
}

/** The rows of the organisation list, as one string each. */
function domainRows(): string[] {
  const list = screen.getByRole("list", { name: "Organisation domains" });
  return within(list)
    .getAllByRole("listitem")
    .map((row) => row.textContent ?? "");
}

describe("OutgoingMessagesTab", () => {
  afterEach(() => {
    vi.mocked(getOutboundSettings).mockReset();
    vi.mocked(forgetKnownRecipients).mockReset();
    vi.mocked(addOrganisationDomain).mockReset();
    vi.mocked(removeOrganisationDomain).mockReset();
  });

  it("shows how many addresses and domains Crawler remembers and says it keeps only fingerprints", async () => {
    vi.mocked(getOutboundSettings).mockResolvedValue(settings());
    render(<OutgoingMessagesTab isOwner />);

    expect(screen.getByRole("region", { name: "Outgoing messages" })).toBeInTheDocument();
    expect(screen.getByText("Loading outgoing message checks…")).toBeInTheDocument();
    expect(
      await screen.findByText(`Crawler has sent mail to 37 addresses at 12 domains for you since ${SINCE_DAY}.`),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        "It keeps one-way fingerprints, never the addresses, so it can tell you when a message goes to someone new.",
      ),
    ).toBeInTheDocument();
    expect(screen.getByText(/^Checks are on\./)).toBeInTheDocument();
    expect(screen.queryByText(/^Checks are off/)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Forget this history" })).toBeInTheDocument();
    expect(screen.queryByText("Loading outgoing message checks…")).not.toBeInTheDocument();
  });

  it("counts one address at one domain in the singular", async () => {
    vi.mocked(getOutboundSettings).mockResolvedValue(
      settings({ known: { addresses: 1, domains: 1, since: null } }),
    );
    render(<OutgoingMessagesTab isOwner />);

    expect(await screen.findByText("Crawler has sent mail to 1 address at 1 domain for you.")).toBeInTheDocument();
  });

  it("says plainly that hidden characters are still removed when the checks are off", async () => {
    vi.mocked(getOutboundSettings).mockResolvedValue(settings({ enabled: false }));
    render(<OutgoingMessagesTab isOwner />);

    expect(
      await screen.findByText(
        "Checks are off (Settings → Permissions). Hidden characters are still removed from everything Crawler sends.",
      ),
    ).toBeInTheDocument();
    expect(screen.queryByText(/^Checks are on\./)).not.toBeInTheDocument();
  });

  it("hides the forget button when nothing has been sent yet", async () => {
    vi.mocked(getOutboundSettings).mockResolvedValue(
      settings({ known: { addresses: 0, domains: 0, since: null } }),
    );
    render(<OutgoingMessagesTab isOwner />);

    expect(await screen.findByText("Crawler has not sent mail for you yet.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Forget this history" })).not.toBeInTheDocument();
  });

  it("forget asks first and only then clears the history and shows how many entries went", async () => {
    vi.mocked(getOutboundSettings).mockResolvedValue(settings());
    vi.mocked(forgetKnownRecipients).mockResolvedValue({ removed: 49 });
    render(<OutgoingMessagesTab isOwner />);

    // Cancel first: nothing is sent.
    fireEvent.click(await screen.findByRole("button", { name: "Forget this history" }));
    let dialog = await screen.findByRole("dialog");
    expect(dialog).toHaveTextContent("Forget the sent-to history?");
    expect(dialog).toHaveTextContent("Every address will count as new again.");
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(forgetKnownRecipients).not.toHaveBeenCalled();

    // Then confirm.
    fireEvent.click(screen.getByRole("button", { name: "Forget this history" }));
    dialog = await screen.findByRole("dialog");
    expect(forgetKnownRecipients).not.toHaveBeenCalled();
    fireEvent.click(within(dialog).getByRole("button", { name: "Forget" }));

    expect(await screen.findByText("Forgot 49 entries.")).toBeInTheDocument();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(vi.mocked(forgetKnownRecipients).mock.calls).toEqual([[]]);
    expect(screen.getByText("Crawler has not sent mail for you yet.")).toBeInTheDocument();
    expect(screen.queryByText(/Crawler has sent mail to/)).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Forget this history" })).not.toBeInTheDocument();
  });

  it("a failed forget shows the server's reason and keeps the counts", async () => {
    vi.mocked(getOutboundSettings).mockResolvedValue(settings());
    vi.mocked(forgetKnownRecipients).mockRejectedValue(
      new ApiError("The sent-to history could not be read. Try again in a minute.", 503),
    );
    render(<OutgoingMessagesTab isOwner />);

    fireEvent.click(await screen.findByRole("button", { name: "Forget this history" }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: "Forget" }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("The sent-to history could not be read. Try again in a minute.");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(
      screen.getByText(`Crawler has sent mail to 37 addresses at 12 domains for you since ${SINCE_DAY}.`),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Forget this history" })).toBeInTheDocument();
    expect(screen.queryByText(/^Forgot /)).not.toBeInTheDocument();
  });

  it("the owner adds a domain trimmed and lower-cased and it appears in the list", async () => {
    vi.mocked(getOutboundSettings).mockResolvedValue(settings());
    vi.mocked(addOrganisationDomain).mockResolvedValue(NORTHWIND);
    render(<OutgoingMessagesTab isOwner />);

    const box = await screen.findByLabelText("Domain to add");
    const add = screen.getByRole("button", { name: "Add" });
    expect(add).toBeDisabled();
    fireEvent.change(box, { target: { value: "   " } });
    expect(add).toBeDisabled();
    fireEvent.change(box, { target: { value: "  NorthWind.COM " } });
    expect(add).toBeEnabled();
    fireEvent.click(add);

    await waitFor(() => expect(domainRows()).toHaveLength(3));
    expect(vi.mocked(addOrganisationDomain).mock.calls).toEqual([["northwind.com"]]);
    expect(domainRows()[2]).toContain("northwind.com");
    expect(screen.getByRole("button", { name: "Remove northwind.com" })).toBeInTheDocument();
    expect(screen.getByLabelText("Domain to add")).toHaveValue("");
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("the server's reason for refusing a domain is shown beside the form", async () => {
    vi.mocked(getOutboundSettings).mockResolvedValue(settings());
    vi.mocked(addOrganisationDomain).mockRejectedValue(
      new ApiError("gmail.com is a public mail service, so it cannot be your organisation's domain.", 422),
    );
    render(<OutgoingMessagesTab isOwner />);

    fireEvent.change(await screen.findByLabelText("Domain to add"), { target: { value: "gmail.com" } });
    fireEvent.click(screen.getByRole("button", { name: "Add" }));

    const form = screen.getByRole("form", { name: "Add an organisation domain" });
    const alert = await within(form).findByRole("alert");
    expect(alert).toHaveTextContent(
      "gmail.com is a public mail service, so it cannot be your organisation's domain.",
    );
    expect(screen.getByLabelText("Domain to add")).toHaveValue("gmail.com");
    expect(domainRows()).toHaveLength(2);
  });

  it("shows a 409 for a domain already listed as the server words it", async () => {
    vi.mocked(getOutboundSettings).mockResolvedValue(settings());
    vi.mocked(addOrganisationDomain).mockRejectedValue(new ApiError("acme.co.uk is already listed.", 409));
    render(<OutgoingMessagesTab isOwner />);

    fireEvent.change(await screen.findByLabelText("Domain to add"), { target: { value: "acme.co.uk" } });
    fireEvent.click(screen.getByRole("button", { name: "Add" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("acme.co.uk is already listed.");
    expect(domainRows()).toHaveLength(2);
  });

  it("remove asks first and removes only its own row", async () => {
    vi.mocked(getOutboundSettings).mockResolvedValue(
      settings({ organisation_domains: [ACME_UK, NORTHWIND] }),
    );
    vi.mocked(removeOrganisationDomain).mockResolvedValue(undefined);
    render(<OutgoingMessagesTab isOwner />);

    fireEvent.click(await screen.findByRole("button", { name: "Remove acme.co.uk" }));
    const dialog = await screen.findByRole("dialog");
    expect(removeOrganisationDomain).not.toHaveBeenCalled();
    expect(dialog).toHaveTextContent("Remove acme.co.uk?");
    expect(dialog).toHaveTextContent("Mail there will count as outside your organisation.");
    fireEvent.click(within(dialog).getByRole("button", { name: "Remove" }));

    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(vi.mocked(removeOrganisationDomain).mock.calls).toEqual([["d1"]]);
    const rows = domainRows();
    expect(rows).toHaveLength(2);
    expect(rows[0]).toContain("acme.com");
    expect(rows[1]).toContain("northwind.com");
    expect(screen.queryByText("acme.co.uk")).not.toBeInTheDocument();
  });

  it("a failed remove keeps the row and shows the server's reason in the dialog", async () => {
    vi.mocked(getOutboundSettings).mockResolvedValue(settings());
    vi.mocked(removeOrganisationDomain).mockRejectedValue(
      new ApiError("The server is still starting. Try again shortly.", 503),
    );
    render(<OutgoingMessagesTab isOwner />);

    fireEvent.click(await screen.findByRole("button", { name: "Remove acme.co.uk" }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: "Remove" }));

    expect(
      await within(dialog).findByText("The server is still starting. Try again shortly."),
    ).toBeInTheDocument();
    expect(domainRows()).toHaveLength(2);
  });

  it("a domain someone else already removed leaves the list without an error", async () => {
    vi.mocked(getOutboundSettings).mockResolvedValue(settings());
    vi.mocked(removeOrganisationDomain).mockRejectedValue(new ApiError("No such domain.", 404));
    render(<OutgoingMessagesTab isOwner />);

    fireEvent.click(await screen.findByRole("button", { name: "Remove acme.co.uk" }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: "Remove" }));

    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(domainRows()).toHaveLength(1);
    expect(screen.queryByText("acme.co.uk")).not.toBeInTheDocument();
    expect(screen.queryByText("No such domain.")).not.toBeInTheDocument();
  });

  it("someone who is not the owner sees the list without add or remove", async () => {
    vi.mocked(getOutboundSettings).mockResolvedValue(
      settings({ organisation_domains: [ACME_UK, NORTHWIND], can_edit_domains: false }),
    );
    render(<OutgoingMessagesTab isOwner={false} />);

    expect(await screen.findByText("Only the owner can change this list.")).toBeInTheDocument();
    const rows = domainRows();
    expect(rows).toHaveLength(3);
    expect(rows[1]).toContain("acme.co.uk");
    expect(rows[2]).toContain("northwind.com");
    expect(screen.queryByRole("button", { name: /^Remove/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Add" })).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Domain to add")).not.toBeInTheDocument();
    // Forgetting is the member's own history, so it stays.
    expect(screen.getByRole("button", { name: "Forget this history" })).toBeInTheDocument();
  });

  it("an owner the server does not let edit the list gets no controls either", async () => {
    vi.mocked(getOutboundSettings).mockResolvedValue(settings({ can_edit_domains: false }));
    render(<OutgoingMessagesTab isOwner />);

    expect(await screen.findByText("Only the owner can change this list.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^Remove/ })).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Domain to add")).not.toBeInTheDocument();
  });

  it("the sign-in domain is listed as from your sign-in email and cannot be removed", async () => {
    vi.mocked(getOutboundSettings).mockResolvedValue(settings());
    render(<OutgoingMessagesTab isOwner />);

    await screen.findByText("acme.com");
    const rows = domainRows();
    expect(rows[0]).toBe("acme.comfrom your sign-in email");
    const signIn = within(screen.getByRole("list", { name: "Organisation domains" })).getAllByRole("listitem")[0];
    expect(within(signIn).queryByRole("button")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Remove acme.com" })).not.toBeInTheDocument();
    expect(rows[1]).toContain("acme.co.uk");
    expect(screen.getByRole("button", { name: "Remove acme.co.uk" })).toBeInTheDocument();
  });

  it("at the domain limit the add form is replaced by the limit sentence", async () => {
    vi.mocked(getOutboundSettings).mockResolvedValue(
      settings({ organisation_domains: [ACME_UK, NORTHWIND], domain_limit: 2 }),
    );
    vi.mocked(removeOrganisationDomain).mockResolvedValue(undefined);
    render(<OutgoingMessagesTab isOwner />);

    expect(await screen.findByText("You can list at most 2 domains.")).toBeInTheDocument();
    expect(screen.queryByLabelText("Domain to add")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Add" })).not.toBeInTheDocument();

    // Removing one brings the form back.
    fireEvent.click(screen.getByRole("button", { name: "Remove northwind.com" }));
    fireEvent.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Remove" }));
    expect(await screen.findByLabelText("Domain to add")).toBeInTheDocument();
    expect(screen.queryByText("You can list at most 2 domains.")).not.toBeInTheDocument();
  });

  it("says when no domain is listed at all", async () => {
    vi.mocked(getOutboundSettings).mockResolvedValue(
      settings({ own_domains: [], organisation_domains: [] }),
    );
    render(<OutgoingMessagesTab isOwner />);

    expect(
      await screen.findByText("No domains are listed, so no message is marked as going outside your organisation."),
    ).toBeInTheDocument();
    expect(screen.queryByRole("list", { name: "Organisation domains" })).not.toBeInTheDocument();
    expect(screen.getByLabelText("Domain to add")).toBeInTheDocument();
  });

  it("a load error offers retry and retry loads the settings", async () => {
    vi.mocked(getOutboundSettings)
      .mockRejectedValueOnce(new ApiError("The server is still starting.", 503))
      .mockResolvedValueOnce(settings());
    render(<OutgoingMessagesTab isOwner />);

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("The server is still starting.");
    fireEvent.click(within(alert).getByRole("button", { name: "Retry" }));

    expect(
      await screen.findByText(`Crawler has sent mail to 37 addresses at 12 domains for you since ${SINCE_DAY}.`),
    ).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(getOutboundSettings).toHaveBeenCalledTimes(2);
  });

  it("a load error without a server message says the settings could not be loaded", async () => {
    vi.mocked(getOutboundSettings).mockRejectedValue(new Error(""));
    render(<OutgoingMessagesTab isOwner />);

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "The outgoing message settings could not be loaded.",
    );
  });
});
