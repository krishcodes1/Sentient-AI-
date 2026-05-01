import { describe, expect, it, beforeEach } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { server } from "@/test/server";
import { renderWithProviders } from "@/test/utils";
import Connectors from "./Connectors";

interface MockConnector {
  id: string;
  connector_type: "canvas" | "google" | "robinhood";
  display_name: string;
  granted_scopes: string[];
  permission_tier: "auto_approve" | "confirm_on_write" | "always_confirm" | "disabled";
  status: "connected" | "error" | "unauthorized" | "pending_oauth";
  is_enabled: boolean;
  last_used_at?: string | null;
  last_error?: string | null;
  created_at: string;
}

function mockConnectorsList(initial: MockConnector[] = []) {
  let store = [...initial];
  server.use(
    http.get("/api/connectors", () => HttpResponse.json(store)),
    http.get("/api/connectors/:id", ({ params }) => {
      const found = store.find((c) => c.id === params.id);
      if (!found) return HttpResponse.json({ detail: "Not found" }, { status: 404 });
      return HttpResponse.json(found);
    }),
    http.post("/api/connectors", async ({ request }) => {
      const body = (await request.json()) as {
        connector_type: MockConnector["connector_type"];
        permission_tier: MockConnector["permission_tier"];
        granted_scopes: string[];
      };
      const created: MockConnector = {
        id: `conn_${Date.now()}`,
        connector_type: body.connector_type,
        display_name:
          body.connector_type === "canvas"
            ? "Canvas LMS"
            : body.connector_type === "google"
              ? "Google Workspace"
              : "Robinhood",
        granted_scopes: body.granted_scopes,
        permission_tier: body.permission_tier,
        status: "connected",
        is_enabled: true,
        created_at: new Date().toISOString(),
      };
      store = [created, ...store];
      // Robinhood doesn't need OAuth in this mock; canvas/google do.
      if (body.connector_type === "robinhood") {
        return HttpResponse.json({ success: true, connector: created });
      }
      return HttpResponse.json({ auth_url: "https://example.test/oauth/authorize?x=1" });
    }),
    http.patch("/api/connectors/:id", async ({ params, request }) => {
      const patch = (await request.json()) as Partial<MockConnector>;
      const idx = store.findIndex((c) => c.id === params.id);
      if (idx === -1) return HttpResponse.json({ detail: "Not found" }, { status: 404 });
      store[idx] = { ...store[idx], ...patch };
      return HttpResponse.json(store[idx]);
    }),
    http.delete("/api/connectors/:id", ({ params }) => {
      store = store.filter((c) => c.id !== params.id);
      return new HttpResponse(null, { status: 204 });
    }),
  );
}

describe("Connectors page", () => {
  beforeEach(() => {
    localStorage.setItem("auth_token", "test-token-abc123");
  });

  it("renders the page with accessible tabs", async () => {
    mockConnectorsList([]);
    renderWithProviders(<Connectors />);

    expect(
      await screen.findByRole("heading", { name: /connectors/i, level: 1 }),
    ).toBeInTheDocument();

    const tablist = screen.getByRole("tablist", { name: /connectors view/i });
    const tabs = within(tablist).getAllByRole("tab");
    expect(tabs).toHaveLength(2);
    expect(tabs[0]).toHaveAttribute("aria-selected", "true");
    expect(tabs[1]).toHaveAttribute("aria-selected", "false");
  });

  it("shows the empty state when there are no connectors", async () => {
    mockConnectorsList([]);
    renderWithProviders(<Connectors />);
    expect(await screen.findByText(/no connectors yet/i)).toBeInTheDocument();
  });

  it("opens the connect modal and steps through the flow", async () => {
    mockConnectorsList([]);
    const user = userEvent.setup();
    renderWithProviders(<Connectors />);

    await user.click(screen.getByRole("tab", { name: /add new/i }));
    await user.click(screen.getByRole("button", { name: /^connect$/i, hidden: false }));

    const dialog = await screen.findByRole("dialog");
    expect(dialog).toHaveAttribute("aria-modal", "true");

    // Step 1 → 2
    await user.click(within(dialog).getByRole("button", { name: /continue/i }));
    expect(within(dialog).getByLabelText(/permission tier/i)).toBeInTheDocument();

    // Step 2 → 3
    await user.click(within(dialog).getByRole("button", { name: /continue/i }));
    expect(within(dialog).getByText(/review & connect/i)).toBeInTheDocument();
  });

  it("submits createConnector with the correct payload (Robinhood)", async () => {
    mockConnectorsList([]);

    let received:
      | { connector_type: string; permission_tier: string; granted_scopes: string[] }
      | null = null;
    server.use(
      http.post("/api/connectors", async ({ request }) => {
        received = (await request.json()) as typeof received;
        return HttpResponse.json({
          success: true,
          connector: {
            id: "conn_robin",
            connector_type: "robinhood",
            display_name: "Robinhood",
            granted_scopes: received!.granted_scopes,
            permission_tier: received!.permission_tier,
            status: "connected",
            is_enabled: true,
            created_at: new Date().toISOString(),
          },
        });
      }),
    );

    const user = userEvent.setup();
    renderWithProviders(<Connectors />);
    await user.click(screen.getByRole("tab", { name: /add new/i }));

    // Click the Robinhood card's Connect button.
    const cards = screen.getAllByRole("article");
    const robinCard = cards.find((c) => within(c).queryByText(/robinhood/i));
    expect(robinCard).toBeDefined();
    await user.click(within(robinCard!).getByRole("button", { name: /connect/i }));

    const dialog = await screen.findByRole("dialog");
    await user.click(within(dialog).getByRole("button", { name: /continue/i }));
    await user.click(within(dialog).getByRole("button", { name: /continue/i }));
    await user.click(within(dialog).getByRole("button", { name: /connect robinhood/i }));

    await waitFor(() => {
      expect(received).not.toBeNull();
    });
    expect(received!.connector_type).toBe("robinhood");
    expect(Array.isArray(received!.granted_scopes)).toBe(true);
    expect(received!.granted_scopes.length).toBeGreaterThan(0);
  });

  it("disconnect confirmation flow calls deleteConnector", async () => {
    mockConnectorsList([
      {
        id: "conn_canvas_1",
        connector_type: "canvas",
        display_name: "Canvas LMS",
        granted_scopes: ["courses.read"],
        permission_tier: "auto_approve",
        status: "connected",
        is_enabled: true,
        created_at: "2026-04-01T00:00:00Z",
      },
    ]);

    const user = userEvent.setup();
    renderWithProviders(<Connectors />);

    expect(await screen.findByText("Canvas LMS")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /disconnect canvas lms/i }));
    const dialog = await screen.findByRole("dialog");
    expect(
      within(dialog).getByText(/this revokes/i),
    ).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: /^disconnect$/i }));

    await waitFor(() => {
      expect(screen.queryByText("Canvas LMS")).not.toBeInTheDocument();
    });
    expect(screen.getByText(/no connectors yet/i)).toBeInTheDocument();
  });

  it("shows the Robinhood permanent-block warning banner", async () => {
    mockConnectorsList([]);
    const user = userEvent.setup();
    renderWithProviders(<Connectors />);

    await user.click(screen.getByRole("tab", { name: /add new/i }));
    const cards = screen.getAllByRole("article");
    const robinCard = cards.find((c) => within(c).queryByText(/robinhood/i));
    await user.click(within(robinCard!).getByRole("button", { name: /connect/i }));

    const dialog = await screen.findByRole("dialog");
    expect(
      within(dialog).getByText(/permanently blocked at the/i),
    ).toBeInTheDocument();
    expect(
      within(dialog).getByText(/this is a feature, not a bug/i),
    ).toBeInTheDocument();
  });
});
