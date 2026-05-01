import { describe, expect, it, beforeEach } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import AuditLogs from "./AuditLogs";
import { renderWithProviders } from "@/test/utils";
import { MOCK_TOKEN } from "@/test/handlers";

describe("AuditLogs page", () => {
  beforeEach(() => {
    localStorage.setItem("sai.access_token", MOCK_TOKEN);
  });

  it("shows skeleton rows while loading", () => {
    renderWithProviders(<AuditLogs />, { initialEntries: ["/audit"] });
    // Filters render synchronously
    expect(screen.getByLabelText(/search action/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/^status$/i)).toBeInTheDocument();
  });

  it("renders the audit log row from the API after load", async () => {
    renderWithProviders(<AuditLogs />, { initialEntries: ["/audit"] });

    await waitFor(() => {
      expect(screen.getByText("message_received")).toBeInTheDocument();
      expect(screen.getByText("Telegram")).toBeInTheDocument();
    });
  });

  it("shows the verified chain integrity banner when valid", async () => {
    renderWithProviders(<AuditLogs />, { initialEntries: ["/audit"] });
    await waitFor(() => {
      expect(screen.getByText(/chain integrity: verified/i)).toBeInTheDocument();
    });
  });
});
