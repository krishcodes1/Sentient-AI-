import { describe, expect, it, vi } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Route, Routes } from "react-router-dom";
import Login from "./Login";
import { renderWithProviders } from "@/test/utils";

function LocationProbe() {
  return <div data-testid="dashboard-route">dashboard</div>;
}

function GatewayProbe() {
  return <div data-testid="gateway-route">gateway</div>;
}

describe("Login page", () => {
  it("submits credentials and navigates to /gateway after successful login", async () => {
    const user = userEvent.setup();

    renderWithProviders(
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/gateway" element={<GatewayProbe />} />
        <Route path="/dashboard" element={<LocationProbe />} />
      </Routes>,
      { initialEntries: ["/login"] },
    );

    await user.type(screen.getByPlaceholderText(/you@example\.com/i), "test@sentient.ai");
    await user.type(screen.getByPlaceholderText(/min\. 8 characters/i), "supersecret");
    await user.click(screen.getByRole("button", { name: /sign in/i }));

    await waitFor(() => {
      expect(screen.getByTestId("gateway-route")).toBeInTheDocument();
    });
    expect(localStorage.getItem("auth_token")).toBeTruthy();
  });

  it("shows an error when login fails", async () => {
    const user = userEvent.setup();
    const { server } = await import("@/test/server");
    const { http, HttpResponse } = await import("msw");
    server.use(
      http.post("/api/auth/login", () =>
        HttpResponse.json({ detail: "Invalid credentials" }, { status: 401 }),
      ),
    );

    // Silence console errors from the failed fetch path during this assertion.
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    renderWithProviders(<Login />, { initialEntries: ["/login"] });
    await user.type(screen.getByPlaceholderText(/you@example\.com/i), "test@sentient.ai");
    await user.type(screen.getByPlaceholderText(/min\. 8 characters/i), "wrongpass");
    await user.click(screen.getByRole("button", { name: /sign in/i }));

    await waitFor(() => {
      expect(screen.getByText(/invalid credentials/i)).toBeInTheDocument();
    });
    errorSpy.mockRestore();
  });
});
