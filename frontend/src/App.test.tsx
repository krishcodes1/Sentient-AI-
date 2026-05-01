import { describe, expect, it } from "vitest";
import { screen } from "@testing-library/react";
import App from "./App";
import { renderWithProviders } from "./test/utils";

describe("App", () => {
  it("renders the login page when navigating to /login", () => {
    renderWithProviders(<App />, { initialEntries: ["/login"] });
    const emailInput = screen.getByPlaceholderText(/you@example\.com/i);
    expect(emailInput).toBeInTheDocument();
    expect(emailInput).toHaveAttribute("type", "email");
  });
});
