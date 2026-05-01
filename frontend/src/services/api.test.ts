import { describe, expect, it } from "vitest";
import { getMe, login } from "./api";
import { MOCK_TOKEN, MOCK_USER } from "@/test/handlers";

describe("api service", () => {
  it("login() stores the auth token in localStorage", async () => {
    const result = await login({ email: "test@sentient.ai", password: "supersecret" });
    expect(result.access_token).toBe(MOCK_TOKEN);
    expect(localStorage.getItem("auth_token")).toBe(MOCK_TOKEN);
    const storedUser = JSON.parse(localStorage.getItem("user") ?? "null");
    expect(storedUser).toMatchObject({ email: MOCK_USER.email });
  });

  it("getMe() returns the current user when the token is valid", async () => {
    localStorage.setItem("auth_token", MOCK_TOKEN);
    const me = await getMe();
    expect(me).toMatchObject({ id: MOCK_USER.id, email: MOCK_USER.email });
  });

  it("getMe() throws an ApiError when the token is invalid", async () => {
    localStorage.setItem("auth_token", "definitely-not-a-real-token");
    await expect(getMe()).rejects.toThrow();
  });
});
