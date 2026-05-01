import { http, HttpResponse } from "msw";

export const MOCK_USER = {
  id: "user_test_1",
  email: "test@sentient.ai",
  name: "Test User",
  is_active: true,
  llm_provider: "anthropic",
  llm_model: "claude-3-5-sonnet",
  onboarding_completed: true,
  email_verified_at: "2026-04-01T00:00:00Z",
  created_at: "2026-01-01T00:00:00Z",
};

export const MOCK_TOKEN = "test-token-abc123";

const authResponse = {
  access_token: MOCK_TOKEN,
  token_type: "bearer",
  user: MOCK_USER,
};

const sampleConversation = {
  id: "conv_1",
  title: "Sample conversation",
  created_at: "2026-04-01T12:00:00Z",
  updated_at: "2026-04-01T12:30:00Z",
};

const sampleConversationDetail = {
  ...sampleConversation,
  messages: [
    {
      id: "msg_1",
      conversation_id: "conv_1",
      role: "user",
      content: "Hi there",
    },
    {
      id: "msg_2",
      conversation_id: "conv_1",
      role: "assistant",
      content: "Hello! How can I help?",
    },
  ],
};

const sampleChannel = {
  id: "ch_1",
  channel_type: "telegram",
  display_name: "Primary Telegram",
  is_enabled: true,
  status: "ok",
  last_error: null,
  config_meta: { bot_username: "sentient_bot", has_bot_token: true, bot_token_preview: "abc***" },
  created_at: "2026-03-01T00:00:00Z",
  updated_at: "2026-04-01T00:00:00Z",
};

const sampleAuditLog = {
  id: "audit_1",
  connector_id: "telegram",
  connector_name: "Telegram",
  action: "message_received",
  endpoint: "/messages",
  scope: "read",
  status: "approved",
  decision_method: "auto",
  reasoning: "Within policy",
  integrity_hash: "deadbeef",
  integrity_valid: true,
  timestamp: "2026-04-30T10:00:00Z",
  user_id: MOCK_USER.id,
};

const sampleConnector = {
  id: "conn_1",
  name: "Canvas LMS",
  type: "canvas",
  auth_method: "oauth2",
  status: "connected",
  is_enabled: true,
  scopes: [],
  permission_tier: "supervised",
  base_url: "https://canvas.example",
  created_at: "2026-02-01T00:00:00Z",
};

const auditStats = {
  last_24h_count: 142,
  approved_24h: 135,
  blocked_24h: 7,
  total: 142,
  approved: 135,
  blocked: 7,
  pending: 0,
  by_connector: { Telegram: 142 },
  timeline: [
    { date: "Apr 30", approved: 50, blocked: 1 },
    { date: "May 01", approved: 85, blocked: 6 },
  ],
};

const openclawStatus = {
  gateway_online: true,
  gateway_url: "http://127.0.0.1:18789",
  channels_configured: 1,
  details: {},
};

export const handlers = [
  http.post("/api/auth/login", async ({ request }) => {
    const body = (await request.json()) as { email?: string; password?: string };
    if (!body?.email || !body?.password) {
      return HttpResponse.json({ detail: "Missing credentials" }, { status: 400 });
    }
    return HttpResponse.json(authResponse);
  }),

  http.post("/api/auth/register", async ({ request }) => {
    const body = (await request.json()) as { email?: string; password?: string; name?: string };
    if (!body?.email || !body?.password) {
      return HttpResponse.json({ detail: "Missing credentials" }, { status: 400 });
    }
    return HttpResponse.json({
      ...authResponse,
      user: { ...MOCK_USER, email: body.email, name: body.name ?? null, onboarding_completed: false },
    });
  }),

  http.get("/api/auth/me", () => HttpResponse.json(MOCK_USER)),

  http.patch("/api/auth/settings", async ({ request }) => {
    const body = (await request.json()) as Record<string, unknown>;
    return HttpResponse.json({ ...MOCK_USER, ...body });
  }),

  http.post("/api/auth/logout", () => HttpResponse.json({ status: "ok" })),

  http.get("/api/agent/conversations", () => HttpResponse.json([sampleConversation])),

  http.post("/api/agent/conversations", async ({ request }) => {
    const body = (await request.json()) as { title?: string };
    return HttpResponse.json({
      ...sampleConversation,
      id: `conv_${Date.now()}`,
      title: body?.title ?? "Untitled",
    });
  }),

  http.get("/api/agent/conversations/:id", () => HttpResponse.json(sampleConversationDetail)),

  http.post("/api/agent/conversations/:id/messages", async ({ request, params }) => {
    const body = (await request.json()) as { content?: string };
    return HttpResponse.json({
      user_message: {
        id: `msg-u-${Date.now()}`,
        conversation_id: String(params.id),
        role: "user",
        content: body?.content ?? "",
      },
      assistant_message: {
        id: `msg-a-${Date.now()}`,
        conversation_id: String(params.id),
        role: "assistant",
        content: "OK.",
      },
    });
  }),

  http.get("/api/channels", () => HttpResponse.json([sampleChannel])),
  http.post("/api/channels", async ({ request }) => {
    const body = (await request.json()) as Record<string, unknown>;
    return HttpResponse.json({
      ...sampleChannel,
      id: `ch_${Date.now()}`,
      ...body,
    });
  }),
  http.patch("/api/channels/:id", async ({ request, params }) => {
    const body = (await request.json()) as Record<string, unknown>;
    return HttpResponse.json({ ...sampleChannel, id: String(params.id), ...body });
  }),
  http.delete("/api/channels/:id", () => new HttpResponse(null, { status: 204 })),

  http.get("/api/channels/openclaw/status", () => HttpResponse.json(openclawStatus)),
  http.post("/api/channels/openclaw/restart", () => HttpResponse.json({ status: "ok" })),
  http.get("/api/openclaw/embed-url", () =>
    HttpResponse.json({ url: "http://127.0.0.1:18789/" }),
  ),

  http.get("/api/connectors", () => HttpResponse.json([sampleConnector])),

  http.get("/api/audit", ({ request }) => {
    const url = new URL(request.url);
    const action = url.searchParams.get("action");
    if (action && action !== sampleAuditLog.action) {
      return HttpResponse.json([]);
    }
    return HttpResponse.json([sampleAuditLog]);
  }),
  http.get("/api/audit/stats", () => HttpResponse.json(auditStats)),
  http.get("/api/audit/verify-chain", () => HttpResponse.json({ valid: true })),
];
