import { useState, useRef, useEffect } from "react";
import {
  Send,
  Plus,
  Bot,
  User,
  CheckCircle2,
  XCircle,
  Clock,
  Shield,
  ChevronRight,
} from "lucide-react";
import clsx from "clsx";
import type { Message, ToolCall, PendingApproval } from "@/types";

interface ConversationPreview {
  id: string;
  title: string;
  lastMessage: string;
  timestamp: string;
}

const mockConversations: ConversationPreview[] = [
  { id: "1", title: "Assignment deadlines", lastMessage: "Here are your upcoming due dates...", timestamp: "2m ago" },
  { id: "2", title: "Grade analysis", lastMessage: "Your GPA trend shows...", timestamp: "1h ago" },
  { id: "3", title: "Portfolio check", lastMessage: "Your crypto holdings are...", timestamp: "3h ago" },
];

const mockMessages: Message[] = [
  {
    id: "1",
    conversation_id: "1",
    role: "user",
    content: "What assignments do I have due this week?",
    timestamp: "2024-04-06T10:00:00Z",
  },
  {
    id: "2",
    conversation_id: "1",
    role: "assistant",
    content: "I'll check your Canvas LMS for upcoming assignments. Let me fetch your course data.",
    tool_calls: [
      { id: "tc1", connector: "Canvas LMS", action: "get_assignments", endpoint: "/api/v1/courses/assignments", status: "success", result: "Found 3 assignments" },
    ],
    timestamp: "2024-04-06T10:00:05Z",
  },
  {
    id: "3",
    conversation_id: "1",
    role: "assistant",
    content: "Here are your upcoming assignments this week:\n\n1. **CSCI335 - Algorithm Analysis HW5** - Due Wednesday, Apr 9\n2. **CSCI300 - Database Project Milestone 2** - Due Thursday, Apr 10\n3. **CSCI270 - Probability Problem Set 4** - Due Friday, Apr 11\n\nWould you like me to create calendar events for these deadlines?",
    pending_approvals: [
      { id: "pa1", connector: "Google Calendar", action: "create_events", scope: "calendar.events", risk_level: "write", reasoning: "Creating calendar events requires write access to Google Calendar" },
    ],
    timestamp: "2024-04-06T10:00:10Z",
  },
];

function ToolCallBadge({ tc }: { tc: ToolCall }) {
  const colors = {
    success: { bg: "rgba(34,197,94,0.1)", text: "var(--accent-success)" },
    blocked: { bg: "rgba(239,68,68,0.1)", text: "var(--accent-danger)" },
    pending: { bg: "rgba(245,158,11,0.1)", text: "var(--accent-warning)" },
    error: { bg: "rgba(239,68,68,0.1)", text: "var(--accent-danger)" },
  };
  const c = colors[tc.status];
  const Icon = tc.status === "success" ? CheckCircle2 : tc.status === "blocked" ? XCircle : Clock;

  return (
    <div
      className="flex items-center gap-2 px-3 py-2 rounded-lg text-xs"
      style={{ backgroundColor: c.bg, border: `1px solid ${c.text}20` }}
    >
      <Icon className="w-3.5 h-3.5" style={{ color: c.text }} />
      <span style={{ color: c.text }} className="font-medium">
        {tc.connector}
      </span>
      <ChevronRight className="w-3 h-3" style={{ color: "var(--text-muted)" }} />
      <span style={{ color: "var(--text-secondary)" }}>{tc.action}</span>
    </div>
  );
}

function ApprovalCard({ approval }: { approval: PendingApproval }) {
  return (
    <div
      className="rounded-lg border p-3 mt-2"
      style={{
        backgroundColor: "rgba(245,158,11,0.05)",
        borderColor: "rgba(245,158,11,0.2)",
      }}
    >
      <div className="flex items-center gap-2 mb-2">
        <Shield className="w-4 h-4" style={{ color: "var(--accent-warning)" }} />
        <span className="text-xs font-semibold" style={{ color: "var(--accent-warning)" }}>
          Approval Required
        </span>
        <span
          className="text-xs px-1.5 py-0.5 rounded"
          style={{
            backgroundColor: "rgba(245,158,11,0.15)",
            color: "var(--accent-warning)",
          }}
        >
          {approval.risk_level}
        </span>
      </div>
      <p className="text-xs mb-2" style={{ color: "var(--text-secondary)" }}>
        <strong>{approval.connector}</strong> wants to <strong>{approval.action}</strong> (scope: {approval.scope})
      </p>
      <p className="text-xs mb-3" style={{ color: "var(--text-muted)" }}>
        {approval.reasoning}
      </p>
      <div className="flex gap-2">
        <button
          className="px-3 py-1.5 rounded-md text-xs font-medium text-white"
          style={{ backgroundColor: "var(--accent-success)" }}
        >
          Approve
        </button>
        <button
          className="px-3 py-1.5 rounded-md text-xs font-medium border"
          style={{
            borderColor: "var(--accent-danger)",
            color: "var(--accent-danger)",
          }}
        >
          Deny
        </button>
      </div>
    </div>
  );
}

export default function Chat() {
  const [activeConv, setActiveConv] = useState("1");
  const [input, setInput] = useState("");
  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [mockMessages]);

  const handleSend = (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim()) return;
    // In production, this would call sendMessage API
    setInput("");
  };

  return (
    <div
      className="flex h-[calc(100vh-3rem)] rounded-xl border overflow-hidden"
      style={{
        backgroundColor: "var(--bg-secondary)",
        borderColor: "var(--border-primary)",
      }}
    >
      {/* Conversation List */}
      <div
        className="w-72 border-r flex flex-col shrink-0"
        style={{ borderColor: "var(--border-primary)" }}
      >
        <div className="p-4 border-b" style={{ borderColor: "var(--border-primary)" }}>
          <button
            className="w-full flex items-center justify-center gap-2 py-2 rounded-lg text-sm font-medium text-white"
            style={{ backgroundColor: "var(--accent-primary)" }}
          >
            <Plus className="w-4 h-4" /> New Chat
          </button>
        </div>
        <div className="flex-1 overflow-y-auto">
          {mockConversations.map((conv) => (
            <button
              key={conv.id}
              onClick={() => setActiveConv(conv.id)}
              className={clsx("w-full text-left px-4 py-3 border-b transition-colors")}
              style={{
                borderColor: "var(--border-primary)",
                backgroundColor: activeConv === conv.id ? "var(--bg-hover)" : "transparent",
              }}
            >
              <div className="flex items-center justify-between">
                <span
                  className="text-sm font-medium truncate"
                  style={{ color: "var(--text-primary)" }}
                >
                  {conv.title}
                </span>
                <span className="text-xs shrink-0" style={{ color: "var(--text-muted)" }}>
                  {conv.timestamp}
                </span>
              </div>
              <p
                className="text-xs mt-1 truncate"
                style={{ color: "var(--text-muted)" }}
              >
                {conv.lastMessage}
              </p>
            </button>
          ))}
        </div>
      </div>

      {/* Chat Area */}
      <div className="flex-1 flex flex-col">
        {/* Messages */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {mockMessages.map((msg) => (
            <div
              key={msg.id}
              className={clsx("flex gap-3", msg.role === "user" ? "justify-end" : "")}
            >
              {msg.role === "assistant" && (
                <div
                  className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0"
                  style={{ backgroundColor: "rgba(99,102,241,0.15)" }}
                >
                  <Bot className="w-4 h-4" style={{ color: "var(--accent-primary)" }} />
                </div>
              )}
              <div
                className={clsx("max-w-[70%] rounded-xl px-4 py-3")}
                style={{
                  backgroundColor:
                    msg.role === "user"
                      ? "var(--accent-primary)"
                      : "var(--bg-primary)",
                  border: msg.role === "assistant" ? "1px solid var(--border-primary)" : "none",
                }}
              >
                <p
                  className="text-sm whitespace-pre-wrap"
                  style={{
                    color: msg.role === "user" ? "#fff" : "var(--text-primary)",
                  }}
                >
                  {msg.content}
                </p>
                {/* Tool calls */}
                {msg.tool_calls && msg.tool_calls.length > 0 && (
                  <div className="mt-2 space-y-1">
                    {msg.tool_calls.map((tc) => (
                      <ToolCallBadge key={tc.id} tc={tc} />
                    ))}
                  </div>
                )}
                {/* Pending approvals */}
                {msg.pending_approvals && msg.pending_approvals.length > 0 && (
                  <div className="mt-2">
                    {msg.pending_approvals.map((pa) => (
                      <ApprovalCard key={pa.id} approval={pa} />
                    ))}
                  </div>
                )}
              </div>
              {msg.role === "user" && (
                <div
                  className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0"
                  style={{ backgroundColor: "rgba(99,102,241,0.3)" }}
                >
                  <User className="w-4 h-4" style={{ color: "var(--accent-primary)" }} />
                </div>
              )}
            </div>
          ))}
          <div ref={messagesEndRef} />
        </div>

        {/* Input */}
        <form
          onSubmit={handleSend}
          className="p-4 border-t"
          style={{ borderColor: "var(--border-primary)" }}
        >
          <div
            className="flex items-center gap-3 rounded-xl border px-4 py-2"
            style={{
              backgroundColor: "var(--bg-input)",
              borderColor: "var(--border-primary)",
            }}
          >
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Ask SentientAI anything..."
              className="flex-1 bg-transparent outline-none text-sm"
              style={{ color: "var(--text-primary)" }}
            />
            <button
              type="submit"
              className="w-8 h-8 rounded-lg flex items-center justify-center transition-colors"
              style={{
                backgroundColor: input.trim()
                  ? "var(--accent-primary)"
                  : "transparent",
              }}
            >
              <Send
                className="w-4 h-4"
                style={{
                  color: input.trim() ? "#fff" : "var(--text-muted)",
                }}
              />
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
