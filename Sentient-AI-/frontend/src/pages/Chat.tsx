import { useEffect, useRef, useState, type FormEvent } from "react";
import {
  Send,
  Plus,
  Bot,
  User as UserIcon,
  CheckCircle2,
  XCircle,
  Shield,
  ChevronRight,
  Loader2,
} from "lucide-react";
import clsx from "clsx";
import type {
  Conversation,
  Message,
  ToolCall,
  PendingApproval,
  BlockedAction,
  User,
} from "@/types";
import {
  createConversation,
  decideApproval,
  getConversation,
  getConversations,
  getMe,
  sendMessage,
} from "@/services/api";

function formatRelative(iso: string | undefined): string {
  if (!iso) return "";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "";
  const diffSec = Math.max(0, Math.round((Date.now() - then) / 1000));
  if (diffSec < 60) return `${diffSec}s ago`;
  const diffMin = Math.round(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.round(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  const diffDay = Math.round(diffHr / 24);
  if (diffDay < 7) return `${diffDay}d ago`;
  return new Date(iso).toLocaleDateString();
}

function ToolCallBadge({ tc }: { tc: ToolCall }) {
  return (
    <div
      className="mono-tag flex items-center gap-2 px-3 py-2 rounded-[8px]"
      style={{
        background: "var(--fill-success)",
        border: "1px solid var(--border-success)",
      }}
    >
      <CheckCircle2 className="w-3.5 h-3.5" style={{ color: "var(--accent-success)" }} />
      <span style={{ color: "var(--accent-success)" }} className="font-medium">
        {tc.name}
      </span>
      <ChevronRight className="w-3 h-3" style={{ color: "var(--text-muted)" }} />
      <span className="truncate max-w-[200px]" style={{ color: "var(--text-secondary)" }}>
        {typeof tc.result === "string" ? tc.result : JSON.stringify(tc.result ?? "")}
      </span>
    </div>
  );
}

function BlockedActionBadge({ ba }: { ba: BlockedAction }) {
  return (
    <div
      className="mono-tag flex items-center gap-2 px-3 py-2 rounded-[8px]"
      style={{
        background: "var(--fill-danger)",
        border: "1px solid var(--border-danger)",
      }}
    >
      <XCircle className="w-3.5 h-3.5" style={{ color: "var(--accent-danger)" }} />
      <span style={{ color: "var(--accent-danger)" }} className="font-medium">
        {ba.tool_name}
      </span>
      <ChevronRight className="w-3 h-3" style={{ color: "var(--text-muted)" }} />
      <span className="truncate max-w-[240px]" style={{ color: "var(--text-secondary)" }}>
        Blocked: {ba.reason}
      </span>
    </div>
  );
}

function ApprovalCard({
  approval,
  onDecide,
}: {
  approval: PendingApproval;
  onDecide: (approved: boolean) => Promise<void>;
}) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handle = async (approved: boolean) => {
    setPending(true);
    setError(null);
    try {
      await onDecide(approved);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setPending(false);
    }
  };

  return (
    <div
      className="rounded-[10px] p-3 mt-2"
      style={{
        background: "var(--fill-warning)",
        border: "1px solid var(--border-warning)",
      }}
    >
      <div className="flex items-center gap-2 mb-2">
        <Shield className="w-4 h-4" style={{ color: "var(--accent-warning)" }} />
        <span
          className="eyebrow"
          style={{ color: "var(--accent-warning)" }}
        >
          Approval required
        </span>
      </div>
      <p className="text-xs mb-2" style={{ color: "var(--text-secondary)" }}>
        Tool <strong>{approval.tool_name}</strong> wants to run.
      </p>
      {Object.keys(approval.arguments ?? {}).length > 0 && (
        <pre
          className="text-xs mb-2 p-2 rounded-[8px] overflow-x-auto"
          style={{
            background: "var(--claw-surface)",
            color: "var(--text-secondary)",
            border: "1px solid var(--claw-border)",
          }}
        >
          {JSON.stringify(approval.arguments, null, 2)}
        </pre>
      )}
      <p className="text-xs mb-3" style={{ color: "var(--text-muted)" }}>
        {approval.reason}
      </p>
      {error && (
        <p className="text-xs mb-2" style={{ color: "var(--accent-danger)" }}>
          {error}
        </p>
      )}
      <div className="flex gap-2">
        <button
          type="button"
          disabled={pending}
          onClick={() => handle(true)}
          className="px-3 py-1.5 rounded-[8px] text-xs font-semibold disabled:opacity-50 inline-flex items-center gap-1.5"
          style={{ background: "var(--accent-success)", color: "#0a0a0b" }}
        >
          {pending ? <Loader2 className="w-3 h-3 animate-spin" /> : null}
          Approve
        </button>
        <button
          type="button"
          disabled={pending}
          onClick={() => handle(false)}
          className="px-3 py-1.5 rounded-[8px] text-xs font-medium disabled:opacity-50"
          style={{
            border: "1px solid var(--border-danger)",
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
  const [me, setMe] = useState<User | null>(null);
  const [authError, setAuthError] = useState<string | null>(null);
  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [activeConv, setActiveConv] = useState<string | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [loadingMessages, setLoadingMessages] = useState(false);
  const [sending, setSending] = useState(false);
  const [creating, setCreating] = useState(false);
  const [input, setInput] = useState("");
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Load the current user once
  useEffect(() => {
    let cancelled = false;
    getMe()
      .then((u) => {
        if (!cancelled) setMe(u);
      })
      .catch((err: Error) => {
        if (!cancelled) setAuthError(err.message);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // Load conversations when we know the user
  useEffect(() => {
    if (!me) return;
    let cancelled = false;
    getConversations(me.id)
      .then((convs) => {
        if (cancelled) return;
        setConversations(convs);
        if (convs.length > 0) setActiveConv((current) => current ?? convs[0].id);
      })
      .catch(() => {
        // empty list on error
      });
    return () => {
      cancelled = true;
    };
  }, [me]);

  // Load messages when the active conversation changes
  useEffect(() => {
    if (!activeConv) {
      setMessages([]);
      return;
    }
    let cancelled = false;
    setLoadingMessages(true);
    getConversation(activeConv)
      .then((conv) => {
        if (!cancelled) setMessages(conv.messages ?? []);
      })
      .catch(() => {
        if (!cancelled) setMessages([]);
      })
      .finally(() => {
        if (!cancelled) setLoadingMessages(false);
      });
    return () => {
      cancelled = true;
    };
  }, [activeConv]);

  // Scroll to bottom on message updates
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const handleNewConversation = async () => {
    if (!me || creating) return;
    setCreating(true);
    try {
      const conv = await createConversation(me.id, "New Conversation");
      setConversations((prev) => [conv, ...prev]);
      setActiveConv(conv.id);
      setMessages([]);
    } catch {
      // ignore
    } finally {
      setCreating(false);
    }
  };

  const handleSend = async (e: FormEvent) => {
    e.preventDefault();
    if (!input.trim() || !activeConv || !me || sending) return;
    const content = input.trim();

    // Optimistically render the user message
    const tempId = `temp-${Date.now()}`;
    const optimistic: Message = {
      id: tempId,
      conversation_id: activeConv,
      role: "user",
      content,
      created_at: new Date().toISOString(),
    };
    setMessages((prev) => [...prev, optimistic]);
    setInput("");
    setSending(true);

    try {
      const res = await sendMessage(activeConv, me.id, content);
      const assistant: Message = {
        ...res.assistant_message,
        tool_calls: res.tool_calls,
        pending_approvals: res.pending_approvals,
        blocked_actions: res.blocked_actions,
      };
      // Replace the optimistic user message with the server's saved copy and append the assistant
      setMessages((prev) => [
        ...prev.filter((m) => m.id !== tempId),
        res.user_message,
        assistant,
      ]);
    } catch (err) {
      setMessages((prev) => [
        ...prev.filter((m) => m.id !== tempId),
        optimistic,
        {
          id: `err-${Date.now()}`,
          conversation_id: activeConv,
          role: "system",
          content: `Error: ${(err as Error).message}`,
          created_at: new Date().toISOString(),
        },
      ]);
    } finally {
      setSending(false);
    }
  };

  const handleApprovalDecision = async (actionId: string, approved: boolean) => {
    if (!me) return;
    await decideApproval(actionId, me.id, approved);
    // Remove the approval from any message that still shows it
    setMessages((prev) =>
      prev.map((m) => ({
        ...m,
        pending_approvals: (m.pending_approvals ?? []).filter(
          (pa) => pa.action_id !== actionId,
        ),
      })),
    );
  };

  if (authError) {
    return (
      <div className="flex items-center justify-center h-[calc(100vh-3rem)]">
        <p className="text-sm" style={{ color: "var(--accent-danger)" }}>
          {authError}
        </p>
      </div>
    );
  }

  return (
    <div
      className="flex h-[calc(100vh-3rem)] rounded-[14px] overflow-hidden"
      style={{
        background: "var(--claw-panel)",
        border: "1px solid var(--claw-border)",
        boxShadow: "var(--shadow-card)",
      }}
    >
      {/* Conversation List */}
      <div
        className="w-72 flex flex-col shrink-0"
        style={{
          borderRight: "1px solid var(--claw-border)",
          background: "var(--claw-sidebar)",
        }}
      >
        <div className="p-4" style={{ borderBottom: "1px solid var(--claw-border)" }}>
          <button
            type="button"
            onClick={handleNewConversation}
            disabled={!me || creating}
            className="w-full flex items-center justify-center gap-2 py-2.5 rounded-[10px] text-sm font-semibold disabled:opacity-50"
            style={{ background: "var(--accent-primary)", color: "#0a0a0b" }}
          >
            {creating ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
            New Chat
          </button>
        </div>
        <div className="px-4 pt-3 pb-1">
          <div className="eyebrow">Conversations</div>
        </div>
        <div className="flex-1 overflow-y-auto">
          {conversations.length === 0 && (
            <p
              className="text-xs text-center px-4 py-8"
              style={{ color: "var(--text-muted)" }}
            >
              No conversations yet. Click New Chat to start one.
            </p>
          )}
          {conversations.map((conv) => {
            const isActive = activeConv === conv.id;
            return (
              <button
                key={conv.id}
                type="button"
                onClick={() => setActiveConv(conv.id)}
                className={clsx(
                  "w-full text-left px-4 py-3 transition-colors relative",
                )}
                style={{
                  borderBottom: "1px solid var(--border-subtle)",
                  background: isActive ? "var(--claw-surface-active)" : "transparent",
                  boxShadow: isActive
                    ? "inset 2px 0 0 var(--accent-primary)"
                    : "none",
                }}
              >
                <div className="flex items-center justify-between gap-2">
                  <span
                    className="text-sm font-medium truncate"
                    style={{ color: isActive ? "var(--text-primary)" : "var(--text-secondary)" }}
                  >
                    {conv.title || "Untitled"}
                  </span>
                  <span className="mono-tag shrink-0" style={{ color: "var(--text-muted)" }}>
                    {formatRelative(conv.updated_at)}
                  </span>
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Chat Area */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Messages */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {!activeConv && !loadingMessages && (
            <div className="flex items-center justify-center h-full">
              <p className="text-sm" style={{ color: "var(--text-muted)" }}>
                Select a conversation or start a new one.
              </p>
            </div>
          )}
          {loadingMessages && (
            <div className="flex items-center justify-center h-full gap-2" style={{ color: "var(--text-muted)" }}>
              <Loader2 className="w-4 h-4 animate-spin" />
              <span className="text-sm">Loading messages...</span>
            </div>
          )}
          {!loadingMessages && activeConv && messages.length === 0 && (
            <div className="flex items-center justify-center h-full">
              <p className="text-sm" style={{ color: "var(--text-muted)" }}>
                No messages yet. Say hello.
              </p>
            </div>
          )}
          {messages.map((msg) => (
            <div
              key={msg.id}
              className={clsx("flex gap-3", msg.role === "user" ? "justify-end" : "")}
            >
              {msg.role === "assistant" && (
                <div
                  className="w-8 h-8 rounded-[8px] flex items-center justify-center shrink-0"
                  style={{
                    background: "var(--accent-glow)",
                    border: "1px solid rgba(34,211,238,0.35)",
                  }}
                >
                  <Bot className="w-4 h-4" style={{ color: "var(--accent-primary)" }} />
                </div>
              )}
              <div
                className={clsx("max-w-[70%] rounded-[12px] px-4 py-3")}
                style={{
                  background:
                    msg.role === "user"
                      ? "var(--accent-primary)"
                      : msg.role === "system"
                      ? "var(--fill-danger)"
                      : "var(--claw-surface)",
                  border:
                    msg.role === "assistant"
                      ? "1px solid var(--claw-border)"
                      : msg.role === "system"
                      ? "1px solid var(--border-danger)"
                      : "none",
                }}
              >
                <p
                  className="text-sm whitespace-pre-wrap"
                  style={{
                    color: msg.role === "user" ? "#0a0a0b" : "var(--text-primary)",
                  }}
                >
                  {msg.content}
                </p>
                {msg.tool_calls && msg.tool_calls.length > 0 && (
                  <div className="mt-2 space-y-1">
                    {msg.tool_calls.map((tc, i) => (
                      <ToolCallBadge key={`${tc.tool_call_id ?? tc.name}-${i}`} tc={tc} />
                    ))}
                  </div>
                )}
                {msg.blocked_actions && msg.blocked_actions.length > 0 && (
                  <div className="mt-2 space-y-1">
                    {msg.blocked_actions.map((ba, i) => (
                      <BlockedActionBadge key={`${ba.tool_name}-${i}`} ba={ba} />
                    ))}
                  </div>
                )}
                {msg.pending_approvals && msg.pending_approvals.length > 0 && (
                  <div className="mt-2 space-y-2">
                    {msg.pending_approvals.map((pa) => (
                      <ApprovalCard
                        key={pa.action_id}
                        approval={pa}
                        onDecide={(approved) => handleApprovalDecision(pa.action_id, approved)}
                      />
                    ))}
                  </div>
                )}
              </div>
              {msg.role === "user" && (
                <div
                  className="w-8 h-8 rounded-[8px] flex items-center justify-center shrink-0"
                  style={{
                    background: "var(--accent-glow)",
                    border: "1px solid rgba(34,211,238,0.35)",
                  }}
                >
                  <UserIcon className="w-4 h-4" style={{ color: "var(--accent-primary)" }} />
                </div>
              )}
            </div>
          ))}
          <div ref={messagesEndRef} />
        </div>

        {/* Input */}
        <form
          onSubmit={handleSend}
          className="p-4"
          style={{ borderTop: "1px solid var(--claw-border)" }}
        >
          <div
            className="flex items-center gap-3 rounded-[12px] px-4 py-2"
            style={{
              background: "var(--bg-input)",
              border: "1px solid var(--claw-border)",
            }}
          >
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder={activeConv ? "Ask SentientAI anything..." : "Start a conversation first"}
              disabled={!activeConv || sending}
              className="flex-1 bg-transparent outline-none text-sm disabled:opacity-50"
              style={{ color: "var(--text-primary)" }}
            />
            <button
              type="submit"
              disabled={!input.trim() || !activeConv || sending}
              className="w-8 h-8 rounded-[8px] flex items-center justify-center transition-colors disabled:opacity-50"
              style={{
                background: input.trim() && activeConv ? "var(--accent-primary)" : "transparent",
              }}
            >
              {sending ? (
                <Loader2 className="w-4 h-4 animate-spin" style={{ color: "#0a0a0b" }} />
              ) : (
                <Send
                  className="w-4 h-4"
                  style={{
                    color: input.trim() && activeConv ? "#0a0a0b" : "var(--text-muted)",
                  }}
                />
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
