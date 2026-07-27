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
  Pencil,
  Trash2,
  AlertTriangle,
  RefreshCw,
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
  deleteConversation,
  getConversation,
  getConversations,
  getMe,
  getPendingApprovals,
  streamMessage,
  updateConversation,
} from "@/services/api";
import ConfirmDialog from "@/components/ConfirmDialog";
import MarkdownMessage from "@/components/MarkdownMessage";

const CONV_PAGE_SIZE = 50;
const DEFAULT_TITLE = "New Conversation";
const AUTO_TITLE_MAX = 40;

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
  const [convError, setConvError] = useState<string | null>(null);
  const [convRetryKey, setConvRetryKey] = useState(0);
  const [hasMoreConvs, setHasMoreConvs] = useState(false);
  const [loadingMoreConvs, setLoadingMoreConvs] = useState(false);
  const [activeConv, setActiveConv] = useState<string | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [messagesError, setMessagesError] = useState<string | null>(null);
  const [messagesRetryKey, setMessagesRetryKey] = useState(0);
  const [approvals, setApprovals] = useState<PendingApproval[]>([]);
  const [loadingMessages, setLoadingMessages] = useState(false);
  const [sending, setSending] = useState(false);
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);
  const [renamingId, setRenamingId] = useState<string | null>(null);
  const [renameText, setRenameText] = useState("");
  const [renameError, setRenameError] = useState<string | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<Conversation | null>(null);
  const [input, setInput] = useState("");
  // Live status line while a turn streams ("Running canvas.get_courses…").
  const [streamStatus, setStreamStatus] = useState<string | null>(null);
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

  // Load the first page of conversations when we know the user
  useEffect(() => {
    if (!me) return;
    let cancelled = false;
    setConvError(null);
    getConversations({ limit: CONV_PAGE_SIZE, offset: 0 })
      .then((convs) => {
        if (cancelled) return;
        setConversations(convs);
        setHasMoreConvs(convs.length === CONV_PAGE_SIZE);
        if (convs.length > 0) setActiveConv((current) => current ?? convs[0].id);
      })
      .catch((err: Error) => {
        if (!cancelled) setConvError(err.message);
      });
    return () => {
      cancelled = true;
    };
  }, [me, convRetryKey]);

  // Load messages (and any still-pending approvals) when the active
  // conversation changes. Approvals are persisted server-side, so fetching
  // them here means Approve/Deny cards survive page reloads instead of
  // living only in the transient send-message response.
  useEffect(() => {
    if (!activeConv) {
      setMessages([]);
      setApprovals([]);
      setMessagesError(null);
      return;
    }
    let cancelled = false;
    setLoadingMessages(true);
    setMessagesError(null);
    setApprovals([]);
    Promise.all([
      getConversation(activeConv),
      // A failed approvals fetch should not block the thread itself.
      getPendingApprovals().catch(() => null),
    ])
      .then(([conv, pending]) => {
        if (cancelled) return;
        setMessages(conv.messages ?? []);
        if (pending) {
          setApprovals(
            pending.filter(
              (pa) => !pa.conversation_id || pa.conversation_id === activeConv,
            ),
          );
        }
      })
      .catch((err: Error) => {
        if (!cancelled) {
          setMessages([]);
          setMessagesError(err.message);
        }
      })
      .finally(() => {
        if (!cancelled) setLoadingMessages(false);
      });
    return () => {
      cancelled = true;
    };
  }, [activeConv, messagesRetryKey]);

  // Scroll to bottom on message updates
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, approvals]);

  const handleNewConversation = async () => {
    if (!me || creating) return;
    setCreating(true);
    setCreateError(null);
    try {
      const conv = await createConversation(DEFAULT_TITLE);
      setConversations((prev) => [conv, ...prev]);
      setActiveConv(conv.id);
      setMessages([]);
    } catch (err) {
      setCreateError((err as Error).message);
    } finally {
      setCreating(false);
    }
  };

  const handleLoadMoreConversations = async () => {
    if (loadingMoreConvs) return;
    setLoadingMoreConvs(true);
    try {
      const next = await getConversations({
        limit: CONV_PAGE_SIZE,
        offset: conversations.length,
      });
      setConversations((prev) => {
        const seen = new Set(prev.map((c) => c.id));
        return [...prev, ...next.filter((c) => !seen.has(c.id))];
      });
      setHasMoreConvs(next.length === CONV_PAGE_SIZE);
    } catch (err) {
      setConvError((err as Error).message);
    } finally {
      setLoadingMoreConvs(false);
    }
  };

  const startRename = (conv: Conversation) => {
    setRenamingId(conv.id);
    setRenameText(conv.title || "");
    setRenameError(null);
  };

  const cancelRename = () => {
    setRenamingId(null);
    setRenameError(null);
  };

  const commitRename = async () => {
    if (!renamingId) return;
    const title = renameText.trim();
    const current = conversations.find((c) => c.id === renamingId);
    if (!title || !current || title === current.title) {
      cancelRename();
      return;
    }
    try {
      const updated = await updateConversation(renamingId, { title });
      setConversations((prev) =>
        prev.map((c) => (c.id === updated.id ? updated : c)),
      );
      cancelRename();
    } catch (err) {
      setRenameError((err as Error).message);
    }
  };

  const handleDeleteConversation = async () => {
    if (!deleteTarget) return;
    await deleteConversation(deleteTarget.id);
    const deletedId = deleteTarget.id;
    const remaining = conversations.filter((c) => c.id !== deletedId);
    setConversations(remaining);
    if (activeConv === deletedId) {
      setActiveConv(remaining[0]?.id ?? null);
    }
    setDeleteTarget(null);
  };

  // After the first user message, give the conversation a real title so the
  // sidebar is not a wall of identical "New Conversation" rows. Cosmetic —
  // failures are ignored and the default title simply stays.
  const maybeAutoTitle = (conversationId: string, content: string) => {
    const conv = conversations.find((c) => c.id === conversationId);
    if (!conv || conv.title !== DEFAULT_TITLE) return;
    const compact = content.replace(/\s+/g, " ").trim();
    if (!compact) return;
    const title =
      compact.length > AUTO_TITLE_MAX
        ? `${compact.slice(0, AUTO_TITLE_MAX).trimEnd()}…`
        : compact;
    updateConversation(conversationId, { title })
      .then((updated) => {
        setConversations((prev) =>
          prev.map((c) => (c.id === updated.id ? updated : c)),
        );
      })
      .catch(() => {
        /* keep the default title on failure */
      });
  };

  const handleSend = async (e: FormEvent) => {
    e.preventDefault();
    if (!input.trim() || !activeConv || !me || sending) return;
    const content = input.trim();
    const conv = activeConv;

    // Optimistically render the user message + an empty assistant bubble
    // that fills in as content_delta events arrive.
    const userTempId = `temp-user-${Date.now()}`;
    const asstTempId = `temp-asst-${Date.now()}`;
    const optimisticUser: Message = {
      id: userTempId,
      conversation_id: conv,
      role: "user",
      content,
      created_at: new Date().toISOString(),
    };
    const streamingAssistant: Message = {
      id: asstTempId,
      conversation_id: conv,
      role: "assistant",
      content: "",
      tool_calls: [],
      blocked_actions: [],
      created_at: new Date().toISOString(),
    };
    setMessages((prev) => [...prev, optimisticUser, streamingAssistant]);
    setInput("");
    setSending(true);
    setStreamStatus(null);

    const patchAssistant = (patch: Partial<Message>) =>
      setMessages((prev) =>
        prev.map((m) => (m.id === asstTempId ? { ...m, ...patch } : m)),
      );

    try {
      await streamMessage(conv, content, {
        onUserMessage: (saved) =>
          setMessages((prev) =>
            prev.map((m) => (m.id === userTempId ? saved : m)),
          ),
        onToolCall: (name) => setStreamStatus(`Running ${name}…`),
        onToolResult: (name) => setStreamStatus(`Finished ${name}`),
        onContentDelta: (text) => {
          setStreamStatus(null);
          setMessages((prev) =>
            prev.map((m) =>
              m.id === asstTempId ? { ...m, content: m.content + text } : m,
            ),
          );
        },
        onPendingApproval: (approval) =>
          setApprovals((prev) => {
            const seen = new Set(prev.map((pa) => pa.action_id));
            return seen.has(approval.action_id) ? prev : [...prev, approval];
          }),
        onBlocked: (blocked) =>
          patchAssistant({
            blocked_actions: [
              ...(streamingAssistant.blocked_actions ?? []),
              blocked,
            ],
          }),
        onDone: (data) =>
          patchAssistant({
            content: data.content ?? "",
            tool_calls: data.tool_calls ?? [],
            blocked_actions: data.blocked_actions ?? [],
          }),
        onSaved: (saved) => {
          if (saved) {
            // Swap the temp assistant bubble for the persisted row, keeping
            // the streamed tool_calls/blocked metadata.
            setMessages((prev) =>
              prev.map((m) =>
                m.id === asstTempId
                  ? { ...saved, tool_calls: m.tool_calls, blocked_actions: m.blocked_actions }
                  : m,
              ),
            );
          }
        },
        onError: (reason) => patchAssistant({ content: `Error: ${reason}` }),
      });
      maybeAutoTitle(conv, content);
    } catch (err) {
      // The whole request failed (auth, network, 4xx). Drop the streaming
      // bubble and surface the error; keep the user's message visible.
      setMessages((prev) => [
        ...prev.filter((m) => m.id !== asstTempId),
        {
          id: `err-${Date.now()}`,
          conversation_id: conv,
          role: "system",
          content: `Error: ${(err as Error).message}`,
          created_at: new Date().toISOString(),
        },
      ]);
    } finally {
      setSending(false);
      setStreamStatus(null);
    }
  };

  const handleApprovalDecision = async (actionId: string, approved: boolean) => {
    await decideApproval(actionId, approved);
    setApprovals((prev) => prev.filter((pa) => pa.action_id !== actionId));
    // The backend persists an assistant message with the tool outcome —
    // refetch the thread so the result of the decision is visible.
    if (activeConv) {
      try {
        const conv = await getConversation(activeConv);
        setMessages(conv.messages ?? []);
      } catch {
        // The decision itself succeeded; the thread catches up on next load.
      }
    }
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
          {createError && (
            <p className="text-xs mt-2" style={{ color: "var(--accent-danger)" }}>
              Could not create a conversation: {createError}
            </p>
          )}
        </div>
        <div className="px-4 pt-3 pb-1">
          <div className="eyebrow">Conversations</div>
        </div>
        <div className="flex-1 overflow-y-auto">
          {convError && (
            <div
              className="mx-3 my-2 px-3 py-2.5 rounded-[8px]"
              style={{
                background: "var(--fill-danger)",
                border: "1px solid var(--border-danger)",
              }}
            >
              <p className="text-xs mb-2" style={{ color: "var(--accent-danger)" }}>
                Conversations failed to load: {convError}
              </p>
              <button
                type="button"
                onClick={() => setConvRetryKey((k) => k + 1)}
                className="inline-flex items-center gap-1.5 text-xs font-semibold"
                style={{ color: "var(--accent-danger)" }}
              >
                <RefreshCw className="w-3 h-3" />
                Retry
              </button>
            </div>
          )}
          {!convError && conversations.length === 0 && (
            <p
              className="text-xs text-center px-4 py-8"
              style={{ color: "var(--text-muted)" }}
            >
              No conversations yet. Click New Chat to start one.
            </p>
          )}
          {conversations.map((conv) => {
            const isActive = activeConv === conv.id;
            const isRenaming = renamingId === conv.id;
            return (
              <div
                key={conv.id}
                role="button"
                tabIndex={0}
                onClick={() => {
                  if (!isRenaming) setActiveConv(conv.id);
                }}
                onKeyDown={(e) => {
                  if (!isRenaming && (e.key === "Enter" || e.key === " ")) {
                    e.preventDefault();
                    setActiveConv(conv.id);
                  }
                }}
                className={clsx(
                  "group w-full text-left px-4 py-3 transition-colors relative cursor-pointer",
                )}
                style={{
                  borderBottom: "1px solid var(--border-subtle)",
                  background: isActive ? "var(--claw-surface-active)" : "transparent",
                  boxShadow: isActive
                    ? "inset 2px 0 0 var(--accent-primary)"
                    : "none",
                }}
              >
                {isRenaming ? (
                  <div onClick={(e) => e.stopPropagation()}>
                    <input
                      type="text"
                      value={renameText}
                      autoFocus
                      onChange={(e) => setRenameText(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") void commitRename();
                        if (e.key === "Escape") cancelRename();
                      }}
                      onBlur={() => void commitRename()}
                      className="w-full px-2 py-1 rounded-[6px] text-sm outline-none"
                      style={{
                        background: "var(--bg-input)",
                        border: "1px solid var(--accent-primary)",
                        color: "var(--text-primary)",
                      }}
                    />
                    {renameError && (
                      <p className="text-xs mt-1" style={{ color: "var(--accent-danger)" }}>
                        {renameError}
                      </p>
                    )}
                  </div>
                ) : (
                  <div className="flex items-center justify-between gap-2">
                    <span
                      className="text-sm font-medium truncate"
                      style={{ color: isActive ? "var(--text-primary)" : "var(--text-secondary)" }}
                    >
                      {conv.title || "Untitled"}
                    </span>
                    <span className="mono-tag shrink-0 group-hover:hidden" style={{ color: "var(--text-muted)" }}>
                      {formatRelative(conv.updated_at)}
                    </span>
                    <span className="hidden group-hover:flex items-center gap-1 shrink-0">
                      <button
                        type="button"
                        aria-label="Rename conversation"
                        onClick={(e) => {
                          e.stopPropagation();
                          startRename(conv);
                        }}
                        className="p-1 rounded-[6px] hover:opacity-80"
                        style={{ color: "var(--text-muted)" }}
                      >
                        <Pencil className="w-3.5 h-3.5" />
                      </button>
                      <button
                        type="button"
                        aria-label="Delete conversation"
                        onClick={(e) => {
                          e.stopPropagation();
                          setDeleteTarget(conv);
                        }}
                        className="p-1 rounded-[6px] hover:opacity-80"
                        style={{ color: "var(--accent-danger)" }}
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </span>
                  </div>
                )}
              </div>
            );
          })}
          {!convError && hasMoreConvs && (
            <div className="px-4 py-3">
              <button
                type="button"
                onClick={() => void handleLoadMoreConversations()}
                disabled={loadingMoreConvs}
                className="w-full inline-flex items-center justify-center gap-2 py-2 rounded-[8px] text-xs font-medium disabled:opacity-50"
                style={{
                  background: "var(--bg-input)",
                  border: "1px solid var(--claw-border)",
                  color: "var(--text-secondary)",
                }}
              >
                {loadingMoreConvs ? (
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                ) : null}
                {loadingMoreConvs ? "Loading..." : "Load more"}
              </button>
            </div>
          )}
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
          {!loadingMessages && activeConv && messagesError && (
            <div className="flex items-center justify-center h-full">
              <div
                className="flex flex-col items-center gap-3 px-6 py-5 rounded-[12px]"
                style={{
                  background: "var(--fill-danger)",
                  border: "1px solid var(--border-danger)",
                }}
              >
                <div className="flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4" style={{ color: "var(--accent-danger)" }} />
                  <p className="text-sm" style={{ color: "var(--accent-danger)" }}>
                    This conversation failed to load: {messagesError}
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => setMessagesRetryKey((k) => k + 1)}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-[8px] text-xs font-semibold"
                  style={{
                    border: "1px solid var(--border-danger)",
                    color: "var(--accent-danger)",
                  }}
                >
                  <RefreshCw className="w-3 h-3" />
                  Retry
                </button>
              </div>
            </div>
          )}
          {!loadingMessages &&
            activeConv &&
            !messagesError &&
            messages.length === 0 &&
            approvals.length === 0 && (
            <div className="flex items-center justify-center h-full">
              <p className="text-sm" style={{ color: "var(--text-muted)" }}>
                No messages yet. Say hello.
              </p>
            </div>
          )}
          {!messagesError && messages.map((msg) => (
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
                {msg.role === "assistant" ? (
                  // Assistant output may be shaped by untrusted tool data, so
                  // it renders through the exfiltration-safe markdown component
                  // (no auto-fetched images, no raw HTML, inert links).
                  <MarkdownMessage content={msg.content} />
                ) : (
                  <p
                    className="text-sm whitespace-pre-wrap"
                    style={{
                      color: msg.role === "user" ? "#0a0a0b" : "var(--text-primary)",
                    }}
                  >
                    {msg.content}
                  </p>
                )}
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
          {/* Pending approvals for this conversation — sourced from the
              server so they survive reloads, plus any raised this turn. */}
          {!loadingMessages && !messagesError && approvals.length > 0 && (
            <div className="flex gap-3">
              <div
                className="w-8 h-8 rounded-[8px] flex items-center justify-center shrink-0"
                style={{
                  background: "var(--accent-glow)",
                  border: "1px solid rgba(34,211,238,0.35)",
                }}
              >
                <Shield className="w-4 h-4" style={{ color: "var(--accent-warning)" }} />
              </div>
              <div className="max-w-[70%] flex-1 space-y-2">
                {approvals.map((pa) => (
                  <ApprovalCard
                    key={pa.action_id}
                    approval={pa}
                    onDecide={(approved) => handleApprovalDecision(pa.action_id, approved)}
                  />
                ))}
              </div>
            </div>
          )}
          {/* Live turn status: tool activity or a thinking indicator while
              the stream is in flight before the first token arrives. */}
          {sending && (
            <div className="flex items-center gap-2 pl-11" style={{ color: "var(--text-muted)" }}>
              <Loader2 className="w-3.5 h-3.5 animate-spin" style={{ color: "var(--accent-primary)" }} />
              <span className="text-xs">{streamStatus ?? "Thinking…"}</span>
            </div>
          )}
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

      <ConfirmDialog
        open={deleteTarget !== null}
        danger
        title="Delete conversation?"
        message={`"${deleteTarget?.title || "Untitled"}" and all of its messages will be permanently deleted. This cannot be undone.`}
        confirmLabel="Delete"
        onCancel={() => setDeleteTarget(null)}
        onConfirm={handleDeleteConversation}
      />
    </div>
  );
}
