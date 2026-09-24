import { useCallback, useEffect, useRef, useState } from "react";
import {
  Plus,
  Bot,
  User as UserIcon,
  CheckCircle2,
  XCircle,
  Shield,
  ChevronRight,
  ChevronDown,
  Loader2,
  Pencil,
  Trash2,
  AlertTriangle,
  RefreshCw,
  Clock,
  Search,
  X,
  PanelLeft,
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
import ChatComposer from "@/components/ChatComposer";
import { ConversationTokenTotal, MessageTokenCaption } from "@/components/TokenUsage";
import { DESKTOP_QUERY, useMediaQuery } from "@/hooks/useMediaQuery";
import { useFocusTrap } from "@/hooks/useFocusTrap";

const CONV_PAGE_SIZE = 50;
const DEFAULT_TITLE = "New Conversation";
const AUTO_TITLE_MAX = 40;
// Approvals raised on another device/tab must show up here without a reload,
// but well inside the 15-minute approval TTL — 20s keeps the loop alive
// without hammering the API.
const APPROVAL_POLL_MS = 20_000;
// How close to the end of the thread still counts as "reading the latest".
// Roughly one line of text plus padding, so a reader who has nudged the
// scrollbar is not dragged back down by the next token.
const NEAR_BOTTOM_PX = 120;

// Countdown helpers live in their own module (shared with Dashboard) so the
// Dashboard chunk doesn't drag in this whole page; re-exported here for
// existing importers.
import { formatCountdown, useCountdown } from "./approvalCountdown";
export { formatCountdown, useCountdown } from "./approvalCountdown";

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

/**
 * Clock time on each bubble, with the full date in the tooltip and in the
 * machine-readable attribute — "2:14 PM" alone is ambiguous the moment a
 * thread spans midnight.
 */
function MessageTime({ iso, onAccent }: { iso?: string; onAccent?: boolean }) {
  if (!iso) return null;
  const when = new Date(iso);
  if (Number.isNaN(when.getTime())) return null;
  return (
    <time
      dateTime={iso}
      title={when.toLocaleString()}
      className="mono-tag block mt-1.5"
      style={{
        color: onAccent ? "var(--text-on-accent)" : "var(--text-muted)",
        // Quiet, but not below 4.5:1 against the accent fill behind it —
        // at 11px this is the smallest text in the thread.
        opacity: onAccent ? 0.9 : 1,
      }}
    >
      {when.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" })}
    </time>
  );
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
  const remaining = useCountdown(approval.expires_at);
  // The server enforces the TTL, so a click after this point would 404 —
  // disable the buttons instead of letting the user walk into that.
  const expired = remaining !== null && remaining <= 0;

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
        background: expired ? "var(--claw-surface)" : "var(--fill-warning)",
        border: `1px solid ${expired ? "var(--claw-border)" : "var(--border-warning)"}`,
        opacity: expired ? 0.75 : 1,
      }}
    >
      <div className="flex items-center justify-between gap-2 mb-2">
        <div className="flex items-center gap-2">
          <Shield
            className="w-4 h-4"
            style={{ color: expired ? "var(--text-muted)" : "var(--accent-warning)" }}
          />
          <span
            className="eyebrow"
            style={{ color: expired ? "var(--text-muted)" : "var(--accent-warning)" }}
          >
            {expired ? "Approval expired" : "Approval required"}
          </span>
        </div>
        {remaining !== null && (
          <span
            className="mono-tag inline-flex items-center gap-1 shrink-0"
            style={{ color: expired ? "var(--accent-danger)" : "var(--accent-warning)" }}
          >
            <Clock className="w-3 h-3" />
            {expired ? "expired" : `expires in ${formatCountdown(remaining)}`}
          </span>
        )}
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
      {/* Backend-flagged risk: the request was shaped by external/untrusted
          content. Rendered in danger colors directly above the buttons so it
          cannot be missed on the way to Approve. */}
      {approval.risk_note && (
        <div
          className="flex items-start gap-2 p-2.5 rounded-[8px] mb-3"
          style={{
            background: "var(--fill-danger)",
            border: "1px solid var(--border-danger)",
          }}
        >
          <AlertTriangle
            className="w-4 h-4 mt-0.5 shrink-0"
            style={{ color: "var(--accent-danger)" }}
          />
          <div className="min-w-0">
            <div className="eyebrow" style={{ color: "var(--accent-danger)" }}>
              Risk warning
            </div>
            <p className="text-xs mt-1" style={{ color: "var(--text-secondary)" }}>
              {approval.risk_note}
            </p>
          </div>
        </div>
      )}
      {expired && (
        <p className="text-xs mb-2" style={{ color: "var(--text-muted)" }}>
          This request expired without a decision. Ask the agent again if the
          action is still needed.
        </p>
      )}
      {error && (
        <p role="alert" className="text-xs mb-2" style={{ color: "var(--accent-danger)" }}>
          {error}
        </p>
      )}
      <div className="flex gap-2">
        <button
          type="button"
          disabled={pending || expired}
          onClick={() => handle(true)}
          className="px-3 py-2 rounded-[8px] text-xs font-semibold disabled:opacity-50 inline-flex items-center gap-1.5"
          style={{
            minHeight: 36,
            background: "var(--accent-success)",
            color: "var(--text-on-accent)",
          }}
        >
          {pending ? <Loader2 className="w-3 h-3 animate-spin" /> : null}
          Approve
        </button>
        <button
          type="button"
          disabled={pending || expired}
          onClick={() => handle(false)}
          className="px-3 py-2 rounded-[8px] text-xs font-medium disabled:opacity-50"
          style={{
            minHeight: 36,
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

/** A turn that never reached the server, kept so Retry can resend it intact. */
interface FailedTurn {
  content: string;
  images: string[];
  error: string;
  /** The optimistic user bubble this attempt left behind, so a retry can
   *  replace exactly that one rather than every pending bubble. */
  userTempId: string;
}

export default function Chat() {
  const [me, setMe] = useState<User | null>(null);
  const [authError, setAuthError] = useState<string | null>(null);
  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [convError, setConvError] = useState<string | null>(null);
  // searchInput is what the user is typing; searchTerm is the debounced
  // value the query actually runs on.
  const [searchInput, setSearchInput] = useState("");
  const [searchTerm, setSearchTerm] = useState("");
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
  const [failedTurn, setFailedTurn] = useState<FailedTurn | null>(null);
  // Live status line while a turn streams ("Running canvas.get_courses…").
  const [streamStatus, setStreamStatus] = useState<string | null>(null);
  // Below the desktop breakpoint the conversation list is an overlay over
  // the thread rather than a column beside it.
  const [listOpen, setListOpen] = useState(false);
  const isDesktop = useMediaQuery(DESKTOP_QUERY, true);
  const listRef = useRef<HTMLDivElement>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  // Whether the reader is at the live end of the thread. Streaming only
  // scrolls while this is true, so scrolling up to re-read something is not
  // undone by the next token.
  const [atBottom, setAtBottom] = useState(true);
  // action_ids GET /agent/approvals has returned at least once. Lets the
  // poller drop cards decided elsewhere (absent from the server list) while
  // never clobbering stream-delivered approvals the server has not yet
  // exposed through the list endpoint.
  const serverSeenApprovals = useRef<Set<string>>(new Set());
  // action_ids this tab has already decided. The server drops them from the
  // list on the next fetch, but a poll that was already in flight when the
  // decision landed would otherwise resurrect a card the user just resolved
  // (and clicking it again 404s). Cleared per conversation with the rest.
  const decidedApprovals = useRef<Set<string>>(new Set());
  // Mirrors `activeConv` so an in-flight approvals fetch can tell it was
  // scoped to a conversation the user has since navigated away from, and
  // drop its result instead of clobbering the new thread's cards.
  const activeConvRef = useRef<string | null>(null);
  // Controller for the in-flight stream; lets the Stop button abort it.
  const abortRef = useRef<AbortController | null>(null);

  const closeList = useCallback(() => setListOpen(false), []);
  useFocusTrap(listOpen && !isDesktop, listRef, closeList);

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

  // Debounce the search box so typing does not fire a query per keystroke.
  useEffect(() => {
    const timer = setTimeout(() => setSearchTerm(searchInput), 250);
    return () => clearTimeout(timer);
  }, [searchInput]);

  // Load the first page of conversations when we know the user, and again
  // whenever the (debounced) search term changes.
  useEffect(() => {
    if (!me) return;
    let cancelled = false;
    setConvError(null);
    getConversations({ limit: CONV_PAGE_SIZE, offset: 0, q: searchTerm })
      .then((convs) => {
        if (cancelled) return;
        setConversations(convs);
        setHasMoreConvs(convs.length === CONV_PAGE_SIZE);
        // Only auto-select while browsing: during a search, jumping into
        // the first hit would yank the reader out of the thread they are
        // already reading.
        if (!searchTerm && convs.length > 0) {
          setActiveConv((current) => current ?? convs[0].id);
        }
      })
      .catch((err: Error) => {
        if (!cancelled) setConvError(err.message);
      });
    return () => {
      cancelled = true;
    };
  }, [me, convRetryKey, searchTerm]);

  // Load messages (and any still-pending approvals) when the active
  // conversation changes. Approvals are persisted server-side, so fetching
  // them here means Approve/Deny cards survive page reloads instead of
  // living only in the transient send-message response.
  useEffect(() => {
    // A turn still streaming into the thread we are leaving would write its
    // tokens into the new one's state.
    abortRef.current?.abort();
    abortRef.current = null;
    setFailedTurn(null);
    setAtBottom(true);
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
    serverSeenApprovals.current = new Set();
    decidedApprovals.current = new Set();
    Promise.all([
      getConversation(activeConv),
      // A failed approvals fetch should not block the thread itself.
      getPendingApprovals().catch(() => null),
    ])
      .then(([conv, pending]) => {
        if (cancelled) return;
        setMessages(conv.messages ?? []);
        if (pending) {
          for (const pa of pending) serverSeenApprovals.current.add(pa.action_id);
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

  useEffect(() => {
    activeConvRef.current = activeConv;
  }, [activeConv]);

  // Leaving the page mid-turn should not leave a reader writing into state
  // that has been torn down.
  useEffect(() => () => abortRef.current?.abort(), []);

  // Pull the approvals queue for the open conversation. Merged by action_id:
  // the server row wins when both exist (it carries the real arguments,
  // reason, expires_at and risk_note — the SSE frame carries none of those),
  // and stream-delivered approvals the list endpoint has never returned are
  // kept. Only cards the server once listed and has since resolved (decided
  // elsewhere, expired and swept) or that this tab decided are dropped.
  const refreshApprovals = useCallback(async () => {
    if (!activeConv) return;
    let pending: PendingApproval[];
    try {
      pending = await getPendingApprovals();
    } catch {
      return; // Best-effort; the next tick catches up.
    }
    // The user may have switched threads while this was in flight; the
    // scoping below would then be wrong for what is on screen.
    if (activeConvRef.current !== activeConv) return;
    const scoped = pending.filter(
      (pa) =>
        // Already resolved from this tab — never re-show it, even if this
        // response was in flight when the decision landed.
        !decidedApprovals.current.has(pa.action_id) &&
        (!pa.conversation_id || pa.conversation_id === activeConv),
    );
    for (const pa of pending) serverSeenApprovals.current.add(pa.action_id);
    setApprovals((prev) => {
      const fromServer = new Set(scoped.map((pa) => pa.action_id));
      const streamOnly = prev.filter(
        (pa) =>
          !fromServer.has(pa.action_id) &&
          !decidedApprovals.current.has(pa.action_id) &&
          !serverSeenApprovals.current.has(pa.action_id),
      );
      return [...scoped, ...streamOnly];
    });
  }, [activeConv]);

  // Keep the queue live so an approval raised on another device/tab shows up
  // here without a reload, well inside the server-side TTL.
  useEffect(() => {
    if (!activeConv) return;
    const interval = setInterval(() => void refreshApprovals(), APPROVAL_POLL_MS);
    return () => clearInterval(interval);
  }, [activeConv, refreshApprovals]);

  const handleScroll = () => {
    const el = scrollRef.current;
    if (!el) return;
    setAtBottom(
      el.scrollHeight - el.scrollTop - el.clientHeight <= NEAR_BOTTOM_PX,
    );
  };

  const jumpToLatest = () => {
    setAtBottom(true);
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  };

  // Follow the conversation only while the reader is already at the end of
  // it. Scrolling up is an explicit "I am reading something else"; yanking
  // them back on every streamed token made scrollback unusable.
  useEffect(() => {
    if (!atBottom) return;
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [messages, approvals, atBottom]);

  const handleNewConversation = async () => {
    if (!me || creating) return;
    setCreating(true);
    setCreateError(null);
    try {
      const conv = await createConversation(DEFAULT_TITLE);
      setConversations((prev) => [conv, ...prev]);
      setActiveConv(conv.id);
      setMessages([]);
      setListOpen(false);
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
        q: searchTerm,
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

  const handleRetry = async (
    errorMessageId: string,
    content: string,
    images: string[],
  ) => {
    if (sending) return;
    // Drop the error bubble; the resend renders its own fresh pair.
    setMessages((prev) => prev.filter((m) => m.id !== errorMessageId));
    await sendContent(content, images);
  };

  const handleStop = () => {
    // Aborts the client stream only. Server-side the turn keeps running
    // to completion (side-effectful tools must not be cut between a side
    // effect and its audit record) and persists via on_orphaned; the
    // finished reply appears on the next thread load.
    abortRef.current?.abort();
  };

  const sendContent = async (content: string, images: string[]) => {
    if (!activeConv || !me || sending) return;
    if (!content && images.length === 0) return;
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
      images,
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
    setFailedTurn(null);
    setSending(true);
    setStreamStatus(null);
    // A message the reader just sent is theirs to follow, wherever they had
    // scrolled to before.
    setAtBottom(true);

    const controller = new AbortController();
    abortRef.current = controller;

    const patchAssistant = (patch: Partial<Message>) =>
      setMessages((prev) =>
        prev.map((m) => (m.id === asstTempId ? { ...m, ...patch } : m)),
      );

    // A provider failure arrives as an `error` frame immediately followed
    // by an empty `done` frame; without this flag the done handler would
    // overwrite the error text with blank content.
    let errored = false;

    try {
      await streamMessage(
        conv,
        content,
        {
          onUserMessage: (saved) =>
            setMessages((prev) =>
              // Keep the local attachments: the saved row may not echo them
              // back, and dropping them would blank thumbnails the user can
              // still see in their own message.
              prev.map((m) =>
                m.id === userTempId ? { ...saved, images: saved.images ?? images } : m,
              ),
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
          onPendingApproval: (approval) => {
            // The runtime emits the full PendingApprovalOut shape, so this is
            // normally a straight passthrough. The fallbacks stay because an
            // approval prompt that renders "Tool undefined wants to run." with
            // no arguments — showing none of what is being approved — is worse
            // than a generic label; refreshApprovals() below reconciles against
            // the list endpoint either way.
            const raw = approval as PendingApproval & { tool?: string };
            const normalized: PendingApproval = {
              ...raw,
              tool_name: raw.tool_name ?? raw.tool ?? "unknown tool",
              arguments: raw.arguments ?? {},
              reason:
                raw.reason ??
                "This tool requires your explicit approval before it runs.",
              conversation_id: raw.conversation_id ?? conv,
            };
            setApprovals((prev) => {
              const seen = new Set(prev.map((pa) => pa.action_id));
              return seen.has(normalized.action_id) ? prev : [...prev, normalized];
            });
          },
          onBlocked: (blocked) =>
            // Append to the message's *current* blocked_actions via a
            // functional update. Reading `streamingAssistant` here would use
            // the array captured before streaming began (always []), so a
            // second blocked event in one turn would overwrite the first.
            setMessages((prev) =>
              prev.map((m) =>
                m.id === asstTempId
                  ? {
                      ...m,
                      blocked_actions: [...(m.blocked_actions ?? []), blocked],
                    }
                  : m,
              ),
            ),
          onDone: (data) => {
            if (errored) return;
            patchAssistant({
              content: data.content ?? "",
              tool_calls: data.tool_calls ?? [],
              blocked_actions: data.blocked_actions ?? [],
            });
          },
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
          onError: (reason) => {
            errored = true;
            patchAssistant({
              content: reason,
              error: true,
              retry_content: content,
              retry_images: images,
            });
          },
        },
        controller.signal,
        images.length > 0 ? images : undefined,
      );
      maybeAutoTitle(conv, content);
      // Any approval raised during this turn arrived over SSE with only
      // {tool, action_id, expires_at, risk_note}. Pull the full rows now so
      // the card shows the actual arguments immediately, rather than after
      // up to APPROVAL_POLL_MS.
      void refreshApprovals();
    } catch (err) {
      if (controller.signal.aborted) {
        // The user pressed Stop. The server finishes the turn on its own and
        // persists it, so whatever streamed so far is real output and stays,
        // marked as cut short; an assistant bubble that never got a token is
        // just noise.
        setMessages((prev) =>
          prev
            .map((m) =>
              m.id === asstTempId
                ? m.content
                  ? { ...m, content: `${m.content}\n\n*— stopped*` }
                  : null
                : m,
            )
            .filter((m): m is Message => m !== null),
        );
      } else {
        // The whole request failed (auth, network, a server that refuses the
        // attachments). Drop the empty streaming bubble, keep the user's
        // message on screen, and hold the turn so Retry can resend it.
        setMessages((prev) => prev.filter((m) => m.id !== asstTempId));
        setFailedTurn({
          content,
          images,
          userTempId,
          error: (err as Error).message,
        });
      }
    } finally {
      if (abortRef.current === controller) abortRef.current = null;
      setSending(false);
      setStreamStatus(null);
    }
  };

  const handleApprovalDecision = async (actionId: string, approved: boolean) => {
    await decideApproval(actionId, approved);
    // Record before removing: a poll that was already in flight must not
    // put this card back on screen.
    decidedApprovals.current.add(actionId);
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
      <div className="flex items-center justify-center chat-shell">
        <p role="alert" className="text-sm" style={{ color: "var(--accent-danger)" }}>
          {authError}
        </p>
      </div>
    );
  }

  const activeTitle =
    conversations.find((c) => c.id === activeConv)?.title || "Conversation";

  return (
    <div
      className="relative flex chat-shell rounded-[14px] overflow-hidden"
      style={{
        background: "var(--claw-panel)",
        border: "1px solid var(--claw-border)",
        boxShadow: "var(--shadow-card)",
      }}
    >
      {/* Conversation List — a column beside the thread on a desktop, an
          overlay over it on anything narrower. */}
      {listOpen && !isDesktop && (
        <div
          className="absolute inset-0 z-20 lg:hidden"
          style={{ background: "var(--scrim)" }}
          onClick={closeList}
          aria-hidden
        />
      )}
      <div
        ref={listRef}
        id="conversation-list"
        role={listOpen && !isDesktop ? "dialog" : undefined}
        aria-modal={listOpen && !isDesktop ? true : undefined}
        aria-label="Conversations"
        className={clsx(
          "absolute inset-y-0 left-0 z-30 w-[86%] max-w-[300px] flex flex-col shrink-0 transition-transform",
          "lg:static lg:w-72 lg:max-w-none lg:translate-x-0 lg:visible lg:z-auto",
          listOpen ? "translate-x-0 visible" : "-translate-x-full invisible",
        )}
        style={{
          borderRight: "1px solid var(--claw-border)",
          background: "var(--claw-sidebar)",
        }}
      >
        <div
          className="p-4 flex items-center gap-2"
          style={{ borderBottom: "1px solid var(--claw-border)" }}
        >
          <button
            type="button"
            onClick={handleNewConversation}
            disabled={!me || creating}
            className="flex-1 flex items-center justify-center gap-2 rounded-[10px] text-sm font-semibold disabled:opacity-50"
            style={{
              minHeight: 44,
              background: "var(--accent-primary)",
              color: "var(--text-on-accent)",
            }}
          >
            {creating ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
            New Chat
          </button>
          <button
            type="button"
            onClick={closeList}
            aria-label="Close conversations"
            className="lg:hidden inline-flex items-center justify-center rounded-[10px] shrink-0"
            style={{ width: 44, height: 44, color: "var(--text-muted)" }}
          >
            <X className="w-4 h-4" aria-hidden />
          </button>
        </div>
        {createError && (
          <p role="alert" className="text-xs px-4 pt-2" style={{ color: "var(--accent-danger)" }}>
            Could not create a conversation: {createError}
          </p>
        )}
        <div className="px-4 pt-3 pb-2">
          <div className="eyebrow mb-2">Conversations</div>
          <div
            className="flex items-center gap-2 rounded-[8px] px-2.5"
            style={{
              minHeight: 40,
              background: "var(--bg-input)",
              border: "1px solid var(--claw-border)",
            }}
          >
            <Search
              className="w-3.5 h-3.5 shrink-0"
              style={{ color: "var(--text-muted)" }}
              aria-hidden
            />
            <input
              type="text"
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              placeholder="Search titles and messages"
              aria-label="Search conversations"
              className="flex-1 min-w-0 bg-transparent outline-none text-xs"
              style={{ color: "var(--text-primary)" }}
            />
            {searchInput && (
              <button
                type="button"
                onClick={() => setSearchInput("")}
                aria-label="Clear search"
                className="tap-target shrink-0"
                style={{ color: "var(--text-muted)" }}
              >
                <X className="w-3.5 h-3.5" aria-hidden />
              </button>
            )}
          </div>
        </div>
        <div className="flex-1 overflow-y-auto">
          {convError && (
            <div
              role="alert"
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
                <RefreshCw className="w-3 h-3" aria-hidden />
                Retry
              </button>
            </div>
          )}
          {!convError && conversations.length === 0 && (
            <p
              className="text-xs text-center px-4 py-8"
              style={{ color: "var(--text-muted)" }}
            >
              {searchTerm
                ? `No conversations match “${searchTerm}”.`
                : "No conversations yet. Click New Chat to start one."}
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
                aria-current={isActive ? "true" : undefined}
                onClick={() => {
                  if (!isRenaming) {
                    setActiveConv(conv.id);
                    setListOpen(false);
                  }
                }}
                onKeyDown={(e) => {
                  if (!isRenaming && (e.key === "Enter" || e.key === " ")) {
                    e.preventDefault();
                    setActiveConv(conv.id);
                    setListOpen(false);
                  }
                }}
                className="group w-full text-left px-4 py-3 transition-colors relative cursor-pointer"
                style={{
                  minHeight: 56,
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
                      aria-label="Conversation title"
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
                      <p role="alert" className="text-xs mt-1" style={{ color: "var(--accent-danger)" }}>
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
                    <span
                      className="mono-tag shrink-0 hidden sm:block"
                      style={{ color: "var(--text-muted)" }}
                    >
                      {formatRelative(conv.updated_at)}
                    </span>
                    <span className="row-actions flex items-center gap-1 shrink-0">
                      <button
                        type="button"
                        aria-label={`Rename ${conv.title || "Untitled"}`}
                        onClick={(e) => {
                          e.stopPropagation();
                          startRename(conv);
                        }}
                        className="tap-target p-1 rounded-[6px]"
                        style={{ color: "var(--text-muted)" }}
                      >
                        <Pencil className="w-3.5 h-3.5" aria-hidden />
                      </button>
                      <button
                        type="button"
                        aria-label={`Delete ${conv.title || "Untitled"}`}
                        onClick={(e) => {
                          e.stopPropagation();
                          setDeleteTarget(conv);
                        }}
                        className="tap-target p-1 rounded-[6px]"
                        style={{ color: "var(--accent-danger)" }}
                      >
                        <Trash2 className="w-3.5 h-3.5" aria-hidden />
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
                className="w-full inline-flex items-center justify-center gap-2 rounded-[8px] text-xs font-medium disabled:opacity-50"
                style={{
                  minHeight: 44,
                  background: "var(--bg-input)",
                  border: "1px solid var(--claw-border)",
                  color: "var(--text-secondary)",
                }}
              >
                {loadingMoreConvs ? (
                  <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden />
                ) : null}
                {loadingMoreConvs ? "Loading..." : "Load more"}
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Chat Area */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* The list is off-canvas below 1024px, so the thread carries its own
            way back to it there. The header itself stays at every width: it
            is where the thread's running token total lives. */}
        <div
          className="flex items-center gap-2 px-3 py-2 lg:px-4 min-h-[56px]"
          style={{ borderBottom: "1px solid var(--claw-border)" }}
        >
          <button
            type="button"
            onClick={() => setListOpen(true)}
            aria-label="Show conversations"
            aria-expanded={listOpen}
            aria-controls="conversation-list"
            className="lg:hidden inline-flex items-center justify-center rounded-[8px] shrink-0"
            style={{ width: 40, height: 40, color: "var(--text-secondary)" }}
          >
            <PanelLeft className="w-4 h-4" aria-hidden />
          </button>
          <span
            className="text-sm font-medium truncate flex-1 min-w-0"
            style={{ color: "var(--text-primary)" }}
          >
            {activeConv ? activeTitle : "No conversation"}
          </span>
          {activeConv && !loadingMessages && !messagesError && (
            <ConversationTokenTotal messages={messages} />
          )}
        </div>

        {/* Messages */}
        <div
          ref={scrollRef}
          onScroll={handleScroll}
          className="flex-1 overflow-y-auto p-3 sm:p-4 space-y-4"
        >
          {!activeConv && !loadingMessages && (
            <div className="flex items-center justify-center h-full">
              <p className="text-sm" style={{ color: "var(--text-muted)" }}>
                Select a conversation or start a new one.
              </p>
            </div>
          )}
          {loadingMessages && (
            <div
              role="status"
              className="flex items-center justify-center h-full gap-2"
              style={{ color: "var(--text-muted)" }}
            >
              <Loader2 className="w-4 h-4 animate-spin" aria-hidden />
              <span className="text-sm">Loading messages...</span>
            </div>
          )}
          {!loadingMessages && activeConv && messagesError && (
            <div className="flex items-center justify-center h-full">
              <div
                role="alert"
                className="flex flex-col items-center gap-3 px-6 py-5 rounded-[12px]"
                style={{
                  background: "var(--fill-danger)",
                  border: "1px solid var(--border-danger)",
                }}
              >
                <div className="flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4" style={{ color: "var(--accent-danger)" }} aria-hidden />
                  <p className="text-sm" style={{ color: "var(--accent-danger)" }}>
                    This conversation failed to load: {messagesError}
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => setMessagesRetryKey((k) => k + 1)}
                  className="inline-flex items-center gap-1.5 px-3 py-2 rounded-[8px] text-xs font-semibold"
                  style={{
                    minHeight: 36,
                    border: "1px solid var(--border-danger)",
                    color: "var(--accent-danger)",
                  }}
                >
                  <RefreshCw className="w-3 h-3" aria-hidden />
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
                  aria-hidden
                  className="w-8 h-8 rounded-[8px] flex items-center justify-center shrink-0"
                  style={{
                    background: "var(--accent-glow)",
                    border: "1px solid var(--border-accent)",
                  }}
                >
                  <Bot className="w-4 h-4" style={{ color: "var(--accent-primary)" }} />
                </div>
              )}
              <div
                className="max-w-[85%] sm:max-w-[70%] rounded-[12px] px-4 py-3"
                style={{
                  background:
                    msg.role === "user"
                      ? "var(--accent-primary)"
                      : msg.error || msg.role === "system"
                      ? "var(--fill-danger)"
                      : "var(--claw-surface)",
                  border:
                    msg.error || msg.role === "system"
                      ? "1px solid var(--border-danger)"
                      : msg.role === "assistant"
                      ? "1px solid var(--claw-border)"
                      : "none",
                }}
              >
                {msg.images && msg.images.length > 0 && (
                  <ul className="flex flex-wrap gap-2 mb-2">
                    {msg.images.map((src, i) => (
                      <li key={i}>
                        {/* Attachments the user picked themselves, so unlike
                            markdown images in assistant output there is no
                            third party whose URL could be fetched here. */}
                        <img
                          src={src}
                          alt={`Attachment ${i + 1}`}
                          className="w-20 h-20 rounded-[8px] object-cover"
                          style={{ border: "1px solid var(--claw-border)" }}
                        />
                      </li>
                    ))}
                  </ul>
                )}
                {msg.error ? (
                  <div>
                    <p
                      role="alert"
                      className="text-sm whitespace-pre-wrap"
                      style={{ color: "var(--accent-danger)" }}
                    >
                      {msg.content || "The assistant failed to respond."}
                    </p>
                    {Boolean(msg.retry_content || msg.retry_images?.length) && (
                      <button
                        type="button"
                        onClick={() =>
                          void handleRetry(
                            msg.id,
                            msg.retry_content ?? "",
                            msg.retry_images ?? [],
                          )
                        }
                        disabled={sending}
                        className="mt-2 inline-flex items-center gap-1.5 text-xs font-semibold disabled:opacity-50"
                        style={{ color: "var(--accent-danger)" }}
                      >
                        <RefreshCw className="w-3 h-3" aria-hidden />
                        Retry
                      </button>
                    )}
                  </div>
                ) : msg.role === "assistant" ? (
                  // Assistant output may be shaped by untrusted tool data, so
                  // it renders through the exfiltration-safe markdown component
                  // (no auto-fetched images, no raw HTML, inert links).
                  <MarkdownMessage content={msg.content} />
                ) : (
                  msg.content && (
                    <p
                      className="text-sm whitespace-pre-wrap"
                      style={{
                        color:
                          msg.role === "user"
                            ? "var(--text-on-accent)"
                            : "var(--text-primary)",
                      }}
                    >
                      {msg.content}
                    </p>
                  )
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
                <MessageTime iso={msg.created_at} onAccent={msg.role === "user"} />
                <MessageTokenCaption message={msg} />
              </div>
              {msg.role === "user" && (
                <div
                  aria-hidden
                  className="w-8 h-8 rounded-[8px] flex items-center justify-center shrink-0"
                  style={{
                    background: "var(--accent-glow)",
                    border: "1px solid var(--border-accent)",
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
                aria-hidden
                className="w-8 h-8 rounded-[8px] flex items-center justify-center shrink-0"
                style={{
                  background: "var(--accent-glow)",
                  border: "1px solid var(--border-accent)",
                }}
              >
                <Shield className="w-4 h-4" style={{ color: "var(--accent-warning)" }} />
              </div>
              <div className="flex-1 min-w-0 space-y-2">
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
          {/* A turn that never reached the server. The user's message is
              still on screen above; this offers it back rather than making
              them retype it (or re-pick the images). */}
          {failedTurn && (
            <div
              role="alert"
              className="flex flex-wrap items-center gap-3 px-4 py-3 rounded-[12px]"
              style={{
                background: "var(--fill-danger)",
                border: "1px solid var(--border-danger)",
              }}
            >
              <AlertTriangle
                className="w-4 h-4 shrink-0"
                style={{ color: "var(--accent-danger)" }}
                aria-hidden
              />
              <p className="text-sm flex-1 min-w-0" style={{ color: "var(--accent-danger)" }}>
                {failedTurn.error}
              </p>
              <button
                type="button"
                onClick={() => {
                  const turn = failedTurn;
                  setFailedTurn(null);
                  // The retry re-appends the user's message, so drop the
                  // copy this attempt already left behind.
                  setMessages((prev) =>
                    prev.filter((m) => m.id !== turn.userTempId),
                  );
                  void sendContent(turn.content, turn.images);
                }}
                className="inline-flex items-center gap-1.5 px-3 py-2 rounded-[8px] text-xs font-semibold shrink-0"
                style={{
                  minHeight: 36,
                  border: "1px solid var(--border-danger)",
                  color: "var(--accent-danger)",
                }}
              >
                <RefreshCw className="w-3 h-3" aria-hidden />
                Retry
              </button>
            </div>
          )}
          {/* Live turn status: tool activity or a thinking indicator while
              the stream is in flight before the first token arrives. */}
          {sending && (
            <div
              role="status"
              aria-live="polite"
              className="flex items-center gap-2 pl-11"
              style={{ color: "var(--text-muted)" }}
            >
              <Loader2
                className="w-3.5 h-3.5 animate-spin"
                style={{ color: "var(--accent-primary)" }}
                aria-hidden
              />
              <span className="text-xs">{streamStatus ?? "Thinking…"}</span>
            </div>
          )}
          <div ref={messagesEndRef} />
        </div>

        {/* Shown only once the reader has left the live end of the thread —
            the counterpart to no longer auto-scrolling them. */}
        {!atBottom && (
          <div className="relative">
            <button
              type="button"
              onClick={jumpToLatest}
              className="absolute -top-12 right-4 inline-flex items-center gap-1.5 px-3 py-2 rounded-full text-xs font-medium shadow-lg"
              style={{
                background: "var(--claw-surface)",
                border: "1px solid var(--claw-border)",
                color: "var(--text-primary)",
              }}
            >
              <ChevronDown className="w-3.5 h-3.5" aria-hidden />
              Jump to latest
            </button>
          </div>
        )}

        <ChatComposer
          disabled={!activeConv}
          sending={sending}
          placeholder={
            activeConv ? "Ask SentientAI anything..." : "Start a conversation first"
          }
          onSend={(content, images) => void sendContent(content, images)}
          onStop={handleStop}
        />
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
