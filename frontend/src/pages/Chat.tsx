import { useState, useRef, useEffect, useCallback } from "react";
import {
  Send,
  Plus,
  Bot,
  User,
  Loader2,
  MessageSquare,
  ArrowUpRight,
} from "lucide-react";
import {
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import type { ChatResponse, Conversation, Message } from "@/types";
import {
  ApiError,
  createConversation,
  getConversation,
  getConversations,
  sendMessage,
} from "@/services/api";
import { toast } from "@/hooks/useToast";
import { Skeleton } from "@/components/ui/Skeleton";
import { ErrorBanner } from "@/components/ui/ErrorBanner";

function getErrorMessage(err: unknown, fallback: string): string {
  if (err instanceof ApiError) return err.message;
  if (err instanceof Error) return err.message;
  if (typeof err === "string") return err;
  return fallback;
}

interface ConversationDetail {
  id: string;
  title: string;
  created_at: string;
  updated_at: string;
  messages: Message[];
}

export default function Chat() {
  const queryClient = useQueryClient();
  const [activeConvId, setActiveConvId] = useState<string | null>(null);
  const [input, setInput] = useState("");
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // ── Queries ─────────────────────────────────────────────────────────────

  const conversationsQuery = useQuery({
    queryKey: ["conversations"],
    queryFn: getConversations,
  });

  const activeConversationQuery = useQuery({
    queryKey: ["conversation", activeConvId],
    queryFn: () =>
      getConversation(activeConvId!) as Promise<ConversationDetail>,
    enabled: Boolean(activeConvId),
  });

  const conversations: Conversation[] = conversationsQuery.data ?? [];
  const messages: Message[] = activeConversationQuery.data?.messages ?? [];

  const scrollToBottom = useCallback(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, []);

  useEffect(() => {
    scrollToBottom();
  }, [messages.length, scrollToBottom]);

  // ── Mutations ───────────────────────────────────────────────────────────

  const createConversationMutation = useMutation({
    mutationFn: (title: string) => createConversation(title),
    onSuccess: (conv) => {
      queryClient.setQueryData<Conversation[]>(["conversations"], (prev) => {
        if (!prev) return [conv];
        return [conv, ...prev.filter((c) => c.id !== conv.id)];
      });
      queryClient.invalidateQueries({ queryKey: ["conversations"] });
    },
    onError: (err: unknown) => {
      toast.error({
        title: "Couldn't create conversation",
        description: getErrorMessage(err, "Please try again."),
      });
    },
  });

  const sendMessageMutation = useMutation<
    ChatResponse,
    unknown,
    { convId: string; content: string },
    { previousDetail?: ConversationDetail; tempId: string }
  >({
    mutationFn: ({ convId, content }) => sendMessage(convId, content),
    onMutate: async ({ convId, content }) => {
      await queryClient.cancelQueries({ queryKey: ["conversation", convId] });
      const previousDetail = queryClient.getQueryData<ConversationDetail>([
        "conversation",
        convId,
      ]);
      const tempId = `temp-${Date.now()}`;
      const optimisticMsg: Message = {
        id: tempId,
        conversation_id: convId,
        role: "user",
        content,
      };
      queryClient.setQueryData<ConversationDetail | undefined>(
        ["conversation", convId],
        (old) => {
          if (!old) {
            return {
              id: convId,
              title: content.slice(0, 80),
              created_at: new Date().toISOString(),
              updated_at: new Date().toISOString(),
              messages: [optimisticMsg],
            };
          }
          return { ...old, messages: [...old.messages, optimisticMsg] };
        },
      );
      return { previousDetail, tempId };
    },
    onError: (err, vars, context) => {
      if (context?.previousDetail !== undefined) {
        queryClient.setQueryData(
          ["conversation", vars.convId],
          context.previousDetail,
        );
      }
      toast.error({
        title: "Message failed",
        description: getErrorMessage(
          err,
          "Something went wrong. Check your API key in Settings.",
        ),
      });
    },
    onSuccess: (resp, vars, context) => {
      // Replace the optimistic temp message with the server's authoritative pair.
      queryClient.setQueryData<ConversationDetail | undefined>(
        ["conversation", vars.convId],
        (old) => {
          const baseMessages = (old?.messages ?? []).filter(
            (m) => m.id !== context?.tempId,
          );
          return {
            id: vars.convId,
            title: old?.title ?? resp.user_message.content.slice(0, 80),
            created_at: old?.created_at ?? new Date().toISOString(),
            updated_at: new Date().toISOString(),
            messages: [...baseMessages, resp.user_message, resp.assistant_message],
          };
        },
      );
      queryClient.setQueryData<Conversation[] | undefined>(
        ["conversations"],
        (prev) =>
          prev?.map((c) =>
            c.id === vars.convId
              ? {
                  ...c,
                  title: resp.user_message.content.slice(0, 80),
                  updated_at: new Date().toISOString(),
                }
              : c,
          ) ?? prev,
      );
      queryClient.invalidateQueries({ queryKey: ["conversations"] });
    },
  });

  // ── Handlers ────────────────────────────────────────────────────────────

  const handleNewChat = () => {
    createConversationMutation.mutate("New Conversation", {
      onSuccess: (conv) => setActiveConvId(conv.id),
    });
  };

  const handleSend = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim() || sendMessageMutation.isPending) return;

    const userContent = input.trim();
    setInput("");

    let convId = activeConvId;
    if (!convId) {
      try {
        const conv = await createConversationMutation.mutateAsync(
          "New Conversation",
        );
        convId = conv.id;
        setActiveConvId(conv.id);
      } catch {
        // Toast already fired in mutation onError; restore input so it isn't lost.
        setInput(userContent);
        return;
      }
    }

    sendMessageMutation.mutate({ convId, content: userContent });
  };

  const sending = sendMessageMutation.isPending;

  return (
    <div
      className="flex h-[calc(100vh-5rem)] rounded-[var(--radius-xl)] border border-[var(--border-subtle)] overflow-hidden min-w-0"
      style={{ backgroundColor: "var(--bg-secondary)", boxShadow: "var(--shadow-card)" }}
    >
      {/* Conversation sidebar */}
      <div className="w-[280px] shrink-0 border-r border-[var(--border-subtle)] flex flex-col bg-[var(--bg-secondary)]">
        <div className="p-3 border-b border-[var(--border-subtle)]">
          <button
            type="button"
            onClick={handleNewChat}
            disabled={createConversationMutation.isPending}
            className="w-full flex items-center justify-center gap-2 py-2.5 rounded-[12px] text-[14px] font-semibold text-white bg-[var(--accent-primary)] hover:brightness-110 transition-all disabled:opacity-50"
          >
            {createConversationMutation.isPending ? (
              <Loader2 className="w-4 h-4 animate-spin" strokeWidth={2.5} />
            ) : (
              <Plus className="w-4 h-4" strokeWidth={2.5} />
            )}{" "}
            New Chat
          </button>
        </div>
        <div className="flex-1 overflow-y-auto min-h-0">
          {conversationsQuery.isLoading && (
            <div className="p-3 space-y-2">
              {Array.from({ length: 5 }).map((_, i) => (
                <Skeleton key={i} height="h-10" width="w-full" className="rounded-[10px]" />
              ))}
            </div>
          )}
          {conversationsQuery.isError && (
            <div className="p-3">
              <ErrorBanner
                title="Couldn't load conversations"
                error={conversationsQuery.error}
                onRetry={() => conversationsQuery.refetch()}
                retrying={conversationsQuery.isFetching}
              />
            </div>
          )}
          {!conversationsQuery.isLoading &&
            !conversationsQuery.isError &&
            conversations.length === 0 && (
              <div className="text-center py-10 px-4">
                <MessageSquare
                  className="w-8 h-8 text-[var(--text-muted)] mx-auto mb-2"
                  strokeWidth={1.5}
                />
                <p className="text-[13px] text-[var(--text-primary)] font-medium">
                  No conversations yet
                </p>
                <p className="mt-1 text-[12px] text-[var(--text-muted)]">
                  Start one with the New button above
                </p>
                <ArrowUpRight
                  className="w-4 h-4 mx-auto mt-2 text-[var(--accent-primary)] -rotate-90"
                  strokeWidth={2}
                  aria-hidden="true"
                />
              </div>
            )}
          {conversations.map((conv) => (
            <button
              key={conv.id}
              type="button"
              onClick={() => setActiveConvId(conv.id)}
              className="w-full text-left px-4 py-3 border-b border-[var(--border-subtle)] transition-colors"
              style={{
                backgroundColor:
                  activeConvId === conv.id ? "rgba(10,132,255,0.12)" : "transparent",
              }}
            >
              <span
                className="text-[14px] font-medium truncate block"
                style={{
                  color:
                    activeConvId === conv.id
                      ? "var(--text-primary)"
                      : "var(--text-secondary)",
                }}
              >
                {conv.title}
              </span>
            </button>
          ))}
        </div>
      </div>

      {/* Chat area */}
      <div className="flex-1 flex flex-col min-w-0 bg-[var(--bg-primary)]">
        <div className="flex-1 overflow-y-auto p-5 md:p-8 min-h-0">
          {!activeConvId && !sending && (
            <div className="flex flex-col items-center justify-center h-full text-center gap-4">
              <div className="w-16 h-16 rounded-[16px] bg-[rgba(10,132,255,0.15)] flex items-center justify-center">
                <Bot className="w-8 h-8 text-[var(--accent-primary)]" strokeWidth={1.5} />
              </div>
              <div>
                <h2 className="text-[20px] font-semibold text-[var(--text-primary)]">
                  Start a conversation
                </h2>
                <p className="text-[14px] text-[var(--text-muted)] mt-1 max-w-sm">
                  Ask SentientAI anything. Your messages are processed securely.
                </p>
              </div>
            </div>
          )}

          {activeConvId && activeConversationQuery.isLoading && (
            <div className="max-w-3xl mx-auto space-y-5">
              {Array.from({ length: 3 }).map((_, i) => (
                <div
                  key={i}
                  className={`flex gap-3 ${i % 2 === 0 ? "" : "justify-end"}`}
                >
                  {i % 2 === 0 && (
                    <Skeleton width="w-9" height="h-9" className="rounded-[12px] shrink-0" />
                  )}
                  <Skeleton
                    width={i % 2 === 0 ? "w-2/3" : "w-1/2"}
                    height="h-12"
                    className="rounded-[16px]"
                  />
                  {i % 2 === 1 && (
                    <Skeleton width="w-9" height="h-9" className="rounded-[12px] shrink-0" />
                  )}
                </div>
              ))}
            </div>
          )}

          {activeConvId && activeConversationQuery.isError && (
            <div className="max-w-3xl mx-auto">
              <ErrorBanner
                title="Couldn't load conversation"
                error={activeConversationQuery.error}
                onRetry={() => activeConversationQuery.refetch()}
                retrying={activeConversationQuery.isFetching}
              />
            </div>
          )}

          {activeConvId && !activeConversationQuery.isLoading && !activeConversationQuery.isError && (
            <div className="max-w-3xl mx-auto space-y-5">
              {messages.map((msg) => (
                <div key={msg.id} className={`flex gap-3 ${msg.role === "user" ? "justify-end" : ""}`}>
                  {msg.role === "assistant" && (
                    <div className="w-9 h-9 rounded-[12px] bg-[rgba(10,132,255,0.15)] flex items-center justify-center shrink-0 mt-0.5">
                      <Bot className="w-[18px] h-[18px] text-[var(--accent-primary)]" strokeWidth={1.75} />
                    </div>
                  )}
                  <div
                    className="max-w-[80%] rounded-[16px] px-4 py-3 min-w-0"
                    style={{
                      backgroundColor: msg.role === "user" ? "var(--accent-primary)" : "var(--bg-secondary)",
                      border: msg.role === "assistant" ? "1px solid var(--border-subtle)" : "none",
                    }}
                  >
                    <p
                      className="text-[15px] leading-relaxed whitespace-pre-wrap break-words"
                      style={{ color: msg.role === "user" ? "#fff" : "var(--text-primary)" }}
                    >
                      {msg.content}
                    </p>
                  </div>
                  {msg.role === "user" && (
                    <div className="w-9 h-9 rounded-[12px] bg-[rgba(10,132,255,0.25)] flex items-center justify-center shrink-0 mt-0.5">
                      <User className="w-[18px] h-[18px] text-[var(--accent-primary)]" strokeWidth={1.75} />
                    </div>
                  )}
                </div>
              ))}

              {sending && (
                <div className="flex gap-3">
                  <div className="w-9 h-9 rounded-[12px] bg-[rgba(10,132,255,0.15)] flex items-center justify-center shrink-0">
                    <Bot className="w-[18px] h-[18px] text-[var(--accent-primary)]" strokeWidth={1.75} />
                  </div>
                  <div className="rounded-[16px] px-4 py-3 border border-[var(--border-subtle)] bg-[var(--bg-secondary)]">
                    <div className="flex items-center gap-2 text-[14px] text-[var(--text-muted)]">
                      <Loader2 className="w-4 h-4 animate-spin" /> Thinking...
                    </div>
                  </div>
                </div>
              )}

              <div ref={messagesEndRef} />
            </div>
          )}
        </div>

        {/* Input bar */}
        <div className="px-5 pb-5 md:px-8 md:pb-6 pt-2">
          <form onSubmit={handleSend} className="max-w-3xl mx-auto">
            <div className="flex items-center gap-3 rounded-[16px] border border-[var(--border-primary)] bg-[var(--bg-secondary)] px-4 py-2.5 shadow-sm focus-within:border-[var(--accent-primary)] transition-colors">
              <input
                type="text"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                placeholder="Ask SentientAI anything..."
                disabled={sending}
                aria-label="Message"
                className="flex-1 bg-transparent outline-none text-[15px] text-[var(--text-primary)] placeholder:text-[var(--text-muted)] disabled:opacity-50"
              />
              <button
                type="submit"
                disabled={!input.trim() || sending}
                className="w-9 h-9 rounded-[10px] flex items-center justify-center transition-all shrink-0 disabled:opacity-30"
                style={{ backgroundColor: input.trim() ? "var(--accent-primary)" : "transparent" }}
              >
                <Send
                  className="w-[18px] h-[18px]"
                  style={{ color: input.trim() ? "#fff" : "var(--text-muted)" }}
                  strokeWidth={2}
                />
              </button>
            </div>
            <p className="text-center text-[11px] text-[var(--text-muted)] mt-2">
              SentientAI may make mistakes. Verify important information.
            </p>
          </form>
        </div>
      </div>
    </div>
  );
}
