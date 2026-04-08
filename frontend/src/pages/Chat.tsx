import { useState, useRef, useEffect, useCallback } from "react";
import {
  Send,
  Plus,
  Bot,
  User,
  Loader2,
  MessageSquare,
} from "lucide-react";
import type { Conversation, Message } from "@/types";
import {
  getConversations,
  createConversation,
  getMessages,
  sendMessage,
} from "@/services/api";

export default function Chat() {
  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [activeConvId, setActiveConvId] = useState<string | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);
  const [loadingConvos, setLoadingConvos] = useState(true);
  const [loadingMessages, setLoadingMessages] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = useCallback(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, []);

  useEffect(() => { scrollToBottom(); }, [messages, scrollToBottom]);

  useEffect(() => {
    getConversations()
      .then(setConversations)
      .catch(() => {})
      .finally(() => setLoadingConvos(false));
  }, []);

  const loadMessages = async (convId: string) => {
    setActiveConvId(convId);
    setLoadingMessages(true);
    try {
      const msgs = await getMessages(convId);
      setMessages(msgs);
    } catch {
      setMessages([]);
    } finally {
      setLoadingMessages(false);
    }
  };

  const handleNewChat = async () => {
    try {
      const conv = await createConversation("New Conversation");
      setConversations((prev) => [conv, ...prev]);
      setActiveConvId(conv.id);
      setMessages([]);
    } catch {}
  };

  const handleSend = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim() || sending) return;

    let convId = activeConvId;

    if (!convId) {
      try {
        const conv = await createConversation("New Conversation");
        setConversations((prev) => [conv, ...prev]);
        convId = conv.id;
        setActiveConvId(convId);
      } catch {
        return;
      }
    }

    const userContent = input.trim();
    setInput("");
    setSending(true);

    const tempUserMsg: Message = {
      id: `temp-${Date.now()}`,
      conversation_id: convId,
      role: "user",
      content: userContent,
    };
    setMessages((prev) => [...prev, tempUserMsg]);

    try {
      const resp = await sendMessage(convId, userContent);
      setMessages((prev) => {
        const withoutTemp = prev.filter((m) => m.id !== tempUserMsg.id);
        return [...withoutTemp, resp.user_message, resp.assistant_message];
      });
      setConversations((prev) =>
        prev.map((c) =>
          c.id === convId ? { ...c, title: resp.user_message.content.slice(0, 80), updated_at: new Date().toISOString() } : c
        )
      );
    } catch (err: any) {
      const errMsg: Message = {
        id: `err-${Date.now()}`,
        conversation_id: convId,
        role: "assistant",
        content: `Something went wrong: ${err.message || "Unknown error"}. Check your API key in Settings.`,
      };
      setMessages((prev) => [...prev, errMsg]);
    } finally {
      setSending(false);
    }
  };

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
            className="w-full flex items-center justify-center gap-2 py-2.5 rounded-[12px] text-[14px] font-semibold text-white bg-[var(--accent-primary)] hover:brightness-110 transition-all"
          >
            <Plus className="w-4 h-4" strokeWidth={2.5} /> New Chat
          </button>
        </div>
        <div className="flex-1 overflow-y-auto min-h-0">
          {loadingConvos && (
            <div className="flex items-center justify-center py-10">
              <Loader2 className="w-5 h-5 animate-spin text-[var(--text-muted)]" />
            </div>
          )}
          {!loadingConvos && conversations.length === 0 && (
            <div className="text-center py-10 px-4">
              <MessageSquare className="w-8 h-8 text-[var(--text-muted)] mx-auto mb-2" strokeWidth={1.5} />
              <p className="text-[13px] text-[var(--text-muted)]">No conversations yet</p>
            </div>
          )}
          {conversations.map((conv) => (
            <button
              key={conv.id}
              type="button"
              onClick={() => loadMessages(conv.id)}
              className="w-full text-left px-4 py-3 border-b border-[var(--border-subtle)] transition-colors"
              style={{
                backgroundColor: activeConvId === conv.id ? "rgba(10,132,255,0.12)" : "transparent",
              }}
            >
              <span
                className="text-[14px] font-medium truncate block"
                style={{
                  color: activeConvId === conv.id ? "var(--text-primary)" : "var(--text-secondary)",
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
        {/* Messages */}
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

          {activeConvId && loadingMessages && (
            <div className="flex items-center justify-center h-full">
              <Loader2 className="w-6 h-6 animate-spin text-[var(--text-muted)]" />
            </div>
          )}

          {activeConvId && !loadingMessages && (
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
            <div
              className="flex items-center gap-3 rounded-[16px] border border-[var(--border-primary)] bg-[var(--bg-secondary)] px-4 py-2.5 shadow-sm focus-within:border-[var(--accent-primary)] transition-colors"
            >
              <input
                type="text"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                placeholder="Ask SentientAI anything..."
                disabled={sending}
                className="flex-1 bg-transparent outline-none text-[15px] text-[var(--text-primary)] placeholder:text-[var(--text-muted)] disabled:opacity-50"
              />
              <button
                type="submit"
                disabled={!input.trim() || sending}
                className="w-9 h-9 rounded-[10px] flex items-center justify-center transition-all shrink-0 disabled:opacity-30"
                style={{
                  backgroundColor: input.trim() ? "var(--accent-primary)" : "transparent",
                }}
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
