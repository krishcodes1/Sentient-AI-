/**
 * Memory page: the memory on/off switch, an add form, a debounced search with category filters,
 * inline editing and confirmed deletion.
 *
 * Why it exists: Users need to see and correct what the assistant is told about them; load state
 * is derived from the last settled query so filtering never flashes the list empty.
 */

import { useEffect, useId, useMemo, useState, type FormEvent } from "react";
import {
  Brain,
  Plus,
  Trash2,
  Loader2,
  Pencil,
  Check,
  X,
  RefreshCw,
  Search,
  ShieldCheck,
} from "lucide-react";
import clsx from "clsx";
import type { Memory, MemoryCategory, User } from "@/types";
import {
  createMemory,
  deleteMemory,
  getMe,
  getMemories,
  updateMemory,
  updateSettings,
} from "@/services/api";
import ConfirmDialog from "@/components/ConfirmDialog";

const CATEGORIES: { value: MemoryCategory; label: string; help: string }[] = [
  { value: "profile", label: "Profile", help: "Who you are — name, role, school." },
  { value: "preference", label: "Preference", help: "How you like the assistant to behave." },
  { value: "project", label: "Project", help: "Ongoing work or goals." },
  { value: "fact", label: "Fact", help: "Any other durable fact." },
];

const CATEGORY_COLORS: Record<MemoryCategory, string> = {
  profile: "var(--accent-primary)",
  preference: "var(--accent-warning)",
  project: "var(--accent-success)",
  fact: "var(--text-secondary)",
};

type CategoryFilter = MemoryCategory | "all";

// Long enough that typing does not fire a request per keystroke, short
// enough that the list still feels live.
const SEARCH_DEBOUNCE_MS = 250;

// Mirrors MAX_SEARCH_CHARS in backend/services/memory.py. Capping the input
// means the user can never type their way into a 422.
const SEARCH_MAX_LENGTH = 200;

const panelStyle = {
  background: "var(--claw-panel)",
  border: "1px solid var(--claw-border)",
  boxShadow: "var(--shadow-card)",
};

const inputStyle = {
  background: "var(--bg-input)",
  border: "1px solid var(--claw-border)",
  color: "var(--text-primary)",
};

function CategoryPill({ category }: { category: MemoryCategory }) {
  return (
    <span
      className="mono-tag px-2 py-0.5 rounded-[6px] capitalize"
      style={{
        color: CATEGORY_COLORS[category],
        border: `1px solid ${CATEGORY_COLORS[category]}`,
        opacity: 0.9,
      }}
    >
      {category}
    </span>
  );
}

export default function MemoryPage() {
  const memoryToggleId = useId();
  const newMemoryId = useId();
  const [me, setMe] = useState<User | null>(null);
  const [memories, setMemories] = useState<Memory[]>([]);
  const [retryKey, setRetryKey] = useState(0);

  // Filters. `search` tracks the input; `debouncedSearch` is what actually
  // reaches the API, so a fast typist issues one request instead of ten.
  const [search, setSearch] = useState("");
  const [debouncedSearch, setDebouncedSearch] = useState("");
  const [categoryFilter, setCategoryFilter] = useState<CategoryFilter>("all");

  // Add form
  const [newContent, setNewContent] = useState("");
  const [newCategory, setNewCategory] = useState<MemoryCategory>("fact");
  const [adding, setAdding] = useState(false);
  const [addError, setAddError] = useState<string | null>(null);

  // Inline edit
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editText, setEditText] = useState("");
  const [editError, setEditError] = useState<string | null>(null);

  // Delete
  const [deleteTarget, setDeleteTarget] = useState<Memory | null>(null);

  // Toggle
  const [togglingMemory, setTogglingMemory] = useState(false);

  useEffect(() => {
    const timer = setTimeout(
      () => setDebouncedSearch(search.trim()),
      SEARCH_DEBOUNCE_MS,
    );
    return () => clearTimeout(timer);
  }, [search]);

  const filtersActive = debouncedSearch !== "" || categoryFilter !== "all";

  // Load state is derived from which query last settled rather than flipped
  // by the fetch effect: a new query (retry, reload, search, category) reads
  // as refreshing — with the old query's error gone — in the very render
  // that asks for it.
  const query = `${retryKey}\u0000${debouncedSearch}\u0000${categoryFilter}`;
  const [settled, setSettled] = useState<{ query: string; error: string | null } | null>(
    null,
  );
  // `loading` covers the first paint only. Later fetches keep the current
  // results on screen so the list does not flash empty between keystrokes.
  const loading = settled === null;
  const refreshing = settled?.query !== query;
  const loadError = settled?.query === query ? settled.error : null;

  useEffect(() => {
    let cancelled = false;
    // getMe() is memoized in the api layer, so re-requesting it alongside a
    // filter change costs nothing and keeps a single error path for both.
    Promise.all([
      getMe(),
      getMemories({
        q: debouncedSearch || undefined,
        category: categoryFilter === "all" ? undefined : categoryFilter,
      }),
    ])
      .then(([user, mems]) => {
        if (cancelled) return;
        setMe(user);
        setMemories(mems);
        setSettled({ query, error: null });
      })
      .catch((err: Error) => {
        if (!cancelled) setSettled({ query, error: err.message });
      });
    return () => {
      cancelled = true;
    };
    // `query` already encodes retryKey; it is how reload() re-runs this.
  }, [query, debouncedSearch, categoryFilter]);

  const reload = () => setRetryKey((k) => k + 1);

  const memoryEnabled = me?.memory_enabled ?? true;

  const emptyFilterLabel = useMemo(() => {
    const parts: string[] = [];
    if (debouncedSearch) parts.push(`"${debouncedSearch}"`);
    if (categoryFilter !== "all") parts.push(`category "${categoryFilter}"`);
    return parts.join(" in ");
  }, [debouncedSearch, categoryFilter]);

  const handleToggleMemory = async () => {
    if (!me) return;
    setTogglingMemory(true);
    try {
      const updated = await updateSettings({ memory_enabled: !memoryEnabled });
      setMe(updated);
    } catch {
      /* leave the toggle as-is on failure */
    } finally {
      setTogglingMemory(false);
    }
  };

  const handleAdd = async (e: FormEvent) => {
    e.preventDefault();
    const content = newContent.trim();
    if (!content || adding) return;
    setAdding(true);
    setAddError(null);
    try {
      const created = await createMemory({ content, category: newCategory });
      // Whether the new memory belongs in a filtered list is the server's
      // call (it owns the matching rules), so refetch instead of guessing.
      if (filtersActive) reload();
      else setMemories((prev) => [created, ...prev]);
      setNewContent("");
      setNewCategory("fact");
    } catch (err) {
      setAddError((err as Error).message);
    } finally {
      setAdding(false);
    }
  };

  const startEdit = (m: Memory) => {
    setEditingId(m.id);
    setEditText(m.content);
    setEditError(null);
  };

  const commitEdit = async (id: string) => {
    const content = editText.trim();
    const current = memories.find((m) => m.id === id);
    if (!content || !current || content === current.content) {
      setEditingId(null);
      return;
    }
    try {
      const updated = await updateMemory(id, { content });
      setMemories((prev) => prev.map((m) => (m.id === id ? updated : m)));
      setEditingId(null);
      // An edit can move a memory in or out of the active search, so let
      // the server re-decide the visible set.
      if (filtersActive) reload();
    } catch (err) {
      setEditError((err as Error).message);
    }
  };

  const handleDelete = async () => {
    if (!deleteTarget) return;
    await deleteMemory(deleteTarget.id);
    setMemories((prev) => prev.filter((m) => m.id !== deleteTarget.id));
    setDeleteTarget(null);
  };

  return (
    <div className="space-y-6 max-w-3xl">
      <div>
        <div className="eyebrow mb-2">Personalization</div>
        <h1 className="flex items-center gap-2.5" style={{ color: "var(--text-primary)" }}>
          <Brain className="w-6 h-6" style={{ color: "var(--accent-primary)" }} />
          Memory
        </h1>
        <p className="text-sm mt-1.5" style={{ color: "var(--text-secondary)" }}>
          Durable facts Crawler AI remembers across every conversation. Saved
          memories are injected into the assistant's context — and screened for
          injection content before they are ever stored.
        </p>
      </div>

      {/* Enable toggle */}
      <section
        className="rounded-[14px] p-5 flex items-center justify-between gap-4 flex-wrap"
        style={panelStyle}
      >
        <div className="flex items-start gap-3 min-w-0">
          <ShieldCheck
            className="w-5 h-5 mt-0.5 shrink-0"
            aria-hidden
            style={{ color: memoryEnabled ? "var(--accent-success)" : "var(--text-muted)" }}
          />
          <div className="min-w-0">
            <div id={memoryToggleId} className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>
              Use memory in conversations
            </div>
            <div className="text-xs mt-0.5" style={{ color: "var(--text-muted)" }}>
              {memoryEnabled
                ? "Your saved memories are added to the assistant's context."
                : "Memory is off — saved memories are kept but not used."}
            </div>
          </div>
        </div>
        <button
          type="button"
          onClick={handleToggleMemory}
          disabled={togglingMemory || !me}
          role="switch"
          aria-checked={memoryEnabled}
          aria-labelledby={memoryToggleId}
          className="tap-target relative inline-flex h-6 w-11 shrink-0 items-center rounded-full transition-colors disabled:opacity-50"
          style={{ background: memoryEnabled ? "var(--accent-primary)" : "var(--claw-border)" }}
        >
          <span
            aria-hidden
            className="inline-block h-4 w-4 transform rounded-full transition-transform"
            style={{
              background: "var(--text-on-accent)",
              transform: memoryEnabled ? "translateX(24px)" : "translateX(4px)",
            }}
          />
        </button>
      </section>

      {/* Add memory */}
      <section className="rounded-[14px] p-6" style={panelStyle}>
        <div className="eyebrow mb-1">Add</div>
        <h2 className="mb-4">New memory</h2>
        <form onSubmit={handleAdd} className="space-y-3">
          <label htmlFor={newMemoryId} className="sr-only">
            New memory
          </label>
          <textarea
            id={newMemoryId}
            value={newContent}
            onChange={(e) => setNewContent(e.target.value)}
            placeholder="e.g. I'm a computer science student at NYIT and prefer concise, technical answers."
            rows={2}
            maxLength={500}
            className="w-full px-3.5 py-2.5 rounded-[10px] text-sm outline-none resize-none"
            style={inputStyle}
          />
          <div className="flex items-center gap-3 flex-wrap">
            <div className="flex gap-2">
              {CATEGORIES.map((c) => {
                const active = newCategory === c.value;
                return (
                  <button
                    key={c.value}
                    type="button"
                    onClick={() => setNewCategory(c.value)}
                    title={c.help}
                    className="px-3 py-1.5 rounded-[8px] text-xs font-medium capitalize transition-colors"
                    style={{
                      background: active ? "var(--accent-glow)" : "var(--claw-surface)",
                      border: active
                        ? "1px solid var(--border-accent)"
                        : "1px solid var(--claw-border)",
                      color: active ? "var(--accent-primary)" : "var(--text-secondary)",
                    }}
                  >
                    {c.label}
                  </button>
                );
              })}
            </div>
            <button
              type="submit"
              disabled={!newContent.trim() || adding}
              className="ml-auto flex items-center gap-2 px-4 rounded-[10px] text-sm font-semibold disabled:opacity-50"
              style={{
                minHeight: 44,
                background: "var(--accent-primary)",
                color: "var(--text-on-accent)",
              }}
            >
              {adding ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
              Save Memory
            </button>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-xs" style={{ color: "var(--text-muted)" }}>
              {newContent.length}/500
            </span>
            {addError && (
              <span role="alert" className="text-xs" style={{ color: "var(--accent-danger)" }}>
                {addError}
              </span>
            )}
          </div>
        </form>
      </section>

      {/* Memory list */}
      <section className="rounded-[14px] p-6" style={panelStyle}>
        <div className="flex items-center justify-between mb-4">
          <div>
            <div className="eyebrow mb-1">Saved</div>
            <h2>Your memories</h2>
          </div>
          <span className="mono-tag" style={{ color: "var(--text-muted)" }}>
            {memories.length} {filtersActive ? "matching" : "saved"}
          </span>
        </div>

        {/* Search + category filter */}
        <div className="flex items-center gap-2 flex-wrap mb-4">
          <div className="relative flex-1 min-w-[200px]">
            <Search
              className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none"
              style={{ color: "var(--text-muted)" }}
            />
            {/* Deliberately type="text": type="search" would paint the
                browser's own clear button next to the one below it. */}
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search memories..."
              aria-label="Search memories"
              maxLength={SEARCH_MAX_LENGTH}
              className="w-full pl-9 pr-9 py-2 rounded-[10px] text-sm outline-none"
              style={inputStyle}
            />
            {refreshing && !loading ? (
              <Loader2
                className="w-3.5 h-3.5 absolute right-3 top-1/2 -translate-y-1/2 animate-spin"
                style={{ color: "var(--text-muted)" }}
              />
            ) : (
              search !== "" && (
                <button
                  type="button"
                  aria-label="Clear search"
                  onClick={() => setSearch("")}
                  className="tap-target absolute right-2.5 top-1/2 -translate-y-1/2 p-1 rounded-[6px]"
                  style={{ color: "var(--text-muted)" }}
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              )
            )}
          </div>
          <div className="flex gap-1.5 flex-wrap">
            {([{ value: "all" as const, label: "All" }, ...CATEGORIES]).map(
              (c) => {
                const active = categoryFilter === c.value;
                return (
                  <button
                    key={c.value}
                    type="button"
                    onClick={() => setCategoryFilter(c.value)}
                    aria-pressed={active}
                    className="px-2.5 py-1.5 rounded-[8px] text-xs font-medium capitalize transition-colors"
                    style={{
                      background: active ? "var(--accent-glow)" : "var(--claw-surface)",
                      border: active
                        ? "1px solid var(--border-accent)"
                        : "1px solid var(--claw-border)",
                      color: active ? "var(--accent-primary)" : "var(--text-secondary)",
                    }}
                  >
                    {c.label}
                  </button>
                );
              },
            )}
          </div>
        </div>

        {loading && (
          <div
            role="status"
            className="flex items-center gap-2 py-8 justify-center"
            style={{ color: "var(--text-muted)" }}
          >
            <Loader2 className="w-4 h-4 animate-spin" aria-hidden />
            <span className="text-sm">Loading memories...</span>
          </div>
        )}

        {!loading && loadError && (
          <div
            role="alert"
            className="rounded-[10px] p-4 flex items-center justify-between gap-3 flex-wrap"
            style={{ background: "var(--fill-danger)", border: "1px solid var(--border-danger)" }}
          >
            <span className="text-sm" style={{ color: "var(--accent-danger)" }}>
              Failed to load: {loadError}
            </span>
            <button
              type="button"
              onClick={() => setRetryKey((k) => k + 1)}
              className="inline-flex items-center gap-1.5 text-xs font-semibold"
              style={{ color: "var(--accent-danger)" }}
            >
              <RefreshCw className="w-3 h-3" /> Retry
            </button>
          </div>
        )}

        {!loading && !loadError && memories.length === 0 && !filtersActive && (
          <p className="text-sm text-center py-8" style={{ color: "var(--text-muted)" }}>
            No memories yet. Add one above and Crawler AI will remember it.
          </p>
        )}

        {/* Distinct from "no memories yet" — the user has memories, this
            filter just does not reach any of them. */}
        {!loading && !loadError && memories.length === 0 && filtersActive && (
          <div className="text-center py-8">
            <p className="text-sm" style={{ color: "var(--text-muted)" }}>
              No memories match {emptyFilterLabel}.
            </p>
            <button
              type="button"
              onClick={() => {
                setSearch("");
                setCategoryFilter("all");
              }}
              className="mt-2 text-xs font-semibold"
              style={{ color: "var(--accent-primary)" }}
            >
              Clear filters
            </button>
          </div>
        )}

        {!loading && !loadError && memories.length > 0 && (
          <ul className="space-y-2">
            {memories.map((m) => {
              const isEditing = editingId === m.id;
              return (
                <li
                  key={m.id}
                  className={clsx("group rounded-[10px] px-4 py-3")}
                  style={{ background: "var(--claw-surface)", border: "1px solid var(--claw-border)" }}
                >
                  {isEditing ? (
                    <div className="space-y-2">
                      <textarea
                        value={editText}
                        autoFocus
                        rows={2}
                        maxLength={500}
                        onChange={(e) => setEditText(e.target.value)}
                        className="w-full px-3 py-2 rounded-[8px] text-sm outline-none resize-none"
                        style={{ ...inputStyle, border: "1px solid var(--accent-primary)" }}
                      />
                      {editError && (
                        <p role="alert" className="text-xs" style={{ color: "var(--accent-danger)" }}>
                          {editError}
                        </p>
                      )}
                      <div className="flex gap-2">
                        <button
                          type="button"
                          onClick={() => commitEdit(m.id)}
                          className="inline-flex items-center gap-1 px-2.5 py-1 rounded-[6px] text-xs font-semibold"
                          style={{
                            minHeight: 32,
                            background: "var(--accent-success)",
                            color: "var(--text-on-accent)",
                          }}
                        >
                          <Check className="w-3 h-3" /> Save
                        </button>
                        <button
                          type="button"
                          onClick={() => setEditingId(null)}
                          className="inline-flex items-center gap-1 px-2.5 py-1 rounded-[6px] text-xs font-medium"
                          style={{ border: "1px solid var(--claw-border)", color: "var(--text-secondary)" }}
                        >
                          <X className="w-3 h-3" /> Cancel
                        </button>
                      </div>
                    </div>
                  ) : (
                    <div className="flex items-start gap-3">
                      <div className="flex-1 min-w-0">
                        <p className="text-sm" style={{ color: "var(--text-primary)" }}>
                          {m.content}
                        </p>
                        <div className="flex items-center gap-2 mt-1.5">
                          <CategoryPill category={m.category} />
                          {m.source === "agent" && (
                            <span className="mono-tag" style={{ color: "var(--text-muted)" }}>
                              proposed by assistant
                            </span>
                          )}
                        </div>
                      </div>
                      <div className="row-actions flex items-center gap-1 shrink-0">
                        <button
                          type="button"
                          aria-label={`Edit memory: ${m.content.slice(0, 40)}`}
                          onClick={() => startEdit(m)}
                          className="tap-target p-1.5 rounded-[6px]"
                          style={{ color: "var(--text-muted)" }}
                        >
                          <Pencil className="w-3.5 h-3.5" />
                        </button>
                        <button
                          type="button"
                          aria-label={`Delete memory: ${m.content.slice(0, 40)}`}
                          onClick={() => setDeleteTarget(m)}
                          className="tap-target p-1.5 rounded-[6px]"
                          style={{ color: "var(--accent-danger)" }}
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </section>

      <ConfirmDialog
        open={deleteTarget !== null}
        danger
        title="Delete this memory?"
        message={`"${deleteTarget?.content ?? ""}" will be permanently forgotten. This cannot be undone.`}
        confirmLabel="Delete"
        onCancel={() => setDeleteTarget(null)}
        onConfirm={handleDelete}
      />
    </div>
  );
}
