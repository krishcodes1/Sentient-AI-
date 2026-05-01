import { useEffect, useMemo, useState } from "react";
import {
  Search,
  CheckCircle2,
  XCircle,
  Clock,
  ChevronRight,
  ShieldCheck,
  ShieldAlert,
  Hash,
  ChevronLeft,
  ChevronRight as ChevronRightIcon,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import type { AuditLog } from "@/types";
import { getAuditLogs, verifyAuditChain } from "@/services/api";
import { Skeleton } from "@/components/ui/Skeleton";
import { ErrorBanner } from "@/components/ui/ErrorBanner";
import { EmptyState } from "@/components/ui/EmptyState";

interface StatusConfigEntry {
  icon: LucideIcon;
  color: string;
  label: string;
}

// Includes "escalated" so we never crash on it.
const statusConfig: Record<
  "approved" | "blocked" | "pending" | "escalated",
  StatusConfigEntry
> = {
  approved: { icon: CheckCircle2, color: "var(--accent-success)", label: "Approved" },
  blocked: { icon: XCircle, color: "var(--accent-danger)", label: "Blocked" },
  pending: { icon: Clock, color: "var(--accent-warning)", label: "Pending" },
  escalated: { icon: ShieldAlert, color: "var(--accent-warning)", label: "Escalated" },
};

interface AuditFilters {
  action?: string;
  status?: string;
  from_ts?: string;
  to_ts?: string;
  limit?: number;
  offset?: number;
}

interface AuditChainResponse {
  valid: boolean;
  broken_at?: string | null;
  message?: string;
}

const PAGE_SIZE = 25;

function useDebounced<T>(value: T, delay: number): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const handle = setTimeout(() => setDebounced(value), delay);
    return () => clearTimeout(handle);
  }, [value, delay]);
  return debounced;
}

function LogRow({
  log,
  expanded,
  onToggle,
}: {
  log: AuditLog;
  expanded: boolean;
  onToggle: () => void;
}) {
  const cfg = statusConfig[log.status as keyof typeof statusConfig] ?? statusConfig.pending;
  const StatusIcon = cfg.icon;
  const ts = new Date(log.timestamp);

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      onToggle();
    }
  };

  return (
    <>
      <tr
        role="button"
        tabIndex={0}
        aria-expanded={expanded}
        className="cursor-pointer transition-colors hover:bg-[rgba(255,255,255,0.04)] focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-primary)]"
        style={{ borderBottom: "1px solid var(--border-subtle)" }}
        onClick={onToggle}
        onKeyDown={onKeyDown}
      >
        <td className="px-4 py-3.5">
          <ChevronRight
            className={`w-4 h-4 transition-transform text-[var(--text-muted)] ${expanded ? "rotate-90" : ""}`}
            aria-hidden="true"
          />
        </td>
        <td className="px-4 py-3.5 text-[12px] text-[var(--text-secondary)] tabular-nums">
          {ts.toLocaleTimeString()} <br />
          <span className="text-[var(--text-muted)]">{ts.toLocaleDateString()}</span>
        </td>
        <td className="px-4 py-3.5 text-[14px] font-medium text-[var(--text-primary)]">
          {log.connector_name}
        </td>
        <td className="px-4 py-3.5 text-[14px] text-[var(--text-secondary)]">{log.action}</td>
        <td className="px-4 py-3.5">
          <code className="text-[12px] px-2 py-1 rounded-[6px] bg-[var(--bg-tertiary)] text-[var(--text-muted)] font-mono">
            {log.scope}
          </code>
        </td>
        <td className="px-4 py-3.5">
          <span
            className="inline-flex items-center gap-1.5 text-[12px] font-semibold px-2.5 py-1 rounded-full"
            style={{
              backgroundColor: `color-mix(in srgb, ${cfg.color} 18%, transparent)`,
              color: cfg.color,
            }}
          >
            <StatusIcon className="w-3.5 h-3.5" strokeWidth={2.5} /> {cfg.label}
          </span>
        </td>
        <td className="px-4 py-3.5">
          {log.integrity_valid ? (
            <ShieldCheck
              className="w-[18px] h-[18px] text-[var(--accent-success)]"
              strokeWidth={2}
              aria-label="Integrity verified"
            />
          ) : (
            <ShieldAlert
              className="w-[18px] h-[18px] text-[var(--accent-danger)]"
              strokeWidth={2}
              aria-label="Integrity broken"
            />
          )}
        </td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={7} className="px-5 py-5 bg-[var(--bg-tertiary)]">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-5 max-w-4xl">
              <div>
                <h4 className="text-[11px] font-semibold uppercase tracking-wide text-[var(--text-muted)] mb-2">
                  Reasoning Chain
                </h4>
                <p className="text-[14px] text-[var(--text-primary)] leading-relaxed">
                  {log.reasoning}
                </p>
                {log.request_data && (
                  <div className="mt-4">
                    <h4 className="text-[11px] font-semibold uppercase tracking-wide text-[var(--text-muted)] mb-1">
                      Params
                    </h4>
                    <pre className="text-[12px] text-[var(--text-muted)] font-mono p-2 rounded-[6px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)] overflow-x-auto">
                      {JSON.stringify(log.request_data, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
              <div className="space-y-4">
                <div>
                  <h4 className="text-[11px] font-semibold uppercase tracking-wide text-[var(--text-muted)] mb-1">
                    Endpoint
                  </h4>
                  <code className="text-[13px] text-[var(--accent-primary)] font-mono">
                    {log.endpoint}
                  </code>
                </div>
                {log.detection_method && (
                  <div>
                    <h4 className="text-[11px] font-semibold uppercase tracking-wide text-[var(--text-muted)] mb-1">
                      Detection
                    </h4>
                    <span className="text-[14px] text-[var(--text-primary)]">
                      {log.detection_method}
                      {log.confidence_score !== undefined && (
                        <span className="text-[var(--text-muted)]">
                          {" "}
                          ({(log.confidence_score * 100).toFixed(0)}% confidence)
                        </span>
                      )}
                    </span>
                  </div>
                )}
                <div>
                  <h4 className="text-[11px] font-semibold uppercase tracking-wide text-[var(--text-muted)] mb-1">
                    Integrity
                  </h4>
                  <div className="flex items-center gap-2">
                    <Hash className="w-3.5 h-3.5 text-[var(--text-muted)]" />
                    <code className="text-[12px] truncate text-[var(--text-muted)] font-mono">
                      {log.integrity_hash}
                    </code>
                  </div>
                </div>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

export default function AuditLogs() {
  const [searchParams, setSearchParams] = useSearchParams();

  const statusFilter = searchParams.get("status") ?? "all";
  const actionFilter = searchParams.get("action") ?? "";
  const fromTs = searchParams.get("from_ts") ?? "";
  const toTs = searchParams.get("to_ts") ?? "";
  const offset = Number(searchParams.get("offset") ?? "0");
  const [searchQuery, setSearchQuery] = useState(actionFilter);
  const debouncedSearch = useDebounced(searchQuery, 300);

  // Sync debounced search back into URL params for shareable links.
  useEffect(() => {
    if (debouncedSearch === actionFilter) return;
    const next = new URLSearchParams(searchParams);
    if (debouncedSearch.trim()) next.set("action", debouncedSearch.trim());
    else next.delete("action");
    next.set("offset", "0");
    setSearchParams(next, { replace: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debouncedSearch]);

  const filters: AuditFilters = useMemo(() => {
    const f: AuditFilters = { limit: PAGE_SIZE, offset };
    if (statusFilter && statusFilter !== "all") f.status = statusFilter;
    if (debouncedSearch.trim()) f.action = debouncedSearch.trim();
    if (fromTs) f.from_ts = fromTs;
    if (toTs) f.to_ts = toTs;
    return f;
  }, [statusFilter, debouncedSearch, fromTs, toTs, offset]);

  const logsQuery = useQuery({
    queryKey: ["audit-logs", filters],
    queryFn: () => getAuditLogs(filters) as Promise<AuditLog[]>,
  });

  const chainQuery = useQuery({
    queryKey: ["audit-chain"],
    queryFn: () => verifyAuditChain() as Promise<AuditChainResponse>,
  });

  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());
  const toggleExpanded = (id: string) =>
    setExpandedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const updateParam = (key: string, value: string) => {
    const next = new URLSearchParams(searchParams);
    if (value && value !== "all") next.set(key, value);
    else next.delete(key);
    next.set("offset", "0");
    setSearchParams(next, { replace: true });
  };

  const updateOffset = (newOffset: number) => {
    const next = new URLSearchParams(searchParams);
    next.set("offset", String(Math.max(0, newOffset)));
    setSearchParams(next, { replace: true });
  };

  const logs: AuditLog[] = logsQuery.data ?? [];
  const hasMore = logs.length === PAGE_SIZE;
  const selectStyle =
    "px-3.5 py-2.5 rounded-[12px] border border-[var(--border-primary)] bg-[var(--bg-input)] text-[14px] text-[var(--text-primary)] outline-none focus:border-[var(--accent-primary)] transition-colors";

  return (
    <div className="space-y-8 min-w-0">
      <header>
        <h1 className="text-[28px] font-semibold tracking-tight text-[var(--text-primary)] md:text-[32px]">
          Audit Logs
        </h1>
        <p className="text-[15px] text-[var(--text-secondary)] mt-1 max-w-lg leading-relaxed">
          Immutable, tamper-evident record of every agent action.
        </p>
      </header>

      {/* Chain integrity banner */}
      {chainQuery.isLoading ? (
        <Skeleton width="w-full" height="h-12" className="rounded-[12px]" />
      ) : chainQuery.isError ? (
        <ErrorBanner
          title="Couldn't verify audit chain"
          error={chainQuery.error}
          onRetry={() => chainQuery.refetch()}
          retrying={chainQuery.isFetching}
        />
      ) : chainQuery.data?.valid ? (
        <div
          role="status"
          className="flex items-center gap-2 rounded-[12px] border border-[rgba(48,209,88,0.3)] bg-[rgba(48,209,88,0.08)] px-4 py-3 text-[13px] text-[var(--accent-success)]"
        >
          <ShieldCheck className="w-4 h-4" strokeWidth={2.5} />
          Chain integrity: verified
        </div>
      ) : (
        <ErrorBanner
          title="Chain integrity broken"
          message={
            chainQuery.data?.broken_at
              ? `Chain broken at log #${chainQuery.data.broken_at}.`
              : chainQuery.data?.message ?? "Audit chain validation failed."
          }
        />
      )}

      {/* Filters */}
      <div
        className="flex flex-wrap items-end gap-3 p-4 rounded-[var(--radius-xl)] border border-[var(--border-subtle)]"
        style={{ backgroundColor: "var(--bg-secondary)", boxShadow: "var(--shadow-card)" }}
      >
        <div className="flex flex-col gap-1 flex-1 min-w-[200px]">
          <label
            htmlFor="audit-search"
            className="text-[11px] font-semibold uppercase tracking-wide text-[var(--text-muted)]"
          >
            Search action
          </label>
          <div className="relative">
            <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--text-muted)]" />
            <input
              id="audit-search"
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="get_assignments, send_email…"
              className="w-full pl-10 pr-4 py-2.5 rounded-[12px] border border-[var(--border-primary)] bg-[var(--bg-input)] text-[14px] text-[var(--text-primary)] outline-none placeholder:text-[var(--text-muted)] focus:border-[var(--accent-primary)] transition-colors"
            />
          </div>
        </div>
        <div className="flex flex-col gap-1">
          <label
            htmlFor="audit-status"
            className="text-[11px] font-semibold uppercase tracking-wide text-[var(--text-muted)]"
          >
            Status
          </label>
          <select
            id="audit-status"
            value={statusFilter}
            onChange={(e) => updateParam("status", e.target.value)}
            className={selectStyle}
          >
            <option value="all">All Statuses</option>
            <option value="approved">Approved</option>
            <option value="blocked">Blocked</option>
            <option value="pending">Pending</option>
            <option value="escalated">Escalated</option>
          </select>
        </div>
        <div className="flex flex-col gap-1">
          <label
            htmlFor="audit-from"
            className="text-[11px] font-semibold uppercase tracking-wide text-[var(--text-muted)]"
          >
            From
          </label>
          <input
            id="audit-from"
            type="datetime-local"
            value={fromTs}
            onChange={(e) => updateParam("from_ts", e.target.value)}
            className={selectStyle}
          />
        </div>
        <div className="flex flex-col gap-1">
          <label
            htmlFor="audit-to"
            className="text-[11px] font-semibold uppercase tracking-wide text-[var(--text-muted)]"
          >
            To
          </label>
          <input
            id="audit-to"
            type="datetime-local"
            value={toTs}
            onChange={(e) => updateParam("to_ts", e.target.value)}
            className={selectStyle}
          />
        </div>
      </div>

      {/* Table */}
      <div
        className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] overflow-hidden"
        style={{ backgroundColor: "var(--bg-secondary)", boxShadow: "var(--shadow-card)" }}
      >
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr
                style={{ borderBottom: "1px solid var(--border-subtle)" }}
                className="bg-[var(--bg-tertiary)]"
              >
                <th scope="col" className="px-4 py-3 text-left w-8" aria-label="Expand row" />
                <th
                  scope="col"
                  className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]"
                >
                  Timestamp
                </th>
                <th
                  scope="col"
                  className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]"
                >
                  Connector
                </th>
                <th
                  scope="col"
                  className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]"
                >
                  Action
                </th>
                <th
                  scope="col"
                  className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]"
                >
                  Scope
                </th>
                <th
                  scope="col"
                  className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]"
                >
                  Status
                </th>
                <th
                  scope="col"
                  className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]"
                >
                  Integrity
                </th>
              </tr>
            </thead>
            <tbody>
              {logsQuery.isLoading &&
                Array.from({ length: 6 }).map((_, i) => (
                  <tr key={i} style={{ borderBottom: "1px solid var(--border-subtle)" }}>
                    <td className="px-4 py-3.5">
                      <Skeleton width="w-4" height="h-4" />
                    </td>
                    <td className="px-4 py-3.5">
                      <Skeleton width="w-20" height="h-3" />
                    </td>
                    <td className="px-4 py-3.5">
                      <Skeleton width="w-24" height="h-3" />
                    </td>
                    <td className="px-4 py-3.5">
                      <Skeleton width="w-32" height="h-3" />
                    </td>
                    <td className="px-4 py-3.5">
                      <Skeleton width="w-16" height="h-3" />
                    </td>
                    <td className="px-4 py-3.5">
                      <Skeleton width="w-20" height="h-5" />
                    </td>
                    <td className="px-4 py-3.5">
                      <Skeleton width="w-5" height="h-5" />
                    </td>
                  </tr>
                ))}
              {logsQuery.isError && (
                <tr>
                  <td colSpan={7} className="px-4 py-6">
                    <ErrorBanner
                      title="Couldn't load audit logs"
                      error={logsQuery.error}
                      onRetry={() => logsQuery.refetch()}
                      retrying={logsQuery.isFetching}
                    />
                  </td>
                </tr>
              )}
              {!logsQuery.isLoading &&
                !logsQuery.isError &&
                logs.map((log) => (
                  <LogRow
                    key={log.id}
                    log={log}
                    expanded={expandedIds.has(log.id)}
                    onToggle={() => toggleExpanded(log.id)}
                  />
                ))}
              {!logsQuery.isLoading && !logsQuery.isError && logs.length === 0 && (
                <tr>
                  <td colSpan={7} className="px-4 py-12">
                    <EmptyState
                      icon={Search}
                      title="No audit logs match your filters"
                      description="Try clearing filters or widening the date range."
                    />
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {!logsQuery.isLoading && !logsQuery.isError && (logs.length > 0 || offset > 0) && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-[var(--border-subtle)]">
            <span className="text-[12px] text-[var(--text-muted)] font-mono tabular-nums">
              Showing {offset + 1}–{offset + logs.length}
            </span>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => updateOffset(offset - PAGE_SIZE)}
                disabled={offset === 0}
                className="inline-flex items-center gap-1 px-3 py-1.5 rounded-[8px] text-[12px] font-medium border border-[var(--border-primary)] text-[var(--text-secondary)] hover:bg-[rgba(255,255,255,0.06)] transition-colors disabled:opacity-40"
              >
                <ChevronLeft className="w-3.5 h-3.5" /> Prev
              </button>
              <button
                type="button"
                onClick={() => updateOffset(offset + PAGE_SIZE)}
                disabled={!hasMore}
                className="inline-flex items-center gap-1 px-3 py-1.5 rounded-[8px] text-[12px] font-medium border border-[var(--border-primary)] text-[var(--text-secondary)] hover:bg-[rgba(255,255,255,0.06)] transition-colors disabled:opacity-40"
              >
                Next <ChevronRightIcon className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
