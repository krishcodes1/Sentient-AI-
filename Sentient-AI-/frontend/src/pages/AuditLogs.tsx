/**
 * Audit logs page: a filterable, searchable table of agent actions with expandable rows that
 * verify each entry's integrity hash.
 *
 * Why it exists: This is the user-facing view of the tamper-evident audit trail; server-side
 * filters (connector, status, paging) and client-side ones (time range, search) meet here.
 */

import { useEffect, useId, useMemo, useState } from "react";
import {
  Search,
  CheckCircle2,
  XCircle,
  Clock,
  ChevronRight,
  ShieldCheck,
  ShieldAlert,
  Hash,
  Loader2,
  RefreshCw,
} from "lucide-react";
import type { AuditLog, AuditStatus } from "@/types";
import { getAuditLogs, getConnectors, verifyAuditLog } from "@/services/api";

const PAGE_SIZE = 100;

type StatusFilter = "all" | AuditStatus;
type ConnectorFilter = "all" | string;
type TimeRangeFilter = "all" | "24h" | "7d" | "30d";

// Fill and border are their own tokens rather than an alpha suffix on
// `color`: appending to a custom property produces `var(--accent-success)1f`,
// which is not a color, so the status chips rendered with no tint at all.
const statusConfig: Record<
  AuditStatus,
  { icon: typeof CheckCircle2; color: string; fill: string; border: string; label: string }
> = {
  approved: {
    icon: CheckCircle2,
    color: "var(--accent-success)",
    fill: "var(--fill-success)",
    border: "var(--border-success)",
    label: "Approved",
  },
  blocked: {
    icon: XCircle,
    color: "var(--accent-danger)",
    fill: "var(--fill-danger)",
    border: "var(--border-danger)",
    label: "Blocked",
  },
  pending: {
    icon: Clock,
    color: "var(--accent-warning)",
    fill: "var(--fill-warning)",
    border: "var(--border-warning)",
    label: "Pending",
  },
};

const timeRangeMs: Record<Exclude<TimeRangeFilter, "all">, number> = {
  "24h": 24 * 60 * 60 * 1000,
  "7d": 7 * 24 * 60 * 60 * 1000,
  "30d": 30 * 24 * 60 * 60 * 1000,
};

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

function renderReasoning(value: AuditLog["reasoning_chain"]): React.ReactNode {
  if (value == null || value === "") {
    return <span style={{ color: "var(--text-muted)" }}>No reasoning recorded.</span>;
  }
  if (typeof value === "string") {
    return <p className="text-sm" style={{ color: "var(--text-primary)" }}>{value}</p>;
  }
  if (Array.isArray(value)) {
    return (
      <ol className="text-sm list-decimal pl-5 space-y-1" style={{ color: "var(--text-primary)" }}>
        {value.map((step, i) => (
          <li key={i}>{typeof step === "string" ? step : JSON.stringify(step)}</li>
        ))}
      </ol>
    );
  }
  return (
    <dl className="text-xs grid grid-cols-[max-content_1fr] gap-x-3 gap-y-1" style={{ color: "var(--text-primary)" }}>
      {Object.entries(value).map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="font-semibold mono-tag" style={{ color: "var(--text-muted)" }}>{k}</dt>
          <dd className="break-words">{typeof v === "string" ? v : JSON.stringify(v)}</dd>
        </div>
      ))}
    </dl>
  );
}

function LogRow({ log }: { log: AuditLog }) {
  const [expanded, setExpanded] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [valid, setValid] = useState<boolean | null>(null);
  const [verifyError, setVerifyError] = useState<string | null>(null);
  const cfg = statusConfig[log.status];
  const StatusIcon = cfg.icon;
  const ts = new Date(log.timestamp);

  // Verification starts from the click that expands the row — the first
  // expand, or a later one after an attempt that failed — rather than from
  // an effect watching `expanded`. The effect version also re-fired every
  // time a failed attempt cleared `verifying`, retrying without end.
  const toggleExpanded = () => {
    const next = !expanded;
    setExpanded(next);
    if (!next || valid !== null || verifying) return;
    setVerifying(true);
    setVerifyError(null);
    verifyAuditLog(log.id)
      .then((res) => setValid(res.valid))
      .catch((err: Error) => setVerifyError(err.message))
      .finally(() => setVerifying(false));
  };

  return (
    <>
      <tr
        className="cursor-pointer transition-colors"
        style={{ borderBottom: "1px solid var(--border-subtle)" }}
        onClick={toggleExpanded}
        onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = "var(--claw-surface)")}
        onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = "transparent")}
      >
        <td className="px-2 py-3">
          {/* The row click is a convenience; this button is the one a
              keyboard or screen reader can actually reach. */}
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              toggleExpanded();
            }}
            aria-expanded={expanded}
            aria-label={`${expanded ? "Hide" : "Show"} details for ${log.action} on ${log.connector_name}`}
            className="inline-flex items-center justify-center rounded-[6px]"
            style={{ width: 36, height: 36, color: "var(--text-muted)" }}
          >
            <ChevronRight
              className={`w-4 h-4 transition-transform ${expanded ? "rotate-90" : ""}`}
              aria-hidden
            />
          </button>
        </td>
        <td className="px-4 py-3 text-xs mono-num">
          {ts.toLocaleTimeString()} <br />
          <span style={{ color: "var(--text-muted)" }}>{ts.toLocaleDateString()}</span>
        </td>
        <td className="px-4 py-3 text-sm font-medium" style={{ color: "var(--text-primary)" }}>
          {log.connector_name}
        </td>
        <td className="px-4 py-3 text-sm" style={{ color: "var(--text-secondary)" }}>
          {log.action}
        </td>
        <td className="px-4 py-3">
          <code
            className="mono-tag px-2 py-1 rounded-[6px]"
            style={{ background: "var(--claw-surface)", color: "var(--text-muted)" }}
          >
            {log.scope_used}
          </code>
        </td>
        <td className="px-4 py-3">
          <span
            className="mono-tag inline-flex items-center gap-1.5 px-2 py-1 rounded-[6px]"
            style={{ backgroundColor: cfg.fill, color: cfg.color, border: `1px solid ${cfg.border}` }}
          >
            <StatusIcon className="w-3 h-3" /> {cfg.label}
          </span>
        </td>
        <td className="px-4 py-3">
          {valid === null ? (
            <Hash className="w-4 h-4" style={{ color: "var(--text-muted)" }} />
          ) : valid ? (
            <ShieldCheck className="w-4 h-4" style={{ color: "var(--accent-success)" }} />
          ) : (
            <ShieldAlert className="w-4 h-4" style={{ color: "var(--accent-danger)" }} />
          )}
        </td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={7} className="px-5 py-5" style={{ background: "var(--claw-surface)" }}>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-5 max-w-4xl">
              <div>
                <div className="eyebrow mb-2">Reasoning chain</div>
                {renderReasoning(log.reasoning_chain)}
                {log.response_summary && (
                  <div className="mt-4">
                    <div className="eyebrow mb-1">Response summary</div>
                    <p className="text-xs" style={{ color: "var(--text-secondary)" }}>
                      {log.response_summary}
                    </p>
                  </div>
                )}
              </div>
              <div className="space-y-4">
                <div>
                  <div className="eyebrow mb-1">Endpoint</div>
                  <code className="text-xs break-all" style={{ color: "var(--accent-primary)" }}>
                    {log.endpoint}
                  </code>
                </div>
                {log.detection_method && (
                  <div>
                    <div className="eyebrow mb-1">Detection method</div>
                    <span className="text-sm" style={{ color: "var(--text-primary)" }}>
                      {log.detection_method}
                      {log.confidence_score != null && (
                        <span className="mono-num" style={{ color: "var(--text-muted)" }}>
                          {" "}({(log.confidence_score * 100).toFixed(0)}% confidence)
                        </span>
                      )}
                    </span>
                  </div>
                )}
                <div>
                  <div className="eyebrow mb-1">Request ID</div>
                  <code className="text-xs break-all" style={{ color: "var(--text-muted)" }}>
                    {log.request_id}
                  </code>
                </div>
                <div>
                  <div className="eyebrow mb-1">Integrity hash · SHA-256</div>
                  <div className="flex items-center gap-2">
                    <Hash className="w-3 h-3 shrink-0" style={{ color: "var(--text-muted)" }} />
                    <code className="text-xs break-all" style={{ color: "var(--text-muted)" }}>
                      {log.integrity_hash}
                    </code>
                  </div>
                  <div className="mt-2.5 text-xs">
                    {verifying && (
                      <span className="mono-tag inline-flex items-center gap-1.5" style={{ color: "var(--text-muted)" }}>
                        <Loader2 className="w-3 h-3 animate-spin" />
                        Verifying chain...
                      </span>
                    )}
                    {!verifying && valid === true && (
                      <span
                        className="mono-tag inline-flex items-center gap-1.5 px-2 py-1 rounded-[6px]"
                        style={{
                          background: "var(--fill-success)",
                          color: "var(--accent-success)",
                          border: "1px solid var(--border-success)",
                        }}
                      >
                        <ShieldCheck className="w-3 h-3" />
                        Integrity verified
                      </span>
                    )}
                    {!verifying && valid === false && (
                      <span
                        className="mono-tag inline-flex items-center gap-1.5 px-2 py-1 rounded-[6px]"
                        style={{
                          background: "var(--fill-danger)",
                          color: "var(--accent-danger)",
                          border: "1px solid var(--border-danger)",
                        }}
                      >
                        <ShieldAlert className="w-3 h-3" />
                        TAMPER DETECTED · hash does not match stored payload
                      </span>
                    )}
                    {!verifying && verifyError && (
                      <span style={{ color: "var(--accent-danger)" }}>
                        Could not verify: {verifyError}
                      </span>
                    )}
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
  const ids = {
    search: useId(),
    connector: useId(),
    status: useId(),
    range: useId(),
  };
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [hasMore, setHasMore] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [connectorFilter, setConnectorFilter] = useState<ConnectorFilter>("all");
  const [timeRange, setTimeRange] = useState<TimeRangeFilter>("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [refreshKey, setRefreshKey] = useState(0);
  const [connectorNames, setConnectorNames] = useState<string[]>([]);
  // The time-range window is anchored to when rows arrived or the range was
  // picked. Reading the clock inside the render-time filter would make it
  // impure (a different answer for the same inputs).
  const [now, setNow] = useState(() => Date.now());

  // Every change that re-runs the fetch effect below comes through one of
  // these handlers, so the loading state flips in the same event rather than
  // in an extra render the effect would trigger.
  const beginReload = () => {
    setLoading(true);
    setError(null);
  };
  const changeConnectorFilter = (value: ConnectorFilter) => {
    setConnectorFilter(value);
    beginReload();
  };
  const changeStatusFilter = (value: StatusFilter) => {
    setStatusFilter(value);
    beginReload();
  };
  const refresh = () => {
    setRefreshKey((k) => k + 1);
    beginReload();
  };
  const changeTimeRange = (value: TimeRangeFilter) => {
    setTimeRange(value);
    setNow(Date.now());
  };

  // The filter dropdown lists every configured connector, not just the ones
  // present in the currently loaded (already-filtered) page of logs.
  //
  // Audit rows store connector_name as the TOOL-NAME PREFIX ("canvas",
  // "google_workspace", "mcp", "agent"), never the user's display name —
  // filtering by display_name matched zero rows for any renamed connector.
  // So the dropdown's values are connector types; display names appear only
  // in the label.
  useEffect(() => {
    let cancelled = false;
    getConnectors()
      .then((data) => {
        if (!cancelled) {
          setConnectorNames(
            Array.from(new Set(data.map((c) => String(c.connector_type)))),
          );
        }
      })
      .catch(() => {
        // Fall back to the names visible in the loaded logs.
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    getAuditLogs({
      connector_name: connectorFilter === "all" ? undefined : connectorFilter,
      status: statusFilter === "all" ? undefined : statusFilter,
      limit: PAGE_SIZE,
    })
      .then((data) => {
        if (cancelled) return;
        setLogs(data);
        setHasMore(data.length === PAGE_SIZE);
        setNow(Date.now());
      })
      .catch((err: Error) => {
        if (!cancelled) setError(err.message);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [connectorFilter, statusFilter, refreshKey]);

  const loadMore = async () => {
    if (loadingMore) return;
    setLoadingMore(true);
    try {
      const next = await getAuditLogs({
        connector_name: connectorFilter === "all" ? undefined : connectorFilter,
        status: statusFilter === "all" ? undefined : statusFilter,
        limit: PAGE_SIZE,
        offset: logs.length,
      });
      setLogs((prev) => [...prev, ...next]);
      setHasMore(next.length === PAGE_SIZE);
      setNow(Date.now());
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoadingMore(false);
    }
  };

  const availableConnectors = useMemo(() => {
    // Union of configured connectors and names seen in the logs, so system
    // entries (or connectors deleted since) remain filterable, and the
    // current selection never vanishes from the dropdown.
    const set = new Set<string>(connectorNames);
    for (const l of logs) set.add(l.connector_name);
    if (connectorFilter !== "all") set.add(connectorFilter);
    return Array.from(set).sort();
  }, [connectorNames, logs, connectorFilter]);

  const filtered = useMemo(() => {
    const cutoff = timeRange === "all" ? 0 : now - timeRangeMs[timeRange];
    const q = searchQuery.trim().toLowerCase();
    return logs.filter((log) => {
      if (cutoff && new Date(log.timestamp).getTime() < cutoff) return false;
      if (!q) return true;
      const haystack = [
        log.connector_name,
        log.action,
        log.endpoint,
        log.scope_used,
        log.integrity_hash,
        log.request_id,
        typeof log.reasoning_chain === "string" ? log.reasoning_chain : JSON.stringify(log.reasoning_chain ?? ""),
      ]
        .join(" ")
        .toLowerCase();
      return haystack.includes(q);
    });
  }, [logs, timeRange, searchQuery, now]);

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-4">
        <div>
          <div className="eyebrow mb-2">Audit trail</div>
          <h1 style={{ color: "var(--text-primary)" }}>Audit logs</h1>
          <p className="text-sm mt-1.5 max-w-2xl" style={{ color: "var(--text-secondary)" }}>
            Immutable, tamper-evident record of every agent action. Expand any row
            to verify its SHA-256 hash against the chain.
          </p>
        </div>
        <button
          type="button"
          onClick={refresh}
          disabled={loading}
          className="inline-flex items-center justify-center gap-2 px-3.5 rounded-[10px] text-sm font-medium disabled:opacity-50 transition-colors shrink-0 self-start"
          style={{ ...inputStyle, minHeight: 44 }}
        >
          <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} aria-hidden />
          Refresh
        </button>
      </div>

      <div
        className="flex flex-wrap items-center gap-3 p-4 rounded-[14px]"
        style={panelStyle}
      >
        <div className="relative flex-1 basis-full sm:basis-auto min-w-[200px]">
          <label htmlFor={ids.search} className="sr-only">
            Search audit logs
          </label>
          <Search
            className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 pointer-events-none"
            style={{ color: "var(--text-muted)" }}
            aria-hidden
          />
          <input
            id={ids.search}
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search by action, endpoint, hash, reasoning..."
            className="w-full pl-10 pr-4 py-2.5 rounded-[10px] text-sm outline-none"
            style={inputStyle}
          />
        </div>

        <label htmlFor={ids.connector} className="sr-only">
          Filter by connector
        </label>
        <select
          id={ids.connector}
          value={connectorFilter}
          onChange={(e) => changeConnectorFilter(e.target.value)}
          className="flex-1 sm:flex-none px-3.5 py-2.5 rounded-[10px] text-sm outline-none"
          style={inputStyle}
        >
          <option value="all">All Connectors</option>
          {availableConnectors.map((name) => (
            <option key={name} value={name}>
              {name}
            </option>
          ))}
        </select>

        <label htmlFor={ids.status} className="sr-only">
          Filter by status
        </label>
        <select
          id={ids.status}
          value={statusFilter}
          onChange={(e) => changeStatusFilter(e.target.value as StatusFilter)}
          className="flex-1 sm:flex-none px-3.5 py-2.5 rounded-[10px] text-sm outline-none"
          style={inputStyle}
        >
          <option value="all">All Statuses</option>
          <option value="approved">Approved</option>
          <option value="blocked">Blocked</option>
          <option value="pending">Pending</option>
        </select>

        <label htmlFor={ids.range} className="sr-only">
          Filter by time range
        </label>
        <select
          id={ids.range}
          value={timeRange}
          onChange={(e) => changeTimeRange(e.target.value as TimeRangeFilter)}
          className="flex-1 sm:flex-none px-3.5 py-2.5 rounded-[10px] text-sm outline-none"
          style={inputStyle}
        >
          <option value="all">All Time</option>
          <option value="24h">Last 24 hours</option>
          <option value="7d">Last 7 days</option>
          <option value="30d">Last 30 days</option>
        </select>
      </div>

      <div className="rounded-[14px] overflow-hidden" style={panelStyle}>
        <div className="px-5 pt-4 pb-3">
          <div className="eyebrow">Action log</div>
        </div>
        {/* Seven columns do not fit a phone. The panel scrolls sideways
            rather than the page, and the columns keep their widths instead
            of collapsing into unreadable slivers. */}
        <div className="overflow-x-auto">
          <table className="w-full min-w-[760px]">
            <caption className="sr-only">
              Agent actions, newest first. Expand a row for its reasoning
              chain and integrity hash.
            </caption>
            <thead>
              <tr
                style={{
                  borderTop: "1px solid var(--border-subtle)",
                  borderBottom: "1px solid var(--border-subtle)",
                  background: "var(--claw-surface)",
                }}
              >
                <th className="px-2 py-2.5 text-left w-10">
                  <span className="sr-only">Expand</span>
                </th>
                <th className="px-4 py-2.5 text-left eyebrow">Timestamp</th>
                <th className="px-4 py-2.5 text-left eyebrow">Connector</th>
                <th className="px-4 py-2.5 text-left eyebrow">Action</th>
                <th className="px-4 py-2.5 text-left eyebrow">Scope</th>
                <th className="px-4 py-2.5 text-left eyebrow">Status</th>
                <th className="px-4 py-2.5 text-left eyebrow">Integrity</th>
              </tr>
            </thead>
            <tbody>
              {loading && (
                <tr>
                  <td colSpan={7} className="px-4 py-10 text-center text-sm" style={{ color: "var(--text-muted)" }}>
                    <span role="status" className="inline-flex items-center gap-2">
                      <Loader2 className="w-4 h-4 animate-spin" aria-hidden />
                      Loading audit logs...
                    </span>
                  </td>
                </tr>
              )}
              {!loading && error && (
                <tr>
                  <td colSpan={7} className="px-4 py-10 text-center text-sm" style={{ color: "var(--accent-danger)" }}>
                    {error}
                  </td>
                </tr>
              )}
              {!loading && !error && filtered.map((log) => <LogRow key={log.id} log={log} />)}
              {!loading && !error && filtered.length === 0 && (
                <tr>
                  <td colSpan={7} className="px-4 py-10 text-center text-sm" style={{ color: "var(--text-muted)" }}>
                    {logs.length === 0
                      ? "No audit log entries yet. Agent actions will appear here once recorded."
                      : "No audit logs match your filters."}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        {!loading && !error && hasMore && (
          <div
            className="flex justify-center px-5 py-3"
            style={{ borderTop: "1px solid var(--border-subtle)" }}
          >
            <button
              type="button"
              onClick={() => void loadMore()}
              disabled={loadingMore}
              className="inline-flex items-center gap-2 px-4 rounded-[10px] text-sm font-medium disabled:opacity-50"
              style={{ ...inputStyle, minHeight: 44 }}
            >
              {loadingMore ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : null}
              {loadingMore ? "Loading..." : `Load ${PAGE_SIZE} more`}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
