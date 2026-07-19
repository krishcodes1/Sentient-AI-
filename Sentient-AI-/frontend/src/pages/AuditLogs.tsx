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
  Loader2,
  RefreshCw,
} from "lucide-react";
import type { AuditLog, AuditStatus } from "@/types";
import { getAuditLogs, getConnectors, verifyAuditLog } from "@/services/api";

const PAGE_SIZE = 100;

type StatusFilter = "all" | AuditStatus;
type ConnectorFilter = "all" | string;
type TimeRangeFilter = "all" | "24h" | "7d" | "30d";

const statusConfig: Record<AuditStatus, { icon: typeof CheckCircle2; color: string; label: string }> = {
  approved: { icon: CheckCircle2, color: "var(--accent-success)", label: "Approved" },
  blocked: { icon: XCircle, color: "var(--accent-danger)", label: "Blocked" },
  pending: { icon: Clock, color: "var(--accent-warning)", label: "Pending" },
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

  useEffect(() => {
    if (!expanded || valid !== null || verifying) return;
    setVerifying(true);
    setVerifyError(null);
    verifyAuditLog(log.id)
      .then((res) => setValid(res.valid))
      .catch((err: Error) => setVerifyError(err.message))
      .finally(() => setVerifying(false));
  }, [expanded, log.id, valid, verifying]);

  return (
    <>
      <tr
        className="cursor-pointer transition-colors"
        style={{ borderBottom: "1px solid var(--border-subtle)" }}
        onClick={() => setExpanded(!expanded)}
        onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = "var(--claw-surface)")}
        onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = "transparent")}
      >
        <td className="px-4 py-3">
          <ChevronRight
            className={`w-4 h-4 transition-transform ${expanded ? "rotate-90" : ""}`}
            style={{ color: "var(--text-muted)" }}
          />
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
            style={{ backgroundColor: `${cfg.color}1f`, color: cfg.color, border: `1px solid ${cfg.color}40` }}
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

  // The filter dropdown lists every configured connector, not just the ones
  // present in the currently loaded (already-filtered) page of logs.
  useEffect(() => {
    let cancelled = false;
    getConnectors()
      .then((data) => {
        if (!cancelled) setConnectorNames(data.map((c) => c.display_name));
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
    setLoading(true);
    setError(null);
    getAuditLogs({
      connector_name: connectorFilter === "all" ? undefined : connectorFilter,
      status: statusFilter === "all" ? undefined : statusFilter,
      limit: PAGE_SIZE,
    })
      .then((data) => {
        if (cancelled) return;
        setLogs(data);
        setHasMore(data.length === PAGE_SIZE);
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
    const now = Date.now();
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
  }, [logs, timeRange, searchQuery]);

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4">
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
          onClick={() => setRefreshKey((k) => k + 1)}
          disabled={loading}
          className="inline-flex items-center gap-2 px-3.5 py-2 rounded-[10px] text-sm font-medium disabled:opacity-50 transition-colors shrink-0"
          style={inputStyle}
        >
          <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </button>
      </div>

      <div
        className="flex flex-wrap items-center gap-3 p-4 rounded-[14px]"
        style={panelStyle}
      >
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4" style={{ color: "var(--text-muted)" }} />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search by action, endpoint, hash, reasoning..."
            className="w-full pl-10 pr-4 py-2.5 rounded-[10px] text-sm outline-none"
            style={inputStyle}
          />
        </div>

        <select
          value={connectorFilter}
          onChange={(e) => setConnectorFilter(e.target.value)}
          className="px-3.5 py-2.5 rounded-[10px] text-sm outline-none"
          style={inputStyle}
        >
          <option value="all">All Connectors</option>
          {availableConnectors.map((name) => (
            <option key={name} value={name}>
              {name}
            </option>
          ))}
        </select>

        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value as StatusFilter)}
          className="px-3.5 py-2.5 rounded-[10px] text-sm outline-none"
          style={inputStyle}
        >
          <option value="all">All Statuses</option>
          <option value="approved">Approved</option>
          <option value="blocked">Blocked</option>
          <option value="pending">Pending</option>
        </select>

        <select
          value={timeRange}
          onChange={(e) => setTimeRange(e.target.value as TimeRangeFilter)}
          className="px-3.5 py-2.5 rounded-[10px] text-sm outline-none"
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
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr
                style={{
                  borderTop: "1px solid var(--border-subtle)",
                  borderBottom: "1px solid var(--border-subtle)",
                  background: "var(--claw-surface)",
                }}
              >
                <th className="px-4 py-2.5 text-left w-8"></th>
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
                    <span className="inline-flex items-center gap-2">
                      <Loader2 className="w-4 h-4 animate-spin" />
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
              className="inline-flex items-center gap-2 px-4 py-2 rounded-[10px] text-sm font-medium disabled:opacity-50"
              style={inputStyle}
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
