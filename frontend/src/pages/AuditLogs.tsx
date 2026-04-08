import { useState } from "react";
import {
  Search,
  CheckCircle2,
  XCircle,
  Clock,
  ChevronRight,
  ShieldCheck,
  ShieldAlert,
  Hash,
} from "lucide-react";
import type { AuditLog } from "@/types";

const mockLogs: AuditLog[] = [
  {
    id: "1", connector_id: "1", connector_name: "Canvas LMS", action: "get_assignments",
    endpoint: "GET /api/v1/courses/123/assignments", scope: "assignments.read", status: "approved",
    decision_method: "auto",
    reasoning: "Read-only Canvas action is auto-approved by default policy. No prompt injection detected in request content.",
    integrity_hash: "a3f2b8c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1",
    integrity_valid: true, timestamp: "2026-04-06T14:32:15Z", user_id: "u1",
  },
  {
    id: "2", connector_id: "2", connector_name: "Gmail", action: "send_email",
    endpoint: "POST /gmail/v1/users/me/messages/send", scope: "gmail.send", status: "approved",
    decision_method: "user",
    reasoning: "Email send action requires user confirmation. User approved the draft email to professor@nyit.edu regarding assignment extension request.",
    integrity_hash: "b4c3d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4",
    integrity_valid: true, timestamp: "2026-04-06T14:28:00Z", user_id: "u1",
  },
  {
    id: "3", connector_id: "3", connector_name: "Robinhood", action: "execute_trade",
    endpoint: "POST /api/crypto/orders", scope: "crypto.trade", status: "blocked",
    decision_method: "policy",
    reasoning: "Financial transaction permanently blocked by platform security policy. Trade execution is unconditionally prohibited regardless of user configuration.",
    detection_method: "hard_block_policy", confidence_score: 1.0,
    integrity_hash: "c5d4e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5",
    integrity_valid: true, timestamp: "2026-04-06T14:15:30Z", user_id: "u1",
  },
  {
    id: "4", connector_id: "1", connector_name: "Canvas LMS", action: "get_grades",
    endpoint: "GET /api/v1/courses/123/enrollments", scope: "grades.read", status: "approved",
    decision_method: "auto",
    reasoning: "Read-only grade access auto-approved. Content sanitization applied to response. No injection patterns detected.",
    integrity_hash: "d6e5f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6",
    integrity_valid: true, timestamp: "2026-04-06T14:10:00Z", user_id: "u1",
  },
  {
    id: "5", connector_id: "2", connector_name: "Gmail", action: "read_message",
    endpoint: "GET /gmail/v1/users/me/messages/abc123", scope: "gmail.readonly", status: "approved",
    decision_method: "auto",
    reasoning: "Read-only Gmail access auto-approved. Prompt injection scan detected and sanitized 2 suspicious patterns in email body before LLM processing.",
    detection_method: "prompt_guard_sanitized", confidence_score: 0.72,
    request_data: { message_id: "abc123", sanitized_patterns: 2 },
    integrity_hash: "e7f6a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7",
    integrity_valid: true, timestamp: "2026-04-06T14:05:00Z", user_id: "u1",
  },
];

const statusConfig = {
  approved: { icon: CheckCircle2, color: "var(--accent-success)", label: "Approved" },
  blocked: { icon: XCircle, color: "var(--accent-danger)", label: "Blocked" },
  pending: { icon: Clock, color: "var(--accent-warning)", label: "Pending" },
  escalated: { icon: ShieldAlert, color: "var(--accent-warning)", label: "Escalated" },
};

function LogRow({ log }: { log: AuditLog }) {
  const [expanded, setExpanded] = useState(false);
  const cfg = statusConfig[log.status];
  const StatusIcon = cfg.icon;
  const ts = new Date(log.timestamp);

  return (
    <>
      <tr
        className="cursor-pointer transition-colors hover:bg-[rgba(255,255,255,0.04)]"
        style={{ borderBottom: "1px solid var(--border-subtle)" }}
        onClick={() => setExpanded(!expanded)}
      >
        <td className="px-4 py-3.5">
          <ChevronRight
            className={`w-4 h-4 transition-transform text-[var(--text-muted)] ${expanded ? "rotate-90" : ""}`}
          />
        </td>
        <td className="px-4 py-3.5 text-[12px] text-[var(--text-secondary)] tabular-nums">
          {ts.toLocaleTimeString()} <br />
          <span className="text-[var(--text-muted)]">{ts.toLocaleDateString()}</span>
        </td>
        <td className="px-4 py-3.5 text-[14px] font-medium text-[var(--text-primary)]">
          {log.connector_name}
        </td>
        <td className="px-4 py-3.5 text-[14px] text-[var(--text-secondary)]">
          {log.action}
        </td>
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
            <ShieldCheck className="w-[18px] h-[18px] text-[var(--accent-success)]" strokeWidth={2} />
          ) : (
            <ShieldAlert className="w-[18px] h-[18px] text-[var(--accent-danger)]" strokeWidth={2} />
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
              </div>
              <div className="space-y-4">
                <div>
                  <h4 className="text-[11px] font-semibold uppercase tracking-wide text-[var(--text-muted)] mb-1">
                    Endpoint
                  </h4>
                  <code className="text-[13px] text-[var(--accent-primary)] font-mono">{log.endpoint}</code>
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
                          {" "}({(log.confidence_score * 100).toFixed(0)}% confidence)
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
  const [statusFilter, setStatusFilter] = useState("all");
  const [connectorFilter, setConnectorFilter] = useState("all");
  const [searchQuery, setSearchQuery] = useState("");

  const filtered = mockLogs.filter((log) => {
    if (statusFilter !== "all" && log.status !== statusFilter) return false;
    if (connectorFilter !== "all" && log.connector_name !== connectorFilter) return false;
    if (searchQuery && !JSON.stringify(log).toLowerCase().includes(searchQuery.toLowerCase())) return false;
    return true;
  });

  const selectStyle = "px-3.5 py-2.5 rounded-[12px] border border-[var(--border-primary)] bg-[var(--bg-input)] text-[14px] text-[var(--text-primary)] outline-none focus:border-[var(--accent-primary)] transition-colors";

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

      {/* Filters */}
      <div
        className="flex flex-wrap items-center gap-3 p-4 rounded-[var(--radius-xl)] border border-[var(--border-subtle)]"
        style={{ backgroundColor: "var(--bg-secondary)", boxShadow: "var(--shadow-card)" }}
      >
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--text-muted)]" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search audit logs..."
            className="w-full pl-10 pr-4 py-2.5 rounded-[12px] border border-[var(--border-primary)] bg-[var(--bg-input)] text-[14px] text-[var(--text-primary)] outline-none placeholder:text-[var(--text-muted)] focus:border-[var(--accent-primary)] transition-colors"
          />
        </div>
        <select
          value={connectorFilter}
          onChange={(e) => setConnectorFilter(e.target.value)}
          className={selectStyle}
        >
          <option value="all">All Connectors</option>
          <option value="Canvas LMS">Canvas LMS</option>
          <option value="Gmail">Gmail</option>
          <option value="Robinhood">Robinhood</option>
        </select>
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className={selectStyle}
        >
          <option value="all">All Statuses</option>
          <option value="approved">Approved</option>
          <option value="blocked">Blocked</option>
          <option value="pending">Pending</option>
        </select>
      </div>

      {/* Table */}
      <div
        className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] overflow-hidden"
        style={{ backgroundColor: "var(--bg-secondary)", boxShadow: "var(--shadow-card)" }}
      >
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr style={{ borderBottom: "1px solid var(--border-subtle)" }} className="bg-[var(--bg-tertiary)]">
                <th className="px-4 py-3 text-left w-8" />
                <th className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">
                  Timestamp
                </th>
                <th className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">
                  Connector
                </th>
                <th className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">
                  Action
                </th>
                <th className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">
                  Scope
                </th>
                <th className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">
                  Status
                </th>
                <th className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">
                  Integrity
                </th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((log) => (
                <LogRow key={log.id} log={log} />
              ))}
              {filtered.length === 0 && (
                <tr>
                  <td colSpan={7} className="px-4 py-12 text-center text-[14px] text-[var(--text-muted)]">
                    No audit logs match your filters
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
