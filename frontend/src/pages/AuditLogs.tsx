import { useState } from "react";
import {
  Search,
  Filter,
  CheckCircle2,
  XCircle,
  Clock,
  ChevronDown,
  ChevronRight,
  ShieldCheck,
  ShieldAlert,
  Hash,
} from "lucide-react";
import type { AuditLog } from "@/types";

const mockLogs: AuditLog[] = [
  {
    id: "1",
    connector_id: "1",
    connector_name: "Canvas LMS",
    action: "get_assignments",
    endpoint: "GET /api/v1/courses/123/assignments",
    scope: "assignments.read",
    status: "approved",
    decision_method: "auto",
    reasoning: "Read-only Canvas action is auto-approved by default policy. No prompt injection detected in request content.",
    integrity_hash: "a3f2b8c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1",
    integrity_valid: true,
    timestamp: "2026-04-06T14:32:15Z",
    user_id: "u1",
  },
  {
    id: "2",
    connector_id: "2",
    connector_name: "Gmail",
    action: "send_email",
    endpoint: "POST /gmail/v1/users/me/messages/send",
    scope: "gmail.send",
    status: "approved",
    decision_method: "user",
    reasoning: "Email send action requires user confirmation. User approved the draft email to professor@nyit.edu regarding assignment extension request.",
    integrity_hash: "b4c3d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4",
    integrity_valid: true,
    timestamp: "2026-04-06T14:28:00Z",
    user_id: "u1",
  },
  {
    id: "3",
    connector_id: "3",
    connector_name: "Robinhood",
    action: "execute_trade",
    endpoint: "POST /api/crypto/orders",
    scope: "crypto.trade",
    status: "blocked",
    decision_method: "policy",
    reasoning: "Financial transaction permanently blocked by platform security policy. Trade execution is unconditionally prohibited regardless of user configuration.",
    detection_method: "hard_block_policy",
    confidence_score: 1.0,
    integrity_hash: "c5d4e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5",
    integrity_valid: true,
    timestamp: "2026-04-06T14:15:30Z",
    user_id: "u1",
  },
  {
    id: "4",
    connector_id: "1",
    connector_name: "Canvas LMS",
    action: "get_grades",
    endpoint: "GET /api/v1/courses/123/enrollments",
    scope: "grades.read",
    status: "approved",
    decision_method: "auto",
    reasoning: "Read-only grade access auto-approved. Content sanitization applied to response. No injection patterns detected.",
    integrity_hash: "d6e5f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6",
    integrity_valid: true,
    timestamp: "2026-04-06T14:10:00Z",
    user_id: "u1",
  },
  {
    id: "5",
    connector_id: "2",
    connector_name: "Gmail",
    action: "read_message",
    endpoint: "GET /gmail/v1/users/me/messages/abc123",
    scope: "gmail.readonly",
    status: "approved",
    decision_method: "auto",
    reasoning: "Read-only Gmail access auto-approved. Prompt injection scan detected and sanitized 2 suspicious patterns in email body before LLM processing.",
    detection_method: "prompt_guard_sanitized",
    confidence_score: 0.72,
    request_data: { message_id: "abc123", sanitized_patterns: 2 },
    integrity_hash: "e7f6a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7",
    integrity_valid: true,
    timestamp: "2026-04-06T14:05:00Z",
    user_id: "u1",
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
        className="cursor-pointer transition-colors"
        style={{ borderBottom: "1px solid var(--border-primary)" }}
        onClick={() => setExpanded(!expanded)}
        onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = "var(--bg-hover)")}
        onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = "transparent")}
      >
        <td className="px-4 py-3">
          <ChevronRight
            className={`w-4 h-4 transition-transform ${expanded ? "rotate-90" : ""}`}
            style={{ color: "var(--text-muted)" }}
          />
        </td>
        <td className="px-4 py-3 text-xs" style={{ color: "var(--text-secondary)" }}>
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
          <code className="text-xs px-1.5 py-0.5 rounded" style={{ backgroundColor: "var(--bg-primary)", color: "var(--text-muted)" }}>
            {log.scope}
          </code>
        </td>
        <td className="px-4 py-3">
          <span
            className="inline-flex items-center gap-1 text-xs font-medium px-2 py-0.5 rounded-full"
            style={{ backgroundColor: `${cfg.color}15`, color: cfg.color }}
          >
            <StatusIcon className="w-3 h-3" /> {cfg.label}
          </span>
        </td>
        <td className="px-4 py-3">
          {log.integrity_valid ? (
            <ShieldCheck className="w-4 h-4" style={{ color: "var(--accent-success)" }} />
          ) : (
            <ShieldAlert className="w-4 h-4" style={{ color: "var(--accent-danger)" }} />
          )}
        </td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={7} className="px-4 py-4" style={{ backgroundColor: "var(--bg-primary)" }}>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <h4 className="text-xs font-semibold mb-2" style={{ color: "var(--text-secondary)" }}>
                  Reasoning Chain
                </h4>
                <p className="text-sm" style={{ color: "var(--text-primary)" }}>
                  {log.reasoning}
                </p>
              </div>
              <div className="space-y-3">
                <div>
                  <h4 className="text-xs font-semibold mb-1" style={{ color: "var(--text-secondary)" }}>
                    Endpoint
                  </h4>
                  <code className="text-xs" style={{ color: "var(--accent-primary)" }}>
                    {log.endpoint}
                  </code>
                </div>
                {log.detection_method && (
                  <div>
                    <h4 className="text-xs font-semibold mb-1" style={{ color: "var(--text-secondary)" }}>
                      Detection Method
                    </h4>
                    <span className="text-sm" style={{ color: "var(--text-primary)" }}>
                      {log.detection_method}
                      {log.confidence_score !== undefined && (
                        <span style={{ color: "var(--text-muted)" }}>
                          {" "}(confidence: {(log.confidence_score * 100).toFixed(0)}%)
                        </span>
                      )}
                    </span>
                  </div>
                )}
                <div>
                  <h4 className="text-xs font-semibold mb-1" style={{ color: "var(--text-secondary)" }}>
                    Integrity Hash
                  </h4>
                  <div className="flex items-center gap-2">
                    <Hash className="w-3 h-3" style={{ color: "var(--text-muted)" }} />
                    <code className="text-xs truncate" style={{ color: "var(--text-muted)" }}>
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

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold" style={{ color: "var(--text-primary)" }}>
          Audit Logs
        </h1>
        <p className="text-sm mt-1" style={{ color: "var(--text-secondary)" }}>
          Immutable, tamper-evident record of every agent action
        </p>
      </div>

      {/* Filters */}
      <div
        className="flex flex-wrap items-center gap-3 p-4 rounded-xl border"
        style={{
          backgroundColor: "var(--bg-secondary)",
          borderColor: "var(--border-primary)",
        }}
      >
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4" style={{ color: "var(--text-muted)" }} />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search audit logs..."
            className="w-full pl-10 pr-4 py-2 rounded-lg border text-sm outline-none"
            style={{
              backgroundColor: "var(--bg-input)",
              borderColor: "var(--border-primary)",
              color: "var(--text-primary)",
            }}
          />
        </div>

        <select
          value={connectorFilter}
          onChange={(e) => setConnectorFilter(e.target.value)}
          className="px-3 py-2 rounded-lg border text-sm outline-none"
          style={{
            backgroundColor: "var(--bg-input)",
            borderColor: "var(--border-primary)",
            color: "var(--text-primary)",
          }}
        >
          <option value="all">All Connectors</option>
          <option value="Canvas LMS">Canvas LMS</option>
          <option value="Gmail">Gmail</option>
          <option value="Robinhood">Robinhood</option>
        </select>

        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="px-3 py-2 rounded-lg border text-sm outline-none"
          style={{
            backgroundColor: "var(--bg-input)",
            borderColor: "var(--border-primary)",
            color: "var(--text-primary)",
          }}
        >
          <option value="all">All Statuses</option>
          <option value="approved">Approved</option>
          <option value="blocked">Blocked</option>
          <option value="pending">Pending</option>
        </select>
      </div>

      {/* Table */}
      <div
        className="rounded-xl border overflow-hidden"
        style={{
          backgroundColor: "var(--bg-secondary)",
          borderColor: "var(--border-primary)",
        }}
      >
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr style={{ borderBottom: "1px solid var(--border-primary)" }}>
                <th className="px-4 py-3 text-left w-8"></th>
                <th className="px-4 py-3 text-left text-xs font-semibold" style={{ color: "var(--text-muted)" }}>
                  Timestamp
                </th>
                <th className="px-4 py-3 text-left text-xs font-semibold" style={{ color: "var(--text-muted)" }}>
                  Connector
                </th>
                <th className="px-4 py-3 text-left text-xs font-semibold" style={{ color: "var(--text-muted)" }}>
                  Action
                </th>
                <th className="px-4 py-3 text-left text-xs font-semibold" style={{ color: "var(--text-muted)" }}>
                  Scope
                </th>
                <th className="px-4 py-3 text-left text-xs font-semibold" style={{ color: "var(--text-muted)" }}>
                  Status
                </th>
                <th className="px-4 py-3 text-left text-xs font-semibold" style={{ color: "var(--text-muted)" }}>
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
                  <td colSpan={7} className="px-4 py-8 text-center text-sm" style={{ color: "var(--text-muted)" }}>
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
