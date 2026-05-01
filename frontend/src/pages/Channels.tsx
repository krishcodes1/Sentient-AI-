import { useEffect, useId, useRef, useState } from "react";
import {
  Plus,
  Check,
  X,
  RefreshCw,
  Loader2,
  Trash2,
  Send as SendIcon,
  MessageCircle,
  Hash,
  Radio,
  Globe,
  Wifi,
  WifiOff,
  Eye,
  EyeOff,
  AlertTriangle,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import clsx from "clsx";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type {
  ChannelResponse,
  ChannelType,
  CreateChannelData,
} from "@/types";
import {
  ApiError,
  createChannel,
  deleteChannel,
  getChannels,
  getOpenClawStatus,
  restartOpenClaw,
  updateChannel,
} from "@/services/api";
import { toast } from "@/hooks/useToast";
import { Skeleton } from "@/components/ui/Skeleton";
import { ErrorBanner } from "@/components/ui/ErrorBanner";
import { EmptyState } from "@/components/ui/EmptyState";

interface ChannelField {
  key: string;
  label: string;
  placeholder: string;
  required: boolean;
  type?: "text" | "password" | "textarea";
  helpText?: string;
  /** Optional regex (as RegExp) the field must match before submission. */
  pattern?: RegExp;
  /** Human-readable hint when validation fails. */
  patternMessage?: string;
}

interface ChannelTemplate {
  type: ChannelType;
  name: string;
  description: string;
  icon: LucideIcon;
  color: string;
  fields: ChannelField[];
}

// Channel-with-status (Round 2 backend additions). Defined locally so we
// don't depend on the foundation type definitions changing in lockstep.
interface ChannelWithStatus extends ChannelResponse {
  status?: "ok" | "error" | "pending" | "disconnected" | string;
  last_error?: string | null;
}

function getErrorMessage(err: unknown, fallback: string): string {
  if (err instanceof ApiError) return err.message;
  if (err instanceof Error) return err.message;
  if (typeof err === "string") return err;
  return fallback;
}

const TELEGRAM_TOKEN_RE = /^\d{8,12}:[A-Za-z0-9_-]{30,}$/;
const SLACK_BOT_RE = /^xoxb-[A-Za-z0-9-]{10,}$/;
const SLACK_APP_RE = /^xapp-[A-Za-z0-9-]{10,}$/;
const DISCORD_TOKEN_RE = /^[A-Za-z0-9_.-]{40,}$/;

const CHANNEL_TEMPLATES: ChannelTemplate[] = [
  {
    type: "telegram",
    name: "Telegram",
    description: "Connect a Telegram bot to chat via @BotFather",
    icon: SendIcon,
    color: "#0088cc",
    fields: [
      {
        key: "bot_token",
        label: "Bot Token",
        placeholder: "123456789:ABCdefGHIjklMNOpqrSTUvwxYZ012345678",
        required: true,
        type: "password",
        helpText: "Get this from @BotFather on Telegram",
        pattern: TELEGRAM_TOKEN_RE,
        patternMessage:
          "Telegram tokens look like 123456789:AAEhBP… (digits, colon, then 30+ chars).",
      },
    ],
  },
  {
    type: "discord",
    name: "Discord",
    description: "Add a Discord bot to your server",
    icon: Hash,
    color: "#5865F2",
    fields: [
      {
        key: "bot_token",
        label: "Bot Token",
        placeholder: "MTIzNDU2Nzg5.AbCdEf.GhIjKlMnOpQrStUvWxYz",
        required: true,
        type: "password",
        helpText: "From Discord Developer Portal > Bot > Token",
        pattern: DISCORD_TOKEN_RE,
        patternMessage: "Discord tokens are 40+ characters of letters, digits, dots and dashes.",
      },
    ],
  },
  {
    type: "slack",
    name: "Slack",
    description: "Connect to Slack workspaces via Bot + App tokens",
    icon: MessageCircle,
    color: "#4A154B",
    fields: [
      {
        key: "bot_token",
        label: "Bot Token",
        placeholder: "xoxb-...",
        required: true,
        type: "password",
        helpText: "OAuth Bot Token from Slack app settings",
        pattern: SLACK_BOT_RE,
        patternMessage: "Bot tokens start with xoxb-.",
      },
      {
        key: "app_token",
        label: "App Token",
        placeholder: "xapp-...",
        required: true,
        type: "password",
        helpText: "App-level token with connections:write scope",
        pattern: SLACK_APP_RE,
        patternMessage: "App tokens start with xapp-.",
      },
    ],
  },
  {
    type: "whatsapp",
    name: "WhatsApp",
    description: "Link your WhatsApp account via QR code scan",
    icon: MessageCircle,
    color: "#25D366",
    fields: [
      {
        key: "allow_from_text",
        label: "Allowed Phone Numbers",
        placeholder: "+15555550123, +15555550456",
        required: false,
        type: "text",
        helpText: "Comma-separated phone numbers that can message the bot",
      },
    ],
  },
  {
    type: "signal",
    name: "Signal",
    description: "Connect as a linked Signal device",
    icon: Radio,
    color: "#3A76F0",
    fields: [],
  },
  {
    type: "webchat",
    name: "WebChat",
    description: "Built-in web chat via OpenClaw gateway UI",
    icon: Globe,
    color: "#0a84ff",
    fields: [],
  },
];

// ─── Subcomponents ─────────────────────────────────────────────────────────

function GatewayStatus({
  online,
  channelsCount,
  onSync,
  syncing,
  loading,
}: {
  online: boolean;
  channelsCount: number;
  onSync: () => void;
  syncing: boolean;
  loading: boolean;
}) {
  return (
    <div
      className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] p-5"
      style={{ backgroundColor: "var(--bg-secondary)", boxShadow: "var(--shadow-card)" }}
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div
            className="w-11 h-11 rounded-[12px] flex items-center justify-center"
            style={{
              backgroundColor: online ? "rgba(48,209,88,0.15)" : "rgba(255,69,58,0.15)",
            }}
          >
            {online ? (
              <Wifi className="w-5 h-5" style={{ color: "var(--accent-success)" }} strokeWidth={1.75} />
            ) : (
              <WifiOff className="w-5 h-5" style={{ color: "var(--accent-danger)" }} strokeWidth={1.75} />
            )}
          </div>
          <div>
            <h3 className="text-[15px] font-semibold text-[var(--text-primary)]">OpenClaw Gateway</h3>
            <p className="text-[13px] text-[var(--text-muted)]">
              {loading ? (
                <Skeleton width="w-24" height="h-3" inline />
              ) : online ? (
                <span className="text-[var(--accent-success)]">Online</span>
              ) : (
                <span className="text-[var(--accent-danger)]">Offline</span>
              )}
              {" · "}
              {channelsCount} channel{channelsCount !== 1 ? "s" : ""} configured
            </p>
          </div>
        </div>
        <button
          type="button"
          onClick={onSync}
          disabled={syncing}
          className="flex items-center gap-2 px-4 py-2 rounded-[10px] text-[13px] font-semibold bg-[rgba(255,255,255,0.06)] border border-[var(--border-subtle)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[rgba(255,255,255,0.1)] transition-all disabled:opacity-50"
        >
          <RefreshCw className={clsx("w-3.5 h-3.5", syncing && "animate-spin")} strokeWidth={2} />
          Sync Config
        </button>
      </div>
    </div>
  );
}

function AddChannelModal({
  template,
  onClose,
  onSave,
  saving,
  serverError,
}: {
  template: ChannelTemplate;
  onClose: () => void;
  onSave: (data: CreateChannelData) => void;
  saving: boolean;
  serverError: string | null;
}) {
  const [fields, setFields] = useState<Record<string, string>>({});
  const [showTokens, setShowTokens] = useState<Record<string, boolean>>({});
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const dialogRef = useRef<HTMLDivElement>(null);
  const firstInputRef = useRef<HTMLInputElement>(null);
  const titleId = useId();
  const descId = useId();

  // Focus first input + Escape-to-close + focus trap.
  useEffect(() => {
    firstInputRef.current?.focus();

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        onClose();
        return;
      }
      if (e.key === "Tab" && dialogRef.current) {
        const focusable = dialogRef.current.querySelectorAll<HTMLElement>(
          'a, button, input, select, textarea, [tabindex]:not([tabindex="-1"])',
        );
        if (focusable.length === 0) return;
        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        if (e.shiftKey && document.activeElement === first) {
          last.focus();
          e.preventDefault();
        } else if (!e.shiftKey && document.activeElement === last) {
          first.focus();
          e.preventDefault();
        }
      }
    };

    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [onClose]);

  const validate = (): boolean => {
    const errs: Record<string, string> = {};
    for (const f of template.fields) {
      const value = (fields[f.key] || "").trim();
      if (f.required && !value) {
        errs[f.key] = `${f.label} is required.`;
        continue;
      }
      if (value && f.pattern && !f.pattern.test(value)) {
        errs[f.key] = f.patternMessage ?? `Invalid ${f.label}.`;
      }
    }
    setFieldErrors(errs);
    return Object.keys(errs).length === 0;
  };

  const handleSave = () => {
    if (!validate()) return;
    const config: Record<string, unknown> = {};
    template.fields.forEach((f) => {
      if (f.key === "allow_from_text") {
        config.allow_from = (fields[f.key] || "")
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean);
      } else {
        config[f.key] = fields[f.key] || "";
      }
    });
    onSave({
      channel_type: template.type,
      display_name: template.name,
      config: config as CreateChannelData["config"],
      is_enabled: true,
    });
  };

  const allRequiredFilled = template.fields
    .filter((f) => f.required)
    .every((f) => (fields[f.key] || "").trim());

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
      onClick={onClose}
    >
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={descId}
        onClick={(e) => e.stopPropagation()}
        className="w-full max-w-lg mx-4 rounded-[var(--radius-xl)] border border-[var(--border-subtle)] overflow-hidden"
        style={{ backgroundColor: "var(--bg-secondary)", boxShadow: "0 32px 64px rgba(0,0,0,0.5)" }}
      >
        <div className="flex items-center gap-3 p-5 border-b border-[var(--border-subtle)]">
          <div
            className="w-10 h-10 rounded-[10px] flex items-center justify-center"
            style={{ backgroundColor: `${template.color}22` }}
          >
            <template.icon className="w-5 h-5" style={{ color: template.color }} strokeWidth={1.75} />
          </div>
          <div className="flex-1">
            <h2 id={titleId} className="text-[17px] font-semibold text-[var(--text-primary)]">
              Connect {template.name}
            </h2>
            <p id={descId} className="text-[13px] text-[var(--text-muted)]">
              {template.description}
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close dialog"
            className="p-2 rounded-[8px] hover:bg-[rgba(255,255,255,0.08)] transition-colors"
          >
            <X className="w-4 h-4 text-[var(--text-muted)]" />
          </button>
        </div>

        <div className="p-5 space-y-4 max-h-[60vh] overflow-y-auto">
          {template.fields.length === 0 && (
            <div className="text-center py-6">
              <p className="text-[14px] text-[var(--text-secondary)]">
                {template.type === "whatsapp"
                  ? "WhatsApp will prompt you to scan a QR code after the gateway restarts."
                  : template.type === "webchat"
                  ? "WebChat is available automatically at the OpenClaw gateway URL."
                  : "This channel will be enabled with default settings."}
              </p>
            </div>
          )}

          {template.fields.map((field, idx) => {
            const inputId = `${titleId}-${field.key}`;
            const errId = `${inputId}-err`;
            const hasError = Boolean(fieldErrors[field.key]);
            return (
              <div key={field.key}>
                <label
                  htmlFor={inputId}
                  className="block text-[13px] font-medium text-[var(--text-secondary)] mb-1.5"
                >
                  {field.label}
                  {field.required && <span className="text-[var(--accent-danger)] ml-0.5">*</span>}
                </label>
                <div className="relative">
                  <input
                    id={inputId}
                    ref={idx === 0 ? firstInputRef : null}
                    type={field.type === "password" && !showTokens[field.key] ? "password" : "text"}
                    value={fields[field.key] || ""}
                    onChange={(e) =>
                      setFields((prev) => ({ ...prev, [field.key]: e.target.value }))
                    }
                    onBlur={validate}
                    aria-invalid={hasError || undefined}
                    aria-describedby={hasError ? errId : undefined}
                    placeholder={field.placeholder}
                    className="w-full px-3.5 py-2.5 rounded-[10px] border bg-[var(--bg-input)] text-[14px] text-[var(--text-primary)] placeholder:text-[var(--text-muted)] outline-none focus:border-[var(--accent-primary)] transition-colors pr-10"
                    style={{
                      borderColor: hasError
                        ? "var(--accent-danger)"
                        : "var(--border-primary)",
                    }}
                  />
                  {field.type === "password" && (
                    <button
                      type="button"
                      aria-label={
                        showTokens[field.key] ? "Hide token" : "Show token"
                      }
                      onClick={() =>
                        setShowTokens((prev) => ({
                          ...prev,
                          [field.key]: !prev[field.key],
                        }))
                      }
                      className="absolute right-2.5 top-1/2 -translate-y-1/2 p-1 rounded hover:bg-[rgba(255,255,255,0.08)]"
                    >
                      {showTokens[field.key] ? (
                        <EyeOff className="w-4 h-4 text-[var(--text-muted)]" />
                      ) : (
                        <Eye className="w-4 h-4 text-[var(--text-muted)]" />
                      )}
                    </button>
                  )}
                </div>
                {field.helpText && !hasError && (
                  <p className="text-[12px] text-[var(--text-muted)] mt-1">
                    {field.helpText}
                  </p>
                )}
                {hasError && (
                  <p id={errId} className="text-[12px] text-[var(--accent-danger)] mt-1">
                    {fieldErrors[field.key]}
                  </p>
                )}
              </div>
            );
          })}

          {serverError && (
            <ErrorBanner title="Couldn't save channel" message={serverError} />
          )}
        </div>

        <div className="flex items-center justify-end gap-3 p-5 border-t border-[var(--border-subtle)]">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 rounded-[10px] text-[14px] font-medium text-[var(--text-secondary)] hover:bg-[rgba(255,255,255,0.06)] transition-colors"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={handleSave}
            disabled={saving || (template.fields.length > 0 && !allRequiredFilled)}
            className="flex items-center gap-2 px-5 py-2 rounded-[10px] text-[14px] font-semibold text-white bg-[var(--accent-primary)] hover:brightness-110 transition-all disabled:opacity-40"
          >
            {saving && <Loader2 className="w-4 h-4 animate-spin" />}
            {saving ? "Connecting…" : "Connect Channel"}
          </button>
        </div>
      </div>
    </div>
  );
}

function ChannelStatusBadge({ channel }: { channel: ChannelWithStatus }) {
  const [showError, setShowError] = useState(false);
  const status = channel.status;
  const hasError = Boolean(channel.last_error);

  let label: string;
  let color: string;
  if (status === "error" || hasError) {
    label = "Error";
    color = "var(--accent-danger)";
  } else if (status === "pending") {
    label = "Pending";
    color = "var(--accent-warning)";
  } else if (status === "disconnected" || channel.is_enabled === false) {
    label = "Disabled";
    color = "var(--accent-danger)";
  } else {
    label = "Active";
    color = "var(--accent-success)";
  }

  return (
    <div className="flex items-center gap-2">
      <span
        className="text-[11px] font-semibold uppercase tracking-wide px-2 py-1 rounded-full"
        style={{
          backgroundColor: `color-mix(in srgb, ${color} 18%, transparent)`,
          color,
        }}
      >
        {label}
      </span>
      {hasError && (
        <div className="relative">
          <button
            type="button"
            onClick={() => setShowError((s) => !s)}
            aria-expanded={showError}
            className="text-[11px] font-medium text-[var(--accent-danger)] hover:underline inline-flex items-center gap-1"
          >
            <AlertTriangle className="w-3 h-3" strokeWidth={2} />
            View error
          </button>
          {showError && (
            <div
              role="dialog"
              className="absolute right-0 top-full mt-1.5 z-10 w-64 rounded-[10px] border border-[var(--border-subtle)] bg-[var(--bg-secondary)] shadow-lg p-3"
            >
              <p className="text-[12px] text-[var(--accent-danger)] font-semibold mb-1">
                Channel error
              </p>
              <p className="text-[12px] text-[var(--text-secondary)] break-words">
                {channel.last_error}
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function ChannelCard({
  channel,
  template,
  onToggle,
  onDelete,
  isToggling,
  isDeleting,
}: {
  channel: ChannelWithStatus;
  template: ChannelTemplate | undefined;
  onToggle: () => void;
  onDelete: () => void;
  isToggling: boolean;
  isDeleting: boolean;
}) {
  const [confirming, setConfirming] = useState(false);
  const Icon = template?.icon ?? Globe;
  const color = template?.color ?? "#0a84ff";

  return (
    <div
      className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] overflow-hidden"
      style={{ backgroundColor: "var(--bg-secondary)", boxShadow: "var(--shadow-card)" }}
    >
      <div className="p-5">
        <div className="flex items-start justify-between mb-3">
          <div className="flex items-center gap-3 min-w-0">
            <div
              className="w-11 h-11 rounded-[12px] flex items-center justify-center shrink-0"
              style={{ backgroundColor: `${color}22` }}
            >
              <Icon className="w-5 h-5" style={{ color }} strokeWidth={1.75} />
            </div>
            <div className="min-w-0">
              <h3 className="text-[15px] font-semibold text-[var(--text-primary)] truncate">
                {channel.display_name}
              </h3>
              <p className="text-[12px] text-[var(--text-muted)]">{channel.channel_type}</p>
            </div>
          </div>
          <ChannelStatusBadge channel={channel} />
        </div>

        {channel.config_meta && (
          <div className="flex flex-wrap gap-2 mt-3">
            {Boolean(channel.config_meta.has_bot_token) && (
              <span className="text-[11px] px-2 py-1 rounded-[6px] bg-[rgba(255,255,255,0.06)] text-[var(--text-muted)]">
                Token: {String(channel.config_meta.bot_token_preview ?? "***")}
              </span>
            )}
            {Boolean(channel.config_meta.has_app_token) && (
              <span className="text-[11px] px-2 py-1 rounded-[6px] bg-[rgba(255,255,255,0.06)] text-[var(--text-muted)]">
                App Token Set
              </span>
            )}
            {Array.isArray(channel.config_meta.allow_from) &&
              (channel.config_meta.allow_from as string[]).length > 0 && (
                <span className="text-[11px] px-2 py-1 rounded-[6px] bg-[rgba(255,255,255,0.06)] text-[var(--text-muted)]">
                  {(channel.config_meta.allow_from as string[]).length} allowed
                </span>
              )}
          </div>
        )}
      </div>

      <div className="flex items-center justify-between px-5 py-3 border-t border-[var(--border-subtle)] bg-[var(--bg-tertiary)]">
        <button
          type="button"
          onClick={onToggle}
          disabled={isToggling}
          className="text-[13px] font-medium text-[var(--accent-primary)] hover:underline disabled:opacity-50 inline-flex items-center gap-1.5"
        >
          {isToggling && <Loader2 className="w-3 h-3 animate-spin" />}
          {channel.is_enabled ? "Disable" : "Enable"}
        </button>
        {!confirming ? (
          <button
            type="button"
            onClick={() => setConfirming(true)}
            disabled={isDeleting}
            className="flex items-center gap-1.5 text-[13px] font-medium text-[var(--text-muted)] hover:text-[var(--accent-danger)] transition-colors disabled:opacity-50"
          >
            <Trash2 className="w-3.5 h-3.5" strokeWidth={2} /> Remove
          </button>
        ) : (
          <div className="flex items-center gap-2">
            <span className="text-[12px] text-[var(--accent-danger)]">Confirm?</span>
            <button
              type="button"
              onClick={onDelete}
              disabled={isDeleting}
              className="text-[12px] font-semibold text-[var(--accent-danger)] hover:underline disabled:opacity-50 inline-flex items-center gap-1"
            >
              {isDeleting && <Loader2 className="w-3 h-3 animate-spin" />} Yes
            </button>
            <button
              type="button"
              onClick={() => setConfirming(false)}
              className="text-[12px] font-medium text-[var(--text-muted)] hover:underline"
            >
              No
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Page ──────────────────────────────────────────────────────────────────

export default function Channels() {
  const queryClient = useQueryClient();
  const [addingTemplate, setAddingTemplate] = useState<ChannelTemplate | null>(null);
  const [addError, setAddError] = useState<string | null>(null);
  const [pendingId, setPendingId] = useState<string | null>(null);

  const channelsQuery = useQuery({
    queryKey: ["channels"],
    queryFn: () => getChannels() as Promise<ChannelWithStatus[]>,
  });

  const statusQuery = useQuery({
    queryKey: ["openclaw-status"],
    queryFn: getOpenClawStatus,
  });

  const createMutation = useMutation({
    mutationFn: createChannel,
    onSuccess: (channel) => {
      queryClient.invalidateQueries({ queryKey: ["channels"] });
      setAddingTemplate(null);
      setAddError(null);
      toast.success({
        title: `Channel ${channel.display_name} added`,
      });
    },
    onError: (err: unknown) => {
      const msg = getErrorMessage(err, "Couldn't create channel.");
      setAddError(msg);
      toast.error({ title: "Couldn't add channel", description: msg });
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Parameters<typeof updateChannel>[1] }) =>
      updateChannel(id, data),
    onSuccess: (channel) => {
      queryClient.invalidateQueries({ queryKey: ["channels"] });
      toast.success({ title: `Channel ${channel.display_name} updated` });
    },
    onError: (err: unknown) => {
      toast.error({
        title: "Couldn't update channel",
        description: getErrorMessage(err, "Try again in a moment."),
      });
    },
    onSettled: () => setPendingId(null),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => deleteChannel(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["channels"] });
      toast.success({ title: "Channel removed" });
    },
    onError: (err: unknown) => {
      toast.error({
        title: "Couldn't remove channel",
        description: getErrorMessage(err, "Try again in a moment."),
      });
    },
    onSettled: () => setPendingId(null),
  });

  const syncMutation = useMutation({
    mutationFn: () => restartOpenClaw(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["channels"] });
      queryClient.invalidateQueries({ queryKey: ["openclaw-status"] });
      toast.success({ title: "Gateway synced" });
    },
    onError: (err: unknown) => {
      toast.error({
        title: "Couldn't sync gateway",
        description: getErrorMessage(err, "Try again in a moment."),
      });
    },
  });

  const channels = channelsQuery.data ?? [];
  const configuredTypes = new Set(channels.map((c) => c.channel_type));
  const availableTemplates = CHANNEL_TEMPLATES.filter((t) => !configuredTypes.has(t.type));
  const gatewayOnline = statusQuery.data?.gateway_online ?? false;
  const channelsCount =
    statusQuery.data?.channels_configured ?? channels.length;

  const handleToggle = (ch: ChannelWithStatus) => {
    setPendingId(ch.id);
    updateMutation.mutate({
      id: ch.id,
      data: { is_enabled: !ch.is_enabled },
    });
  };

  const handleDelete = (ch: ChannelWithStatus) => {
    setPendingId(ch.id);
    deleteMutation.mutate(ch.id);
  };

  if (channelsQuery.isLoading) {
    return (
      <div className="space-y-8">
        <header>
          <Skeleton width="w-48" height="h-9" className="mb-2" />
          <Skeleton width="w-72" height="h-4" />
        </header>
        <Skeleton width="w-full" height="h-24" className="rounded-[var(--radius-xl)]" />
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton
              key={i}
              width="w-full"
              height="h-40"
              className="rounded-[var(--radius-xl)]"
            />
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-8 min-w-0">
      <header>
        <h1 className="text-[28px] font-semibold tracking-tight text-[var(--text-primary)] md:text-[32px]">
          Channels
        </h1>
        <p className="text-[15px] text-[var(--text-secondary)] mt-1 max-w-xl leading-relaxed">
          Connect messaging platforms to your AI. Powered by OpenClaw gateway —
          messages from Telegram, Discord, Slack, and more are routed to your chosen
          AI provider.
        </p>
      </header>

      {channelsQuery.isError && (
        <ErrorBanner
          title="Couldn't load channels"
          error={channelsQuery.error}
          onRetry={() => channelsQuery.refetch()}
          retrying={channelsQuery.isFetching}
        />
      )}

      <GatewayStatus
        online={gatewayOnline}
        channelsCount={channelsCount}
        onSync={() => syncMutation.mutate()}
        syncing={syncMutation.isPending}
        loading={statusQuery.isLoading}
      />

      {channels.length > 0 && (
        <div>
          <h2 className="text-[17px] font-semibold text-[var(--text-primary)] mb-4">
            Connected Channels
          </h2>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
            {channels.map((ch) => (
              <ChannelCard
                key={ch.id}
                channel={ch}
                template={CHANNEL_TEMPLATES.find((t) => t.type === ch.channel_type)}
                onToggle={() => handleToggle(ch)}
                onDelete={() => handleDelete(ch)}
                isToggling={updateMutation.isPending && pendingId === ch.id}
                isDeleting={deleteMutation.isPending && pendingId === ch.id}
              />
            ))}
          </div>
        </div>
      )}

      <div>
        <h2 className="text-[17px] font-semibold text-[var(--text-primary)] mb-4">
          {channels.length > 0 ? "Add More Channels" : "Get Started"}
        </h2>
        {channels.length === 0 && availableTemplates.length === CHANNEL_TEMPLATES.length && (
          <EmptyState
            icon={Plus}
            title="No channels connected yet"
            description="Pick a platform below to wire up your first integration."
            className="mb-4"
          />
        )}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {availableTemplates.map((template) => (
            <button
              key={template.type}
              type="button"
              onClick={() => {
                setAddError(null);
                setAddingTemplate(template);
              }}
              className="group rounded-[var(--radius-xl)] border border-[var(--border-subtle)] p-5 text-left transition-all hover:border-[var(--accent-primary)] hover:bg-[rgba(10,132,255,0.04)]"
              style={{ backgroundColor: "var(--bg-secondary)" }}
            >
              <div className="flex items-center gap-3 mb-3">
                <div
                  className="w-10 h-10 rounded-[10px] flex items-center justify-center"
                  style={{ backgroundColor: `${template.color}22` }}
                >
                  <template.icon
                    className="w-5 h-5"
                    style={{ color: template.color }}
                    strokeWidth={1.75}
                  />
                </div>
                <h3 className="text-[15px] font-semibold text-[var(--text-primary)]">
                  {template.name}
                </h3>
              </div>
              <p className="text-[13px] text-[var(--text-muted)] leading-relaxed">
                {template.description}
              </p>
              <div className="mt-3 flex items-center gap-1.5 text-[12px] font-medium text-[var(--accent-primary)] opacity-0 group-hover:opacity-100 transition-opacity">
                <Plus className="w-3.5 h-3.5" strokeWidth={2.5} /> Connect
              </div>
            </button>
          ))}

          {availableTemplates.length === 0 && (
            <div className="col-span-full text-center py-8">
              <Check
                className="w-8 h-8 text-[var(--accent-success)] mx-auto mb-2"
                strokeWidth={1.5}
              />
              <p className="text-[14px] text-[var(--text-secondary)]">
                All available channels are connected!
              </p>
            </div>
          )}
        </div>
      </div>

      {addingTemplate && (
        <AddChannelModal
          template={addingTemplate}
          onClose={() => {
            setAddingTemplate(null);
            setAddError(null);
          }}
          onSave={(data) => createMutation.mutate(data)}
          saving={createMutation.isPending}
          serverError={addError}
        />
      )}
    </div>
  );
}
