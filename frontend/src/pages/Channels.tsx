import { useState, useEffect, useCallback } from "react";
import {
  Plus,
  Check,
  X,
  ChevronDown,
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
} from "lucide-react";
import clsx from "clsx";
import type { ChannelResponse, ChannelType, CreateChannelData } from "@/types";
import {
  getChannels,
  createChannel,
  updateChannel,
  deleteChannel,
  getOpenClawStatus,
  restartOpenClawSync,
} from "@/services/api";

interface ChannelTemplate {
  type: ChannelType;
  name: string;
  description: string;
  icon: React.ComponentType<any>;
  color: string;
  fields: ChannelField[];
}

interface ChannelField {
  key: string;
  label: string;
  placeholder: string;
  required: boolean;
  type?: "text" | "password" | "textarea";
  helpText?: string;
}

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
        placeholder: "123456:ABCdefGHIjklMNOpqrSTUvwx",
        required: true,
        type: "password",
        helpText: "Get this from @BotFather on Telegram",
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
      },
      {
        key: "app_token",
        label: "App Token",
        placeholder: "xapp-...",
        required: true,
        type: "password",
        helpText: "App-level token with connections:write scope",
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

function GatewayStatus({
  online,
  channelsCount,
  onSync,
  syncing,
}: {
  online: boolean;
  channelsCount: number;
  onSync: () => void;
  syncing: boolean;
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
            <h3 className="text-[15px] font-semibold text-[var(--text-primary)]">
              OpenClaw Gateway
            </h3>
            <p className="text-[13px] text-[var(--text-muted)]">
              {online ? (
                <span className="text-[var(--accent-success)]">Online</span>
              ) : (
                <span className="text-[var(--accent-danger)]">Offline</span>
              )}
              {" \u00b7 "}
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
}: {
  template: ChannelTemplate;
  onClose: () => void;
  onSave: (data: CreateChannelData) => void;
  saving: boolean;
}) {
  const [fields, setFields] = useState<Record<string, string>>({});
  const [showTokens, setShowTokens] = useState<Record<string, boolean>>({});

  const handleSave = () => {
    const config: Record<string, any> = {};
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
      config,
      is_enabled: true,
    });
  };

  const allRequiredFilled = template.fields
    .filter((f) => f.required)
    .every((f) => (fields[f.key] || "").trim());

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div
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
            <h2 className="text-[17px] font-semibold text-[var(--text-primary)]">
              Connect {template.name}
            </h2>
            <p className="text-[13px] text-[var(--text-muted)]">{template.description}</p>
          </div>
          <button
            type="button"
            onClick={onClose}
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

          {template.fields.map((field) => (
            <div key={field.key}>
              <label className="block text-[13px] font-medium text-[var(--text-secondary)] mb-1.5">
                {field.label}
                {field.required && <span className="text-[var(--accent-danger)] ml-0.5">*</span>}
              </label>
              <div className="relative">
                <input
                  type={field.type === "password" && !showTokens[field.key] ? "password" : "text"}
                  value={fields[field.key] || ""}
                  onChange={(e) => setFields((prev) => ({ ...prev, [field.key]: e.target.value }))}
                  placeholder={field.placeholder}
                  className="w-full px-3.5 py-2.5 rounded-[10px] border border-[var(--border-primary)] bg-[var(--bg-input)] text-[14px] text-[var(--text-primary)] placeholder:text-[var(--text-muted)] outline-none focus:border-[var(--accent-primary)] transition-colors pr-10"
                />
                {field.type === "password" && (
                  <button
                    type="button"
                    onClick={() =>
                      setShowTokens((prev) => ({ ...prev, [field.key]: !prev[field.key] }))
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
              {field.helpText && (
                <p className="text-[12px] text-[var(--text-muted)] mt-1">{field.helpText}</p>
              )}
            </div>
          ))}
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
            Connect Channel
          </button>
        </div>
      </div>
    </div>
  );
}

function ChannelCard({
  channel,
  template,
  onToggle,
  onDelete,
}: {
  channel: ChannelResponse;
  template: ChannelTemplate | undefined;
  onToggle: () => void;
  onDelete: () => void;
}) {
  const [confirming, setConfirming] = useState(false);
  const Icon = template?.icon || Globe;
  const color = template?.color || "#0a84ff";

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
              <p className="text-[12px] text-[var(--text-muted)]">
                {channel.channel_type}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <span
              className="text-[11px] font-semibold uppercase tracking-wide px-2 py-1 rounded-full"
              style={{
                backgroundColor: channel.is_enabled ? "rgba(48,209,88,0.18)" : "rgba(255,69,58,0.18)",
                color: channel.is_enabled ? "var(--accent-success)" : "var(--accent-danger)",
              }}
            >
              {channel.is_enabled ? "Active" : "Disabled"}
            </span>
          </div>
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
          className="text-[13px] font-medium text-[var(--accent-primary)] hover:underline"
        >
          {channel.is_enabled ? "Disable" : "Enable"}
        </button>
        {!confirming ? (
          <button
            type="button"
            onClick={() => setConfirming(true)}
            className="flex items-center gap-1.5 text-[13px] font-medium text-[var(--text-muted)] hover:text-[var(--accent-danger)] transition-colors"
          >
            <Trash2 className="w-3.5 h-3.5" strokeWidth={2} /> Remove
          </button>
        ) : (
          <div className="flex items-center gap-2">
            <span className="text-[12px] text-[var(--accent-danger)]">Confirm?</span>
            <button
              type="button"
              onClick={onDelete}
              className="text-[12px] font-semibold text-[var(--accent-danger)] hover:underline"
            >
              Yes
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

export default function Channels() {
  const [channels, setChannels] = useState<ChannelResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [gatewayOnline, setGatewayOnline] = useState(false);
  const [channelsCount, setChannelsCount] = useState(0);
  const [addingTemplate, setAddingTemplate] = useState<ChannelTemplate | null>(null);
  const [saving, setSaving] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [error, setError] = useState("");

  const loadData = useCallback(async () => {
    try {
      const [channelList, status] = await Promise.all([
        getChannels(),
        getOpenClawStatus().catch(() => null),
      ]);
      setChannels(channelList);
      if (status) {
        setGatewayOnline(status.gateway_online);
        setChannelsCount(status.channels_configured);
      }
    } catch {
      // channels endpoint may fail if user is new
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const configuredTypes = new Set(channels.map((c) => c.channel_type));
  const availableTemplates = CHANNEL_TEMPLATES.filter((t) => !configuredTypes.has(t.type));

  const handleAddChannel = async (data: CreateChannelData) => {
    setSaving(true);
    setError("");
    try {
      const created = await createChannel(data);
      setChannels((prev) => [created, ...prev]);
      setAddingTemplate(null);
      setChannelsCount((c) => c + 1);
    } catch (err: any) {
      setError(err.message || "Failed to create channel");
    } finally {
      setSaving(false);
    }
  };

  const handleToggle = async (ch: ChannelResponse) => {
    try {
      const updated = await updateChannel(ch.id, { is_enabled: !ch.is_enabled });
      setChannels((prev) => prev.map((c) => (c.id === ch.id ? updated : c)));
    } catch {}
  };

  const handleDelete = async (ch: ChannelResponse) => {
    try {
      await deleteChannel(ch.id);
      setChannels((prev) => prev.filter((c) => c.id !== ch.id));
      setChannelsCount((c) => Math.max(0, c - 1));
    } catch {}
  };

  const handleSync = async () => {
    setSyncing(true);
    try {
      await restartOpenClawSync();
      await loadData();
    } catch {}
    setSyncing(false);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-6 h-6 animate-spin text-[var(--text-muted)]" />
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
          Connect messaging platforms to your AI. Powered by OpenClaw gateway &mdash; messages from Telegram, Discord, Slack, and more are routed to your chosen AI provider.
        </p>
      </header>

      <GatewayStatus
        online={gatewayOnline}
        channelsCount={channelsCount}
        onSync={handleSync}
        syncing={syncing}
      />

      {error && (
        <div className="rounded-[12px] border border-[rgba(255,69,58,0.3)] bg-[rgba(255,69,58,0.08)] px-4 py-3">
          <p className="text-[13px] text-[var(--accent-danger)]">{error}</p>
        </div>
      )}

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
              />
            ))}
          </div>
        </div>
      )}

      <div>
        <h2 className="text-[17px] font-semibold text-[var(--text-primary)] mb-4">
          {channels.length > 0 ? "Add More Channels" : "Get Started"}
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {availableTemplates.map((template) => (
            <button
              key={template.type}
              type="button"
              onClick={() => setAddingTemplate(template)}
              className="group rounded-[var(--radius-xl)] border border-[var(--border-subtle)] p-5 text-left transition-all hover:border-[var(--accent-primary)] hover:bg-[rgba(10,132,255,0.04)]"
              style={{ backgroundColor: "var(--bg-secondary)" }}
            >
              <div className="flex items-center gap-3 mb-3">
                <div
                  className="w-10 h-10 rounded-[10px] flex items-center justify-center"
                  style={{ backgroundColor: `${template.color}22` }}
                >
                  <template.icon className="w-5 h-5" style={{ color: template.color }} strokeWidth={1.75} />
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
              <Check className="w-8 h-8 text-[var(--accent-success)] mx-auto mb-2" strokeWidth={1.5} />
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
            setError("");
          }}
          onSave={handleAddChannel}
          saving={saving}
        />
      )}
    </div>
  );
}
