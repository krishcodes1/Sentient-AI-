import { useEffect, useState } from "react";
import { ExternalLink, Loader2 } from "lucide-react";
import { getOpenClawEmbedUrl } from "@/services/api";

const FALLBACK =
  (typeof import.meta.env.VITE_OPENCLAW_GATEWAY_URL === "string"
    && import.meta.env.VITE_OPENCLAW_GATEWAY_URL) ||
  "http://127.0.0.1:18789/";

function normalizeUrl(u: string): string {
  const t = u.trim();
  return t.endsWith("/") ? t : `${t}/`;
}

export default function Gateway() {
  const [url, setUrl] = useState<string | null>(null);
  const [notice, setNotice] = useState("");

  useEffect(() => {
    getOpenClawEmbedUrl()
      .then((r) => setUrl(normalizeUrl(r.url)))
      .catch(() => {
        setUrl(normalizeUrl(FALLBACK));
        setNotice("Could not load URL from API — using default. Ensure the gateway is on port 18789.");
      });
  }, []);

  const openHref = url ?? normalizeUrl(FALLBACK);

  return (
    <div className="flex flex-col flex-1 min-h-0 min-w-0 bg-[var(--bg-primary)]">
      <div className="shrink-0 flex flex-wrap items-center gap-2 px-3 py-2 border-b border-[var(--claw-border)] bg-[var(--claw-panel)]">
        <span className="text-[11px] font-mono text-[var(--text-muted)] uppercase tracking-wider">
          OpenClaw
        </span>
        <span className="text-[11px] font-mono text-[var(--claw-accent)] truncate max-w-[min(100%,320px)]">
          {openHref}
        </span>
        <a
          href={openHref}
          target="_blank"
          rel="noopener noreferrer"
          className="ml-auto inline-flex items-center gap-1 text-[11px] font-mono text-[var(--claw-accent-bright)] hover:underline shrink-0"
        >
          <ExternalLink className="w-3 h-3" />
          Open in new tab
        </a>
      </div>
      {notice ? (
        <p className="shrink-0 px-3 py-1.5 text-[11px] text-[var(--accent-warning)] bg-[rgba(251,191,36,0.08)] border-b border-[var(--claw-border)]">
          {notice}
        </p>
      ) : null}
      <div className="relative flex-1 min-h-0 w-full">
        {!url ? (
          <div className="absolute inset-0 flex items-center justify-center bg-[var(--bg-primary)]">
            <Loader2 className="w-6 h-6 animate-spin text-[var(--claw-accent)]" />
          </div>
        ) : (
          <iframe
            title="OpenClaw Control UI"
            src={url}
            className="absolute inset-0 w-full h-full border-0 bg-[#0a0a0b]"
            allow="clipboard-read; clipboard-write; fullscreen"
            referrerPolicy="no-referrer-when-downgrade"
          />
        )}
      </div>
      <p className="shrink-0 px-3 py-2 text-[10px] leading-snug text-[var(--text-muted)] font-mono border-t border-[var(--claw-border)] bg-[var(--claw-panel)]">
        Full native OpenClaw dashboard — channels, WebChat, sessions, and config. If the frame is empty, your browser may block cross-origin embedding; use &quot;Open in new tab&quot;.
      </p>
    </div>
  );
}
