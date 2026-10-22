/**
 * SecurityNotes: the lines an approval card shows about what the server's call checks noticed
 * (a first-time recipient, a flagged link, an MCP tool that changed), one row per note in the
 * order the server sent them, coloured by severity.
 *
 * Why it exists: a note is only worth something if the owner reads it before Approve, on every
 * card type. Chat's ApprovalCard and Dashboard's ApprovalRow show the same notes the same way, so
 * the rendering lives here once. The text is a plain React text child, never markup: a note can
 * quote an address someone else wrote.
 */

import { AlertTriangle, Info } from "lucide-react";
import type { SecurityNote, SecurityNoteSeverity } from "@/types";

const STYLE: Record<SecurityNoteSeverity, { background?: string; color: string; Icon: typeof Info }> = {
  high: { background: "var(--fill-danger)", color: "var(--accent-danger)", Icon: AlertTriangle },
  warn: { background: "var(--fill-warning)", color: "var(--accent-warning)", Icon: AlertTriangle },
  info: { color: "var(--text-muted)", Icon: Info },
};

export default function SecurityNotes({ notes }: { notes?: SecurityNote[] | null }) {
  if (!notes || notes.length === 0) return null;
  return (
    <section aria-label="Security notes" className="mb-3">
      <div className="eyebrow mb-1" style={{ color: "var(--text-muted)" }}>
        Security notes
      </div>
      <ul className="flex flex-col gap-1">
        {notes.map((note, index) => {
          // An unknown severity reads as a warning, never as "info" (as on the server).
          const style = STYLE[note.severity] ?? STYLE.warn;
          const { Icon } = style;
          return (
            <li
              key={`${note.kind}-${index}`}
              data-severity={STYLE[note.severity] ? note.severity : "warn"}
              className="flex items-start gap-2 px-2 py-1.5 rounded-[8px] text-xs"
              style={{ background: style.background, color: "var(--text-secondary)" }}
            >
              <Icon className="w-3.5 h-3.5 mt-0.5 shrink-0" style={{ color: style.color }} aria-hidden />
              <span className="min-w-0 break-words">{note.text}</span>
            </li>
          );
        })}
      </ul>
    </section>
  );
}
