/**
 * Maps the kebab-case lucide icon names the backend connector definitions use (the `icon` field
 * of GET /connectors/types, e.g. "graduation-cap") to lucide-react components, with Plug for any
 * name this build does not know.
 *
 * Why it exists: the Connectors page renders its cards from the backend catalog, so the icon is
 * data. An explicit map keeps the bundle to the icons actually used (importing lucide's whole
 * `icons` object would ship every icon), and a plain .ts module keeps React Fast Refresh working
 * for the page. Depends only on lucide-react; no network.
 */

import {
  BookOpen,
  Briefcase,
  Building2,
  Calendar,
  Cloud,
  Database,
  FileText,
  Folder,
  Github,
  Globe,
  GraduationCap,
  Mail,
  MessageSquare,
  NotebookPen,
  NotebookText,
  Plug,
  Server,
  Slack,
  TrendingUp,
  type LucideIcon,
} from "lucide-react";

/** Known icon names. Add a line here when a new connector picks an icon
 * that is not listed yet; until then its card shows the Plug fallback. */
export const CONNECTOR_ICONS: Readonly<Record<string, LucideIcon>> = {
  "book-open": BookOpen,
  briefcase: Briefcase,
  "building-2": Building2,
  calendar: Calendar,
  cloud: Cloud,
  database: Database,
  "file-text": FileText,
  folder: Folder,
  // lucide marks its brand icons deprecated (to be removed in 1.0); the
  // 0.x pin keeps them, and the fallback covers their eventual removal.
  github: Github,
  globe: Globe,
  "graduation-cap": GraduationCap,
  mail: Mail,
  "message-square": MessageSquare,
  "notebook-pen": NotebookPen,
  "notebook-text": NotebookText,
  plug: Plug,
  server: Server,
  slack: Slack,
  "trending-up": TrendingUp,
};

/** The fallback for an unknown, empty or missing icon name. */
export const FALLBACK_CONNECTOR_ICON: LucideIcon = Plug;

/** The lucide component for a catalog icon name (Plug when unknown). */
export function connectorIcon(name: string | null | undefined): LucideIcon {
  if (!name) return FALLBACK_CONNECTOR_ICON;
  return Object.prototype.hasOwnProperty.call(CONNECTOR_ICONS, name)
    ? CONNECTOR_ICONS[name]
    : FALLBACK_CONNECTOR_ICON;
}
