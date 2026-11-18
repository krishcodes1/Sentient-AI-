/**
 * The Permissions screen's two simplifications of the capability list: protection levels (one
 * choice that sets what Crawler does on its own) and everyday categories (where each switch lives
 * when you fine-tune).
 *
 * Why it exists: forty switches in one list made people scroll past every one to find the few
 * they care about. A plain module (no components), so CapabilityList keeps fast refresh.
 *
 * Levels only touch the switches that decide how much Crawler acts by itself. The protections
 * (hide personal details, scam and link checks, tool rules…) and the features you pick for
 * yourself (reminders, tutor mode, voice notes…) are never changed by a level. Hands-off leaves
 * money, screen and computer control as they are: those stay a choice made one switch at a time.
 */

import {
  BookOpen,
  Clock,
  CreditCard,
  Globe,
  Monitor,
  Plug,
  Shapes,
  Shield,
  ShieldCheck,
  Zap,
  type LucideIcon,
} from "lucide-react";
import type { CapabilityStatus } from "@/types";

export type CategoryId = "safety" | "computer" | "web" | "money" | "apps" | "background" | "learning" | "other";

export interface Category {
  id: CategoryId;
  label: string;
  blurb: string;
  icon: LucideIcon;
  keys: string[];
}

// Keys come from backend/services/capabilities. A key missing here lands in "Other", so a new
// capability still shows up; give it a home here when you add one.
export const CATEGORIES: Category[] = [
  {
    id: "safety",
    label: "Privacy and safety",
    blurb: "Checks that run before anything leaves Crawler or reaches you. Keep these on unless one gets in your way.",
    icon: ShieldCheck,
    keys: [
      "hide_personal_details",
      "outbound_checks",
      "mail_scam_scan",
      "scam_check",
      "link_reputation",
      "file_reputation",
      "breach_monitor",
      "mcp_pinning",
      "tool_rules",
    ],
  },
  {
    id: "computer",
    label: "Your computer",
    blurb: "What Crawler may see and touch on this computer. macOS asks you separately for the screen and controls.",
    icon: Monitor,
    keys: ["screen", "computer_control", "file_reading", "installs", "voice_notes", "voice_notes_cloud"],
  },
  {
    id: "web",
    label: "Websites",
    blurb: "Reading the web, and using sites in Crawler's own browser.",
    icon: Globe,
    keys: [
      "web_browsing",
      "site_screenshots",
      "video_transcripts",
      "browser_control",
      "browser_act",
      "browser_ask_every_step",
      "browser_site_rules",
    ],
  },
  {
    id: "money",
    label: "Money",
    blurb: "Crawler only pays with a card you stored, inside the limits you set, and shows you each checkout first.",
    icon: CreditCard,
    keys: ["purchases"],
  },
  {
    id: "apps",
    label: "Connected apps",
    blurb: "Chat apps, and the changes Crawler may make in the apps you connected.",
    icon: Plug,
    keys: ["low_risk_actions", "telegram", "slack", "event_triggers"],
  },
  {
    id: "background",
    label: "Background tasks",
    blurb: "Work Crawler does while you are away, on a schedule or when something happens.",
    icon: Clock,
    keys: ["scheduled_tasks", "trigger_runs", "page_watch", "errand_runs", "calendar_errands", "reminders"],
  },
  {
    id: "learning",
    label: "Memory and learning",
    blurb: "What Crawler remembers about you, your documents, and study help.",
    icon: BookOpen,
    keys: ["save_memories", "knowledge_base", "knowledge_semantic", "study", "tutor_mode"],
  },
  { id: "other", label: "Other", blurb: "Everything else Crawler can do.", icon: Shapes, keys: [] },
];

export function groupByCategory(items: CapabilityStatus[]): { category: Category; items: CapabilityStatus[] }[] {
  const home = new Map<string, CategoryId>();
  for (const c of CATEGORIES) for (const key of c.keys) home.set(key, c.id);
  return CATEGORIES.map((category) => ({
    category,
    items: items.filter((item) => (home.get(item.key) ?? "other") === category.id),
  }));
}

export type LevelId = "cautious" | "balanced" | "hands_off";

export interface Level {
  id: LevelId;
  label: string;
  summary: string;
  icon: LucideIcon;
  /** The switches this level sets. Anything not listed is left as it is. */
  targets: Record<string, boolean>;
}

const NOTHING_ON_ITS_OWN: Record<string, boolean> = {
  low_risk_actions: false,
  browser_control: false,
  browser_act: false,
  computer_control: false,
  screen: false,
  purchases: false,
  scheduled_tasks: false,
  page_watch: false,
  event_triggers: false,
  trigger_runs: false,
  errand_runs: false,
  calendar_errands: false,
};

export const LEVELS: Level[] = [
  {
    id: "cautious",
    label: "Cautious",
    summary: "Reads and answers. Every change waits for you, and nothing runs in the background.",
    icon: Shield,
    targets: NOTHING_ON_ITS_OWN,
  },
  {
    // The switches Crawler ships with.
    id: "balanced",
    label: "Balanced",
    summary: "Makes small, undoable changes in apps you pick and asks before the rest. No browser, computer or money control.",
    icon: ShieldCheck,
    targets: { ...NOTHING_ON_ITS_OWN, low_risk_actions: true },
  },
  {
    id: "hands_off",
    label: "Hands-off",
    summary:
      "Also browses, fills in forms and runs scheduled tasks. Still asks before anything that pays, sends, posts or deletes.",
    icon: Zap,
    targets: {
      low_risk_actions: true,
      browser_control: true,
      browser_act: true,
      browser_ask_every_step: false,
      scheduled_tasks: true,
      page_watch: true,
      event_triggers: true,
      trigger_runs: true,
    },
  },
];

/** The switches picking `level` would change, as an updateCapabilities patch. Empty = already on it. */
export function levelPatch(level: Level, items: CapabilityStatus[]): Record<string, boolean> {
  const patch: Record<string, boolean> = {};
  for (const item of items) {
    const target = level.targets[item.key];
    if (target !== undefined && target !== item.enabled) patch[item.key] = target;
  }
  return patch;
}

/** A small pill under the summary. "cloud" marks data leaving this computer and is drawn amber. */
export type ChipKind = "asks" | "auto" | "local" | "cloud" | "schedule";

export interface About {
  /** One line, read at a glance. */
  summary: string;
  /** What it does without asking. */
  own?: string;
  /** What waits for your OK. */
  asks?: string;
  /** Where your data goes. */
  data?: string;
  chips?: [ChipKind, string][];
}

// The glance view of each capability, behind its info button: three short facts instead of the
// server's paragraph. Keep each true to its description in backend/services/capabilities; a key
// missing here shows the server's first sentence and full description instead.
const ABOUT: Record<string, About> = {
  web_browsing: {
    summary: "Searches the web and reads pages to answer you.",
    own: "Searches the public web and reads pages as text.",
    chips: [["auto", "Only reads"]],
  },
  site_screenshots: {
    summary: "Takes a picture of a page that can't be read as text.",
    own: "Opens a page in a hidden browser and takes a picture of it, for pages like flights and products.",
    chips: [["auto", "Only reads"]],
  },
  screen: {
    summary: "Takes a picture of your screen when you ask.",
    asks: "It only takes a picture of your screen when you ask for one.",
    chips: [["asks", "Only when you ask"]],
  },
  reminders: {
    summary: "Sets reminders and sends them to you.",
    own: "Sets, lists and cancels reminders.",
    data: "Reminders reach you on Telegram when it's linked.",
  },
  save_memories: {
    summary: "Remembers facts about you, after you OK the exact text.",
    asks: "Every memory, showing you the exact text it will save.",
    chips: [["asks", "Asks first"]],
  },
  installs: {
    summary: "Installs extra components from a fixed list, asking each time.",
    asks: "Every install, each time. Only components on a fixed list, like the hidden browser.",
    chips: [["asks", "Asks first"]],
  },
  telegram: {
    summary: "Chat with Crawler and approve actions from Telegram.",
    own: "Lets you chat with Crawler and approve actions from your phone.",
    data: "Your chats with Crawler go through Telegram.",
    chips: [["cloud", "Goes through Telegram"]],
  },
  slack: {
    summary: "Chat with Crawler and approve actions from Slack.",
    own: "Lets you chat with Crawler in Slack direct messages and approve actions there.",
    data: "Your chats with Crawler go through Slack.",
    chips: [["cloud", "Goes through Slack"]],
  },
  browser_control: {
    summary: "Opens and reads sites in Crawler's own browser.",
    own: "Opens sites in its own browser, reads pages and follows links. Typing and clicking is a separate switch.",
    chips: [["auto", "Only reads"]],
  },
  browser_act: {
    summary: "Fills in forms and clicks on sites. Asks before paying or sending.",
    own: "Steps that commit you to nothing: searching, choosing options, adding to the cart.",
    asks: "Paying, sending, posting, deleting, cancelling, signing you up, agreeing to terms or typing your details, on a card with a picture of the page.",
    chips: [["asks", "Asks before paying or sending"]],
  },
  browser_ask_every_step: {
    summary: "Shows you a card before every single website step.",
    own: "With this off, the ordinary steps of a website errand.",
    asks: "With this on, every step. Paying, sending, posting or deleting always asks.",
  },
  computer_control: {
    summary: "Clicks and types in your apps, asking before each action.",
    asks: "Every action: clicking, typing, pressing keys and opening apps.",
    chips: [["asks", "Asks every action"]],
  },
  purchases: {
    summary: "Buys small things with your stored card, within your limits.",
    own: "Books tickets and makes small purchases in Crawler's browser, inside your spending caps.",
    asks: "Every purchase, before it's paid.",
    data: "Pays only with the card you stored.",
    chips: [["asks", "You approve every purchase"]],
  },
  page_watch: {
    summary: "Tells you on Telegram when a page you name changes.",
    own: "Checks the pages you name, at most every 30 minutes.",
    data: "Changes are messaged to you on Telegram.",
    chips: [["schedule", "On a schedule"]],
  },
  hide_personal_details: {
    summary: "Hides your email, phone, address and birthday from the AI.",
    own: "Swaps email addresses, phone numbers, street addresses and birth dates for placeholders.",
    data: "Your cloud AI provider only sees placeholders. Real values come back only in replies and actions you approve.",
    chips: [["local", "Before anything leaves"]],
  },
  file_reading: {
    summary: "Reads PDFs, Office and text files, on this computer.",
    own: "Reads PDF, Word, PowerPoint, Excel, CSV, text and HTML files you send or your apps hold.",
    data: "Files are read on this computer.",
    chips: [["local", "On this computer"]],
  },
  scheduled_tasks: {
    summary: "Runs your prompts on a schedule and sends a daily briefing.",
    own: "Runs prompts you approved on a schedule, and a daily briefing of Canvas, calendar and mail.",
    asks: "Changing anything. Scheduled runs only read.",
    chips: [["schedule", "On a schedule"]],
  },
  tutor_mode: {
    summary: "Gives hints and questions instead of final answers.",
    own: "In tutor mode, guides with questions and hints instead of final answers. The owner can lock it on for chosen courses or accounts.",
  },
  knowledge_base: {
    summary: "Saves your documents here and searches them with sources.",
    own: "Searches the documents you saved, with citations.",
    asks: "Saving or deleting from chat.",
    data: "Collections are kept on this computer.",
    chips: [["local", "Kept on this computer"]],
  },
  knowledge_semantic: {
    summary: "Searches by meaning. May send document text to your AI provider.",
    own: "Also finds passages by meaning, not just matching words.",
    data: "With Ollama, indexed on this computer. With Gemini or OpenAI, document text (keys, card and ID numbers removed) goes to that provider.",
    chips: [["cloud", "May send text to your AI provider"]],
  },
  study: {
    summary: "Makes flashcards and practice quizzes from your notes.",
    own: "Makes decks and quizzes from your notes and course files, reviews them with you and exports to Anki.",
  },
  event_triggers: {
    summary: "Messages you when something new happens in your apps.",
    own: "Checks your connected apps on a schedule for the things you named.",
    data: "Tells you on Telegram or Slack.",
    chips: [["schedule", "On a schedule"]],
  },
  trigger_runs: {
    summary: "Runs your task when a trigger fires. Changes wait for you.",
    own: "Runs the task you wrote, with read-only access to that app, within a daily limit.",
    asks: "Anything it wants to change.",
    chips: [["schedule", "When a trigger fires"]],
  },
  low_risk_actions: {
    summary: "Makes small, undoable changes without asking. Sends and deletes still ask.",
    own: "Small, undoable changes in the accounts you choose: stars, labels, drafts, private events and to-dos.",
    asks: "Sends, deletes, sharing and anything other people see.",
    chips: [["auto", "Small changes only"]],
  },
  voice_notes: {
    summary: "Turns voice notes into text, on this computer.",
    own: "Turns Telegram voice notes into text and answers them like a typed message.",
    data: "The recording never leaves this computer and isn't kept.",
    chips: [["local", "Never leaves this computer"]],
  },
  voice_notes_cloud: {
    summary: "Sends voice notes to your AI provider to turn into text.",
    own: "Turns Telegram voice notes into text when transcription on this computer is off.",
    data: "Your AI provider hears the recording. Crawler keeps only the text.",
    chips: [["cloud", "Audio goes to your AI provider"]],
  },
  video_transcripts: {
    summary: "Summarises videos and podcasts you link.",
    own: "Reads the captions or transcript of a video, lecture or podcast you link, and answers with timestamps.",
    data: "YouTube videos are read by your AI provider (Gemini only).",
    chips: [["cloud", "Uses your AI provider"]],
  },
  outbound_checks: {
    summary: "Checks who a message goes to, and what it carries, before it's sent.",
    own: "Checks recipients (first time, outside your organisation, look-alikes) and links that could carry your data out.",
    asks: "Anything flagged that would have gone without asking.",
  },
  mail_scam_scan: {
    summary: "Scans new email for phishing and alerts you.",
    own: "Checks new Gmail and Outlook mail for forged senders, hidden links and risky attachments, on this computer.",
    asks: "Moving any email.",
    data: "Mail that looks wrong goes to your AI provider for a second look.",
    chips: [["cloud", "Some mail to your AI provider"]],
  },
  scam_check: {
    summary: "Checks a message, link or screenshot for scams when you ask.",
    own: "Checks a message, link, screenshot or QR code you send for scam signs.",
    data: "Your AI provider takes a look. Links go to Google Safe Browsing only if the owner added a key.",
    chips: [["asks", "Only when you ask"]],
  },
  link_reputation: {
    summary: "Checks links against Google's list of dangerous sites.",
    own: "Looks up links from mail alerts, scam checks, outgoing messages and the browser.",
    data: "Only the link goes to Google, with your own key. Nothing is sent without one.",
    chips: [["cloud", "Links go to Google"]],
  },
  mcp_pinning: {
    summary: "Holds back MCP tools that change until you review them.",
    own: "Remembers exactly what each MCP tool says it does.",
    asks: "A changed or new tool waits for your review on the Security page.",
  },
  breach_monitor: {
    summary: "Tells you when your email shows up in a data breach.",
    own: "Checks your addresses for new breaches once a week.",
    data: "Your addresses go to Have I Been Pwned, with your own key. The password check never sends your password.",
    chips: [["schedule", "Weekly"]],
  },
  browser_site_rules: {
    summary: "Blocks sites you pick and warns on banks and government sites.",
    own: "Never opens the sites you block.",
    asks: "Warns on every approval for banks, brokers, crypto, tax and government sites.",
  },
  tool_rules: {
    summary: "Asks you first when an action breaks a safety rule.",
    own: "Checks every action against built-in rules and the ones you add.",
    asks: "Any action that breaks a rule. The card names the rule.",
  },
  file_reputation: {
    summary: "Checks files with VirusTotal. Uploads only if you OK it.",
    own: "Looks up the fingerprint of files and attachments in VirusTotal, with your own key.",
    asks: "Uploading a file.",
    data: "Only the fingerprint (SHA-256) is sent.",
  },
  errand_runs: {
    summary: "Shops for your errands while you're away. Asks once before paying.",
    own: "Finds the best price, adds it to the cart and goes to checkout while you're away.",
    asks: "Once, before paying. Nothing is bought until you approve.",
    chips: [["asks", "Asks before paying"]],
  },
  calendar_errands: {
    summary: "Plans orders from your calendar notes and tells you.",
    own: "Reads your calendar notes for the next six months each day, and plans orders a week ahead.",
    asks: "Paying, like any errand.",
    chips: [["schedule", "Daily"]],
  },
};

export function aboutOf(item: CapabilityStatus): About | undefined {
  return ABOUT[item.key];
}

/** The one-line summary, or the description's first sentence for a capability not listed. */
export function summaryOf(item: CapabilityStatus): string {
  return ABOUT[item.key]?.summary ?? item.description.match(/^.+?[.!?](?=\s|$)/)?.[0] ?? item.description;
}

const RISK_ORDER: Record<CapabilityStatus["risk"], number> = { high: 0, medium: 1, low: 2 };

/** Riskiest first, so a short preview shows the switches that matter most. */
export function byRisk(items: CapabilityStatus[]): CapabilityStatus[] {
  return [...items].sort((a, b) => RISK_ORDER[a.risk] - RISK_ORDER[b.risk]);
}
