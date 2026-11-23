/**
 * Per-OS wording for the setup window: which Docker Desktop to install, what to call the
 * computer, where the app keeps its files, where the tray icon lives.
 *
 * Why it exists: The same four steps run on macOS and Windows, but the words people need differ
 * ("Docker Desktop for Mac" vs "... for Windows", the WSL 2 note, menu bar vs system tray). The
 * browser installer (installer/page.html) had the same table; this is its desktop twin.
 */

import type { Platform } from "./bridge";

export interface PlatformWords {
  /** "Mac" / "PC", as in "Checking your Mac…". */
  computer: string;
  /** Product name of the Docker Desktop build for this OS. */
  docker: string;
  headline: string;
  /** Where Crawler AI keeps its files, including the keys. */
  dataDir: string;
  /** Where the app's icon lives while the window is closed. */
  tray: string;
  /** Shown when the app couldn't launch Docker Desktop itself. */
  openDockerYourself: string;
  /** OS name for the version line. */
  osName: string;
  /** As in "Runs … on this Mac". */
  runsIn: string;
  /** What closing the window (and quitting the app) does to Crawler AI. */
  closeNote: string;
}

export const WORDS: Record<Platform, PlatformWords> = {
  mac: {
    computer: "Mac",
    docker: "Docker Desktop for Mac",
    headline: "Set up Crawler AI on this Mac",
    dataDir: "~/Library/Application Support/Crawler AI",
    tray: "menu-bar icon",
    openDockerYourself: "Open it from Applications",
    osName: "macOS",
    runsIn: "in Docker Desktop for Mac",
    closeNote: "Closing this window keeps Crawler AI running in Docker Desktop.",
  },
  windows: {
    computer: "PC",
    docker: "Docker Desktop for Windows",
    headline: "Set up Crawler AI on this PC",
    dataDir: "%LOCALAPPDATA%\\Crawler AI",
    tray: "system-tray icon",
    openDockerYourself: "Open it from the Start menu",
    osName: "Windows",
    runsIn: "in Docker Desktop for Windows",
    closeNote: "Closing this window keeps Crawler AI running in Docker Desktop.",
  },
};

/** A Mac release build: Crawler AI runs as the app's own processes, no Docker. */
export const NATIVE_MAC: PlatformWords = {
  ...WORDS.mac,
  headline: "Setting up Crawler AI on this Mac",
  runsIn: "natively",
  closeNote: "Closing this window keeps Crawler AI running; quitting the app stops it.",
};

export function wordsFor(platform: Platform, native: boolean | undefined): PlatformWords {
  return native && platform === "mac" ? NATIVE_MAC : WORDS[platform];
}

export const DOCKER_DESKTOP_URL = "https://www.docker.com/products/docker-desktop/";
export const WSL_URL = "https://learn.microsoft.com/windows/wsl/install";
export const LOCAL_URL = "http://localhost:3000";

/**
 * First guess before `app_info()` answers: the WebView runs on the machine it describes.
 * Anything that isn't Windows is treated as a Mac (the only two targets in v1).
 */
export function guessPlatform(): Platform {
  const nav = typeof navigator === "undefined" ? undefined : navigator;
  const hint =
    (nav as (Navigator & { userAgentData?: { platform?: string } }) | undefined)?.userAgentData
      ?.platform ||
    nav?.platform ||
    nav?.userAgent ||
    "";
  return /win/i.test(hint) ? "windows" : "mac";
}
