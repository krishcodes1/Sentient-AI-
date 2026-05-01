/**
 * Environment / build-time constants.
 * - API_BASE: the base URL of the backend API. Defaults to "/api" so the Vite proxy
 *   (or a same-origin reverse proxy in prod) handles routing.
 * - OPENCLAW_BROWSER_URL: the browser-facing OpenClaw Control UI URL. Used for iframes
 *   and "open in new tab" links. Falls back to `<origin>/openclaw` so reverse-proxied
 *   deployments work without env config.
 */
export const API_BASE = import.meta.env.VITE_API_BASE_URL || "/api";

export const OPENCLAW_BROWSER_URL =
  import.meta.env.VITE_OPENCLAW_BROWSER_URL ||
  (typeof window !== "undefined"
    ? `${window.location.origin}/openclaw`
    : "/openclaw");

export const APP_VERSION = "0.2.0";
export const IS_DEV = import.meta.env.DEV;
export const IS_PROD = import.meta.env.PROD;
