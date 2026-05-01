/* SentientAI app-shell service worker.
 *
 * Strategy:
 *   - Install: pre-cache a tiny app shell (HTML, manifest, brand SVG).
 *   - Activate: nuke any cache that does not match CACHE_NAME.
 *   - Fetch:
 *       * /api/* requests        -> network-first, no fallback caching.
 *       * Same-origin GET assets -> cache-first, then network.
 *       * Navigation requests    -> network, fall back to cached / on offline.
 */

const CACHE_NAME = "sentientai-shell-v1";
const APP_SHELL = ["/", "/index.html", "/manifest.webmanifest", "/icons/icon.svg"];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches
      .open(CACHE_NAME)
      .then((cache) => cache.addAll(APP_SHELL))
      .then(() => self.skipWaiting()),
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key))),
      )
      .then(() => self.clients.claim()),
  );
});

function isApiRequest(url) {
  return url.pathname.startsWith("/api/");
}

function isNavigation(request) {
  return request.mode === "navigate" || request.headers.get("accept")?.includes("text/html");
}

async function networkFirst(request) {
  try {
    const response = await fetch(request);
    return response;
  } catch (err) {
    const cached = await caches.match(request);
    if (cached) return cached;
    throw err;
  }
}

async function cacheFirst(request) {
  const cached = await caches.match(request);
  if (cached) return cached;
  const response = await fetch(request);
  if (response && response.ok && response.type === "basic") {
    const copy = response.clone();
    caches.open(CACHE_NAME).then((cache) => cache.put(request, copy));
  }
  return response;
}

async function navigationHandler(request) {
  try {
    return await fetch(request);
  } catch {
    const cache = await caches.open(CACHE_NAME);
    const fallback = (await cache.match("/index.html")) || (await cache.match("/"));
    if (fallback) return fallback;
    return new Response("Offline", { status: 503, statusText: "Offline" });
  }
}

self.addEventListener("fetch", (event) => {
  const { request } = event;
  if (request.method !== "GET") return;

  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;

  if (isApiRequest(url)) {
    event.respondWith(networkFirst(request));
    return;
  }

  if (isNavigation(request)) {
    event.respondWith(navigationHandler(request));
    return;
  }

  event.respondWith(cacheFirst(request));
});
