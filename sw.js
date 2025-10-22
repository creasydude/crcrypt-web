// sw.js
// Service Worker for CRCrypt Web.
// Offline cache of static assets only. No user data is cached or persisted.

const CACHE_VERSION = "v5";
const CACHE_NAME = `crcrypt-web-${CACHE_VERSION}`;
const CORE_ASSETS = [
  "index.html",
  "styles.css",
  "manifest.webmanifest",
  "src/ui.js",
  "src/crypto.js",
  "src/utils/hex.js"
];

/**
 * Install event: pre-cache core static assets.
 */
function swInstall(event) {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => cache.addAll(CORE_ASSETS))
      .then(() => self.skipWaiting())
      .catch(() => {
        // If pre-cache fails (e.g., served via file://), continue without SW.
        // The app still runs; offline cache just won't be available.
      })
  );
}

/**
 * Activate event: clean old caches and take control.
 */
function swActivate(event) {
  event.waitUntil(
    (async () => {
      const keys = await caches.keys();
      const deletions = keys
        .filter((k) => k !== CACHE_NAME)
        .map((k) => caches.delete(k));
      await Promise.all(deletions);
      if ("navigationPreload" in self.registration) {
        try { await self.registration.navigationPreload.enable(); } catch (e) {}
      }
      await self.clients.claim();
    })()
  );
}

/**
 * Fetch handler: serve from cache for core assets; otherwise network fallback.
 * No runtime caching of responses to avoid unintended persistence.
 */
function swFetch(event) {
  const req = event.request;
  if (req.method !== "GET") return;

  const url = new URL(req.url);

  // Handle navigation requests: serve app shell
  if (req.mode === "navigate") {
    // Robust navigation handler: try network first; on failure or bad status, use cached app shell.
    event.respondWith((async () => {
      try {
        const net = await fetch(req);
        if (net && net.ok) return net;
      } catch (_) {
        // ignore network error and try cache
      }
      const cached = (await caches.match("index.html")) || (await caches.match("/index.html"));
      if (cached) return cached;
      return new Response(
        "<h1>Offline</h1><p>The app shell is not cached yet.</p>",
        { status: 503, headers: { "Content-Type": "text/html" } }
      );
    })());
    return;
  }

  // Same-origin static assets: serve from cache if present, else network
  if (url.origin === self.location.origin) {
    event.respondWith(
      caches.match(req).then((cached) => {
        return cached || fetch(req);
      })
    );
  }
}

// Bind events
self.addEventListener("install", swInstall);
self.addEventListener("activate", swActivate);
self.addEventListener("fetch", swFetch);

// Security note:
// - Only static assets listed in CORE_ASSETS are pre-cached.
// - No dynamic responses or user data are cached at runtime.
// - Clipboard and inputs are handled entirely client-side without persistence.