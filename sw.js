/*
 * Totals POS - Service Worker
 * ---------------------------------------------------------------------------
 * Provides full offline capability and "push updates over the web" delivery.
 *
 * HOW UPDATES REACH CASHIERS WITHOUT A SITE VISIT:
 *   Every time you push a new version of the app to GitHub Pages, bump
 *   APP_VERSION below. Installed clients poll for a new service worker
 *   (browsers check periodically and on navigation). When a new version is
 *   found it is pre-cached in the background; the app then shows an
 *   "Update available" banner and applies it on the next reload. No one has
 *   to reinstall anything and no store review is involved.
 */

const APP_VERSION = 'v1.5.1';
const CACHE = `totals-pos-${APP_VERSION}`;

// The complete app shell. Everything here is available offline after first load.
const SHELL = [
  './',
  './index.html',
  './manifest.webmanifest',
  './css/app.css',
  './js/config.js',
  './js/db.js',
  './js/sync.js',
  './js/receipt.js',
  './js/scan.js',
  './js/app.js',
  './vendor/sql-wasm.js',
  './vendor/sql-wasm.wasm',
  './vendor/zxing.min.js',
  './vendor/xlsx.full.min.js',
  './icons/icon.svg'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    (async () => {
      const cache = await caches.open(CACHE);
      // addAll fails the whole install if any file 404s, so cache best-effort.
      await Promise.allSettled(SHELL.map((url) => cache.add(url)));
      // Do NOT skipWaiting automatically. We let the page decide when to
      // activate the update so a cashier is never interrupted mid-sale.
    })()
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    (async () => {
      const keys = await caches.keys();
      await Promise.all(
        keys.filter((k) => k.startsWith('totals-pos-') && k !== CACHE)
            .map((k) => caches.delete(k))
      );
      await self.clients.claim();
    })()
  );
});

// The page posts {type:'SKIP_WAITING'} when the user accepts an update.
self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
  if (event.data && event.data.type === 'GET_VERSION') {
    event.ports[0] && event.ports[0].postMessage({ version: APP_VERSION });
  }
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;

  const url = new URL(req.url);

  // Never cache calls to the cloud backend API — always go to the network so
  // stock and tenant data stay live. Sync layer handles offline queueing.
  if (url.pathname.includes('/api/') || url.searchParams.has('nocache')) {
    return; // default browser network handling
  }

  // Same-origin app shell: cache-first with background refresh.
  if (url.origin === self.location.origin) {
    event.respondWith(
      (async () => {
        const cache = await caches.open(CACHE);
        const cached = await cache.match(req, { ignoreSearch: false });
        const network = fetch(req)
          .then((res) => {
            if (res && res.ok && res.type === 'basic') {
              cache.put(req, res.clone());
            }
            return res;
          })
          .catch(() => null);
        return cached || (await network) || cache.match('./index.html');
      })()
    );
  }
});

// Background Sync: retry uploading pending sales when connectivity returns.
self.addEventListener('sync', (event) => {
  if (event.tag === 'totals-sync') {
    event.waitUntil(
      self.clients.matchAll({ includeUncontrolled: true }).then((clients) => {
        clients.forEach((c) => c.postMessage({ type: 'RUN_SYNC' }));
      })
    );
  }
});
