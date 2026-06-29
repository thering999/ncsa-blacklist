// NOTE: Place a 192x192 PNG at /public/icon-192.png for notification icons.

const CACHE_NAME = 'ncsa-v2';
const CACHE_URLS = ['/', '/index.html', '/manifest.json'];
const API_PATHS = ['/check', '/bulk', '/recent', '/stats', '/search', '/trend'];

// ── Install ──────────────────────────────────────────────────────────────────
self.addEventListener('install', (e) => {
  e.waitUntil(
    caches.open(CACHE_NAME).then((c) => c.addAll(CACHE_URLS))
  );
  self.skipWaiting();
});

// ── Activate ─────────────────────────────────────────────────────────────────
self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

// ── Fetch ─────────────────────────────────────────────────────────────────────
self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  const isAPI = API_PATHS.some((p) => url.pathname.startsWith(p));

  if (isAPI) {
    // Network-first for API
    e.respondWith(
      fetch(e.request).catch(() => caches.match(e.request))
    );
  } else {
    // Cache-first for static assets
    e.respondWith(
      caches.match(e.request).then((cached) => {
        if (cached) return cached;
        return fetch(e.request).then((res) => {
          if (!res || res.status !== 200 || res.type !== 'basic') return res;
          const clone = res.clone();
          caches.open(CACHE_NAME).then((c) => c.put(e.request, clone));
          return res;
        });
      })
    );
  }
});

// ── Push Notification ─────────────────────────────────────────────────────────
self.addEventListener('push', (e) => {
  let data = { title: 'NCSA Dashboard', body: 'มีการแจ้งเตือนใหม่', url: '/' };
  try {
    if (e.data) Object.assign(data, e.data.json());
  } catch (_) {}

  e.waitUntil(
    self.registration.showNotification(data.title, {
      body: data.body,
      icon: '/icon-192.png',
      badge: '/icon-192.png',
      tag: data.tag ?? 'ncsa-alert',
      data: { url: data.url ?? '/' },
      requireInteraction: data.requireInteraction ?? false,
    })
  );
});

self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  const target = e.notification.data?.url ?? '/';
  e.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((list) => {
      for (const client of list) {
        if (new URL(client.url).pathname === target && 'focus' in client) {
          return client.focus();
        }
      }
      return self.clients.openWindow(target);
    })
  );
});

// ── Message from main thread ──────────────────────────────────────────────────
self.addEventListener('message', (e) => {
  if (e.data?.type === 'WATCHLIST_HIT') {
    const { ip, detail } = e.data;
    self.registration.showNotification('⚠️ Watchlist Hit', {
      body: `${ip} — ${detail ?? 'พบใน NCSA Blacklist'}`,
      icon: '/icon-192.png',
      tag: `watchlist-${ip}`,
      requireInteraction: true,
      data: { url: '/' },
    });
  }
});

// ── Background Sync ───────────────────────────────────────────────────────────
self.addEventListener('sync', (e) => {
  if (e.tag === 'ncsa-feed-sync') {
    e.waitUntil(syncFeed());
  }
});

async function getAdminToken() {
  return new Promise((resolve) => {
    const req = indexedDB.open('ncsaConfig', 1);
    req.onupgradeneeded = (e) => {
      e.target.result.createObjectStore('config');
    };
    req.onsuccess = (e) => {
      const db = e.target.result;
      try {
        const tx = db.transaction('config', 'readonly');
        const get = tx.objectStore('config').get('adminToken');
        get.onsuccess = () => resolve(get.result ?? null);
        get.onerror = () => resolve(null);
      } catch (_) {
        resolve(null);
      }
    };
    req.onerror = () => resolve(null);
  });
}

async function syncFeed() {
  const token = await getAdminToken();
  if (!token) return;
  await fetch('/admin/sync', {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}` },
  });
}
