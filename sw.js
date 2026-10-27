// CryptoGuard AML Scanner Service Worker (Optimización para redes móviles y sin Wi-Fi)
const CACHE_NAME = 'cryptoscan-cache-v2.7';
const ASSETS_TO_CACHE = [
  './',
  './index.html',
  './styles.css?v=2.7',
  './app.js?v=2.7'
];

self.addEventListener('install', (event) => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(ASSETS_TO_CACHE).catch((err) => {
        console.warn('SW Precache warning:', err);
      });
    })
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.map((key) => {
          if (key !== CACHE_NAME) {
            return caches.delete(key);
          }
        })
      );
    }).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // Ignorar métodos que no sean GET y APIs dinámicas on-chain de blockchain
  if (
    event.request.method !== 'GET' ||
    url.hostname.includes('trongrid.io') ||
    url.hostname.includes('tronscan') ||
    url.hostname.includes('blockscout.com') ||
    url.hostname.includes('blockstream.info') ||
    url.hostname.includes('publicnode.com') ||
    url.hostname.includes('1rpc.io') ||
    url.hostname.includes('solana.com')
  ) {
    return;
  }

  // Estrategia Stale-While-Revalidate para archivos locales y assets estáticos
  event.respondWith(
    caches.match(event.request).then((cachedResponse) => {
      const fetchPromise = fetch(event.request).then((networkResponse) => {
        if (networkResponse && networkResponse.status === 200) {
          const responseToCache = networkResponse.clone();
          caches.open(CACHE_NAME).then((cache) => {
            cache.put(event.request, responseToCache);
          });
        }
        return networkResponse;
      }).catch(() => cachedResponse);

      return cachedResponse || fetchPromise;
    })
  );
});
