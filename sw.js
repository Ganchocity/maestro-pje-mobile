/**
 * Maestro PJe Mobile - Service Worker para suporte Offline no Android (v4)
 * Política:
 *  - Apenas requisições GET são interceptadas; mutações seguem direto para a rede.
 *  - Firestore API: estritamente Network-Only (nunca cacheado para evitar dados obsoletos).
 *  - Navegação / Share Target: Network-First com fallback para ./index.html.
 *  - Assets estáticos locais: Stale-While-Revalidate mantendo atualização automática silenciosa.
 */
const CACHE_NAME = 'maestro-pje-mobile-v9';
const ASSETS_TO_CACHE = [
  './',
  './index.html',
  './styles.css',
  './whatsapp-parser.js',
  './app.js',
  './manifest.json',
  './icon.svg'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => cache.addAll(ASSETS_TO_CACHE))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(
        keys.map((key) => {
          if (key !== CACHE_NAME) {
            return caches.delete(key);
          }
          return null;
        })
      ))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;

  // Mutações (POST, PATCH, DELETE, etc.) seguem direto para a rede sem cache
  if (!req || req.method !== 'GET') {
    return;
  }

  let reqUrl;
  try {
    reqUrl = new URL(req.url);
  } catch (e) {
    return;
  }

  // Firestore API: estritamente Network-Only (sem cache de respostas da nuvem)
  if (reqUrl.hostname.includes('firestore.googleapis.com')) {
    event.respondWith(fetch(req));
    return;
  }

  // Navegação e retorno do Share Target do Android (?shared_text=...)
  if (req.mode === 'navigate' || req.url.includes('shared_text=')) {
    event.respondWith(
      fetch(req).catch(() => caches.match('./index.html'))
    );
    return;
  }

  // Assets estáticos da mesma origem: Stale-While-Revalidate
  if (reqUrl.origin === self.location.origin) {
    event.respondWith(
      caches.open(CACHE_NAME).then((cache) =>
        cache.match(req).then((cachedResponse) => {
          const networkPromise = fetch(req)
            .then((networkResponse) => {
              if (networkResponse && networkResponse.status === 200 && networkResponse.type === 'basic') {
                cache.put(req, networkResponse.clone());
              }
              return networkResponse;
            })
            .catch(() => null);

          if (cachedResponse) {
            event.waitUntil(networkPromise);
            return cachedResponse;
          }

          return networkPromise.then((res) => res || Response.error());
        })
      )
    );
  }
});
