// Service worker probe: reports navigator values from the service worker
// realm (spoofing extensions frequently do not patch it).
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));
self.addEventListener('message', (e) => {
  const n = self.navigator;
  e.ports[0].postMessage({
    userAgent: n.userAgent, platform: n.platform, language: n.language, languages: n.languages ? [...n.languages] : null,
    hardwareConcurrency: n.hardwareConcurrency, deviceMemory: n.deviceMemory,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
  });
});
