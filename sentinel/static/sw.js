/* Cache only the public offline shell and public design assets. Never API data or authenticated pages. */
const CACHE='sentinel-shell-v3';
const ASSETS=['/offline','/assets/sentinel.svg'];
self.addEventListener('install',event=>{event.waitUntil(caches.open(CACHE).then(cache=>cache.addAll(ASSETS)).then(()=>self.skipWaiting()));});
self.addEventListener('activate',event=>{event.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(key=>key.startsWith('sentinel-shell-')&&key!==CACHE).map(key=>caches.delete(key)))).then(()=>self.clients.claim()));});
self.addEventListener('fetch',event=>{
  if(event.request.method!=='GET'||new URL(event.request.url).origin!==self.location.origin)return;
  if(event.request.mode==='navigate'){event.respondWith(fetch(event.request).catch(()=>caches.match('/offline')));return;}
  if(ASSETS.includes(new URL(event.request.url).pathname))event.respondWith(fetch(event.request).catch(()=>caches.match(event.request)));
});
