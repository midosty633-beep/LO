const VERSION='mahami-notifications-v1';
self.addEventListener('install',event=>event.waitUntil(self.skipWaiting()));
self.addEventListener('activate',event=>event.waitUntil(self.clients.claim()));
self.addEventListener('notificationclick',event=>{
  event.notification.close();
  const target=new URL(event.notification?.data?.url || './', self.registration.scope).href;
  event.waitUntil((async()=>{
    const list=await clients.matchAll({type:'window',includeUncontrolled:true});
    for(const c of list){if('focus' in c){await c.focus(); if('navigate' in c && target) await c.navigate(target); return;}}
    if(clients.openWindow) await clients.openWindow(target);
  })());
});
