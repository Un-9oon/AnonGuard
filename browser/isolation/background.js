'use strict';
const isolation = new CircuitIsolation(() => {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(bytes, value => value.toString(16).padStart(2, '0')).join('');
});
// The managed browser's default proxy is an unavailable loopback endpoint.
// Never return a direct proxy or allow default-proxy fallback. A null final
// entry terminates the list, as specified by Mozilla's proxy.onRequest API.
const blocked = () => [{type: 'socks', host: '127.0.0.1', port: 9,
  proxyDNS: true, failoverTimeout: 1}, null];
browser.proxy.onRequest.addListener(details => {
  try { return isolation.route(details); }
  catch (_) { return blocked(); }
}, {urls: ['<all_urls>']});
// Blocking webRequest is a second guard: it also prevents navigation when
// origin/document attribution is unavailable. Never guess using destination,
// iframe host, a referrer or a mutable tab URL.
browser.webRequest.onBeforeRequest.addListener(details => {
  try { isolation.route(details); return {}; }
  catch (_) { return {cancel: true}; }
}, {urls: ['<all_urls>']}, ['blocking']);
browser.proxy.onError.addListener(() => { isolation.failed = true; });
browser.tabs.onRemoved.addListener(tab => isolation.removeTab(tab));
