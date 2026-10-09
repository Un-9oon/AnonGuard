/* Native Firefox site isolation. No telemetry or persistent browsing records. */
'use strict';
class CircuitIsolation {
  constructor(randomLabel, limit = 512) {
    this.randomLabel = randomLabel;
    this.limit = limit;
    this.contexts = new Map();
    this.failed = false;
  }
  site(url) {
    const parsed = new URL(url);
    if (!['https:', 'http:', 'wss:', 'ws:'].includes(parsed.protocol) ||
        !parsed.hostname || parsed.username || parsed.password) throw Error('Unsupported origin');
    return parsed.origin;
  }
  scope(details) {
    if (!Number.isInteger(details.tabId) || details.tabId < 0 ||
        typeof details.cookieStoreId !== 'string' || !details.cookieStoreId) throw Error('Unknown context');
    return JSON.stringify([details.tabId, details.cookieStoreId, !!details.incognito]);
  }
  topOrigin(details) {
    if (details.type === 'main_frame') {
      if (details.frameId !== 0 || details.parentFrameId !== -1) throw Error('Invalid top frame');
      return this.site(details.url);
    }
    // Firefox ESR 140 supplies frameAncestors, not documentId. Use the
    // browser-provided frame ancestry for nested requests, never a mutable tab
    // URL or a server-controlled Referer header. Old documents retain their own
    // ancestry during navigation, so they cannot migrate into the new context.
    if (!Number.isInteger(details.frameId) || details.frameId < 0 ||
        !Array.isArray(details.frameAncestors)) throw Error('Missing frame attribution');
    if (details.frameId === 0) {
      if (details.parentFrameId !== -1 || details.frameAncestors.length !== 0) throw Error('Invalid root ancestry');
      return this.site(details.documentUrl);
    }
    const roots = details.frameAncestors.filter(frame => frame.frameId === 0);
    if (roots.length !== 1 || details.frameAncestors.length > 64) throw Error('Unknown root document');
    return this.site(roots[0].url);
  }
  route(details) {
    if (this.failed) throw Error('Isolation unavailable');
    const scope = this.scope(details);
    this.site(details.url);
    const origin = this.topOrigin(details);
    const key = JSON.stringify([scope, origin]);
    let record = this.contexts.get(key);
    if (!record) {
      if (this.contexts.size >= this.limit) throw Error('Context bound');
      const label = this.randomLabel();
      if (!/^[0-9a-f]{64}$/.test(label)) throw Error('Invalid local label');
      record = {scope, label};
      this.contexts.set(key, record);
    }
    return [{type: 'socks', host: '127.0.0.1', port: 9050,
      username: record.label, password: 'anonguard-browser-v1', proxyDNS: true,
      connectionIsolationKey: record.label, failoverTimeout: 1}, null];
  }
  removeTab(tabId) {
    for (const [key, record] of this.contexts) {
      if (JSON.parse(record.scope)[0] === tabId) this.contexts.delete(key);
    }
  }
}
if (typeof module !== 'undefined') module.exports = CircuitIsolation;
