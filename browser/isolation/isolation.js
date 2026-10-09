/* No telemetry, stored browsing history or remote code. Native client only. */
'use strict';
class CircuitIsolation {
  constructor(randomLabel, limit = 2048) {
    this.randomLabel = randomLabel;
    this.limit = limit;
    this.documents = new Map();
    this.pending = new Map();
    this.failed = false;
  }
  site(url) {
    const parsed = new URL(url);
    if (!['https:', 'http:', 'wss:', 'ws:'].includes(parsed.protocol) ||
        !parsed.hostname || parsed.username || parsed.password) throw Error('Unsupported origin');
    return parsed.hostname;
  }
  scope(details) {
    if (!Number.isInteger(details.tabId) || details.tabId < 0 ||
        typeof details.cookieStoreId !== 'string' || !details.cookieStoreId) throw Error('Unknown context');
    return JSON.stringify([details.tabId, details.cookieStoreId, !!details.incognito]);
  }
  route(details) {
    if (this.failed) throw Error('Isolation unavailable');
    const scope = this.scope(details);
    this.site(details.url);
    let record;
    if (details.type === 'main_frame') {
      if (details.frameId !== 0) throw Error('Invalid top frame');
      // Every top-level navigation gets fresh credentials; redirects retain the
      // same requestId but must not carry credentials to a different hostname.
      const key = JSON.stringify([scope, details.requestId, this.site(details.url)]);
      record = this.pending.get(key);
      if (!record) {
        if (this.pending.size + this.documents.size >= this.limit) throw Error('Context bound');
        record = {scope, site: this.site(details.url), label: this.randomLabel()};
        this.pending.set(key, record);
      }
      // A committed document is bound only by its own request's identity below.
      if (details.documentId) this.bind(details.documentId, record);
    } else {
      const document = details.type === 'sub_frame' ? details.parentDocumentId : details.documentId;
      record = this.documents.get(document);
      if (!record || record.scope !== scope) throw Error('Unbound document');
      if (details.type === 'sub_frame' && details.documentId) this.bind(details.documentId, record);
    }
    return [{type: 'socks', host: '127.0.0.1', port: 9050,
      username: record.label, password: 'anonguard-browser-v1', proxyDNS: true,
      connectionIsolationKey: record.label, failoverTimeout: 1}, null];
  }
  bind(id, record) {
    if (typeof id !== 'string' || !id || id.length > 128) throw Error('Invalid document identity');
    const previous = this.documents.get(id);
    if (previous && previous !== record) throw Error('Document identity reused');
    if (!previous && this.pending.size + this.documents.size >= this.limit) throw Error('Document bound');
    this.documents.set(id, record);
  }
  removeTab(tabId) {
    for (const map of [this.documents, this.pending]) {
      for (const [key, value] of map) if (JSON.parse(value.scope)[0] === tabId) map.delete(key);
    }
  }
}
if (typeof module !== 'undefined') module.exports = CircuitIsolation;
