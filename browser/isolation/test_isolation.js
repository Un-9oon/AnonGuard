'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const CircuitIsolation = require('./isolation.js');
function fixture() {
  let counter = 0;
  return new CircuitIsolation(() => (++counter).toString(16).padStart(64, '0'));
}
const main = {tabId: 1, cookieStoreId: 'firefox-default', incognito: false,
  type: 'main_frame', frameId: 0, requestId: '1', documentId: 'root', url: 'https://example.com/'};
test('third-party frames and resources retain owning document context', () => {
  const engine = fixture();
  const first = engine.route(main);
  const iframe = engine.route({...main, type: 'sub_frame', frameId: 1,
    parentDocumentId: 'root', documentId: 'child', requestId: '2', url: 'https://third.example/'});
  const image = engine.route({...main, type: 'image', frameId: 1, documentId: 'child', url: 'https://cdn.example/img'});
  assert.deepEqual(first, iframe);
  assert.deepEqual(first, image);
  assert.equal(first[0].proxyDNS, true);
  assert.equal(first[1], null);
  assert.equal(first[0].connectionIsolationKey, first[0].username);
});
test('navigation, tabs and containers never share credentials', () => {
  const engine = fixture();
  const first = engine.route(main)[0].username;
  for (const change of [{requestId: '2', documentId: 'next'},
    {tabId: 2, documentId: 'tab'}, {cookieStoreId: 'firefox-container-1', documentId: 'container'},
    {incognito: true, documentId: 'private'}]) {
    assert.notEqual(first, engine.route({...main, ...change})[0].username);
  }
});
test('missing document, cross-tab attribution and malformed targets refuse', () => {
  const engine = fixture(); engine.route(main);
  for (const change of [{type: 'image', documentId: undefined},
    {type: 'image', tabId: 2}, {type: 'image', cookieStoreId: undefined},
    {tabId: -1}, {url: 'file:///etc/passwd'}, {url: 'https://user:pass@example.com/'}]) {
    assert.throws(() => engine.route({...main, ...change}));
  }
});
test('redirect hostname and document identity reuse cannot cross contexts', () => {
  const engine = fixture(); const first = engine.route({...main, documentId: undefined})[0].username;
  assert.notEqual(first, engine.route({...main, documentId: undefined, url: 'https://other.example/'} )[0].username);
  engine.route(main);
  assert.throws(() => engine.route({...main, requestId: '2'}));
});
test('bounds, tab disposal and fatal proxy errors fail closed', () => {
  const engine = fixture(); engine.limit = 2; engine.route(main);
  assert.throws(() => engine.route({...main, requestId: '2', documentId: 'next'}));
  engine.removeTab(1);
  assert.equal(engine.documents.size, 0); assert.equal(engine.pending.size, 0);
  engine.failed = true; assert.throws(() => engine.route(main));
});
test('browser listeners cancel unknown attribution and never return direct fallback', () => {
  const fs = require('node:fs'); const vm = require('node:vm');
  const listeners = {};
  const event = name => ({addListener: callback => {listeners[name] = callback;}});
  const mock = {proxy: {onRequest: event('proxy'), onError: event('error')},
    webRequest: {onBeforeRequest: event('request')}, tabs: {onRemoved: event('removed')}};
  vm.runInNewContext(fs.readFileSync(require.resolve('./background.js'), 'utf8'),
    {CircuitIsolation, crypto: require('node:crypto').webcrypto, browser: mock, Uint8Array});
  const route = listeners.proxy(main);
  assert.equal(route[0].port, 9050); assert.equal(route[1], null);
  assert.equal(route[0].username.length, 64);
  assert.equal(listeners.request({...main, type: 'image', documentId: undefined}).cancel, true);
  assert.equal(listeners.proxy({...main, tabId: -1})[0].port, 9);
  listeners.error(); assert.equal(listeners.proxy(main)[0].port, 9);
});
