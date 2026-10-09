'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const CircuitIsolation = require('./isolation.js');
function fixture() {let counter = 0; return new CircuitIsolation(() => (++counter).toString(16).padStart(64, '0'));}
const main = {tabId: 1, cookieStoreId: 'firefox-default', incognito: false,
  type: 'main_frame', frameId: 0, parentFrameId: -1, frameAncestors: [],
  requestId: '1', url: 'https://example.com/'};
test('root resources and nested third parties inherit the browser-provided root', () => {
  const engine = fixture(); const first = engine.route(main);
  assert.deepEqual(first, engine.route({...main, type: 'script',
    documentUrl: main.url, url: 'https://cdn.example/script.js'}));
  const nested = {...main, type: 'image', frameId: 2, parentFrameId: 1,
    frameAncestors: [{frameId: 1, url: 'https://iframe.example/'}, {frameId: 0, url: main.url}],
    documentUrl: 'https://iframe.example/', url: 'https://cdn.example/img'};
  assert.deepEqual(first, engine.route(nested));
  assert.equal(first[0].proxyDNS, true); assert.equal(first[1], null);
  assert.equal(first[0].connectionIsolationKey, first[0].username);
});
test('sites, tabs, containers and private windows never share credentials', () => {
  const engine = fixture(); const first = engine.route(main)[0].username;
  for (const change of [{url: 'https://other.example/'}, {tabId: 2},
    {cookieStoreId: 'firefox-container-1'}, {incognito: true}]) {
    assert.notEqual(first, engine.route({...main, ...change})[0].username);
  }
  assert.equal(first, engine.route({...main, requestId: 'reload', url: 'https://example.com/next'})[0].username);
});
test('missing, ambiguous and malformed attribution refuses', () => {
  const engine = fixture();
  for (const change of [{type: 'image'}, {type: 'image', documentUrl: main.url, frameAncestors: undefined},
    {type: 'image', frameId: 1, parentFrameId: 0, frameAncestors: []},
    {type: 'image', frameId: 1, frameAncestors: [{frameId: 0,url:main.url},{frameId:0,url:main.url}]},
    {tabId: -1}, {cookieStoreId: undefined}, {url: 'file:///etc/passwd'},
    {url: 'https://user:pass@example.com/'}]) assert.throws(() => engine.route({...main,...change}));
});
test('old documents and redirects remain isolated during navigation', () => {
  const engine=fixture(); const first=engine.route(main);
  const next=engine.route({...main,url:'https://other.example/'});
  assert.notDeepEqual(first,next);
  assert.deepEqual(first,engine.route({...main,type:'image',documentUrl:main.url,url:'https://cdn.example/img'}));
});
test('bounds, disposal, RNG failure and fatal proxy errors fail closed', () => {
  const engine=fixture(); engine.limit=1; engine.route(main);
  assert.throws(()=>engine.route({...main,url:'https://other.example/'}));
  engine.removeTab(1); assert.equal(engine.contexts.size,0);
  engine.failed=true; assert.throws(()=>engine.route(main));
  assert.throws(()=>new CircuitIsolation(()=> 'bad').route(main));
});
test('browser listeners cancel unknown attribution without direct fallback', () => {
  const fs=require('node:fs'), vm=require('node:vm'), listeners={};
  const event=name=>({addListener:callback=>{listeners[name]=callback;}});
  const mock={proxy:{onRequest:event('proxy'),onError:event('error')},
    webRequest:{onBeforeRequest:event('request')},tabs:{onRemoved:event('removed')}};
  vm.runInNewContext(fs.readFileSync(require.resolve('./background.js'),'utf8'),
    {CircuitIsolation,crypto:require('node:crypto').webcrypto,browser:mock,Uint8Array});
  const route=listeners.proxy(main); assert.equal(route[0].port,9050);assert.equal(route[1],null);
  assert.equal(listeners.request({...main,type:'image'}).cancel,true);
  listeners.error();assert.equal(listeners.proxy(main)[0].port,9);
});
