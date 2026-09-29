// Hook-based decoder: wrap String so that every obfuscator string that gets
// resolved at runtime is captured. Works even when the pool lives in a closure.
//
// Usage: node hook_decode.js <file.js> [outDir]
const fs = require('fs');
const vm = require('vm');
const path = require('path');

const srcPath = process.argv[2];
const outDir = process.argv[3] || ('/tmp/hook_' + path.basename(srcPath).replace(/\W+/g, '_'));
fs.mkdirSync(outDir, { recursive: true });
const code = fs.readFileSync(srcPath, 'utf8');

function makeStub(tag) {
  const target = function () { return makeStub(tag + '()'); };
  return new Proxy(target, {
    get(t, prop) {
      if (prop === Symbol.toPrimitive) return () => '';
      if (prop === 'toString') return () => '';
      if (prop === 'valueOf') return () => 0;
      if (prop === Symbol.iterator) return function* () {};
      if (prop === 'then') return undefined;
      if (prop === 'length') return 0;
      if (prop === 'constructor') return Object;
      if (prop === 'prototype') return undefined;
      return makeStub(tag + '.' + String(prop));
    },
    set() { return true; },
    apply() { return makeStub(tag + '()'); },
    construct() { return makeStub('new ' + tag); },
    has() { return true; },
  });
}

const captured = [];
const seen = new Set();
const HARVEST_RE = /https?:|\/\/[a-z0-9.-]+\/|[a-z0-9_-]{2,}\/[a-z0-9_\/-]{4,}|token|secret|project|\btg\b|\bws\b|api|collect|exfil|redirect|key|cookie|localStorage|sendBeacon|iframe/i;

// Wrap String so `String(x)`-style and string concat results get inspected.
// The obfuscator's accessor returns a primitive string, so we instead hook
// the point of use: patch String.prototype.concat, .replace, .split, and
// JSON.parse -- every resolved pool string passes through one of them.
const capturedAll = [];
function note(s) {
  if (typeof s !== 'string' || s.length < 4) return;
  if (seen.has(s)) return;
  seen.add(s);
  capturedAll.push(s);
}

const sb = {
  console: { log(){}, warn(){}, error(){}, info(){}, debug(){}, trace(){} },
  TextDecoder, TextEncoder, Buffer, URL, URLSearchParams,
  setTimeout, clearTimeout, setInterval, clearInterval,
  process: { env: {} },
  crypto: { getRandomValues: (a) => { for (let i = 0; i < a.length; i++) a[i] = (i * 37) & 255; return a; } },
};
sb.globalThis = sb; sb.window = sb; sb.self = sb; sb.top = sb; sb.parent = sb;
sb.navigator = { userAgent: 'Mozilla/5.0 (X11; Linux x86_64) Chrome/120', language: 'en-US',
                 languages: ['en-US'], platform: 'Linux x86_64' };
sb.screen = { width: 1920, height: 1080, availWidth: 1920, availHeight: 1040, colorDepth: 24 };
sb.innerWidth = 1920; sb.innerHeight = 1080; sb.outerWidth = 1920; sb.outerHeight = 1080;
sb.devicePixelRatio = 1;
sb.location = { href: 'https://example.invalid/', protocol: 'https:', host: 'example.invalid',
                hostname: 'example.invalid', pathname: '/', search: '', hash: '', origin: 'https://example.invalid' };
sb.history = { replaceState(){}, pushState(){} };
sb.localStorage = { getItem: () => null, setItem(){}, removeItem(){}, clear(){}, key: () => null, length: 0 };
sb.sessionStorage = sb.localStorage;
sb.addEventListener = () => {}; sb.removeEventListener = () => {};
sb.requestAnimationFrame = (f) => { try { f(0); } catch (e) {} return 1; };
sb.getComputedStyle = () => makeStub('css');
sb.matchMedia = () => ({ matches: false, addListener(){}, removeListener(){} });
sb.performance = { now: () => Date.now() };
sb.fetch = () => Promise.resolve(makeStub('resp'));
sb.btoa = (s) => { note(String(s)); return Buffer.from(String(s), 'binary').toString('base64'); };
sb.atob = (s) => { const r = Buffer.from(String(s), 'base64').toString('binary'); note(r); return r; };
sb.XMLHttpRequest = function () { return makeStub('xhr'); };
sb.WebSocket = function () { return makeStub('ws'); };
sb.Image = function () { return makeStub('img'); };
sb.ImageData = function () {};
sb.Worker = function () { return makeStub('worker'); };
sb.RTCPeerConnection = function () { return makeStub('rtc'); };
sb.MediaStream = function () { return makeStub('ms'); };
sb.AudioContext = function () { return makeStub('audio'); };
sb.Notification = function () { return makeStub('notif'); };
sb.alert = () => {}; sb.confirm = () => false; sb.prompt = () => null;
sb.document = new Proxy(makeStub('document'), {
  get(t, prop) {
    if (prop === 'readyState') return 'complete';
    if (prop === 'cookie') return '';
    if (prop === 'referrer') return '';
    if (prop === 'URL') return 'https://example.invalid/';
    if (prop === 'location') return sb.location;
    return makeStub('document.' + String(prop));
  },
});
sb.window.document = sb.document;

// Instrument the String prototype INSIDE the sandbox right after creation.
const HOOK = `
;(function(){
  var _origConcat = String.prototype.concat;
  String.prototype.concat = function(){
    for (var i = 0; i < arguments.length; i++) {
      var a = arguments[i];
      if (typeof a === 'string' && a.length >= 4) {
        try { (globalThis.__NOTE__)(a); } catch(e){}
      }
    }
    return _origConcat.apply(this, arguments);
  };
  var _origReplace = String.prototype.replace;
  String.prototype.replace = function(){
    var r = arguments[1];
    if (typeof r === 'string' && r.length >= 4) { try { (globalThis.__NOTE__)(r); } catch(e){} }
    return _origReplace.apply(this, arguments);
  };
  var _origSplit = String.prototype.split;
  String.prototype.split = function(){
    var r = _origSplit.apply(this, arguments);
    if (Array.isArray(r)) for (var i=0;i<r.length;i++) if (typeof r[i]==='string' && r[i].length>=4) { try { (globalThis.__NOTE__)(r[i]); } catch(e){} }
    return r;
  };
  var _origPush = Array.prototype.push;
  Array.prototype.push = function(){
    for (var i=0;i<arguments.length;i++) if (typeof arguments[i]==='string' && arguments[i].length>=4) { try { (globalThis.__NOTE__)(arguments[i]); } catch(e){} }
    return _origPush.apply(this, arguments);
  };
  var _origJSONparse = JSON.parse;
  JSON.parse = function(t, rev){
    try { var v = _origJSONparse(t, rev); if (Array.isArray(v)) { for (var i=0;i<v.length;i++) if (typeof v[i]==='string') { try { (globalThis.__NOTE__)(v[i]); } catch(e){} } } return v; } catch(e){ throw e; }
  };
})();
`;
sb.__NOTE__ = note;

let ran = false, err = null;
try {
  vm.createContext(sb);
  vm.runInContext(HOOK, sb, { timeout: 10000 });
  vm.runInContext(code, sb, { timeout: 40000 });
  ran = true;
} catch (e) { err = e; }

fs.writeFileSync(path.join(outDir, 'captured.json'), JSON.stringify(capturedAll, null, 1));
const interesting = capturedAll.filter(s => HARVEST_RE.test(s));
fs.writeFileSync(path.join(outDir, 'interesting.json'), JSON.stringify(interesting, null, 1));

console.log('ran: ' + ran + (err ? ('  err: ' + err.message) : ''));
console.log('captured strings: ' + capturedAll.length);
console.log('interesting: ' + interesting.length);
console.log('outDir: ' + outDir);
interesting.slice(0, 120).forEach(s => console.log(' | ' + s));
