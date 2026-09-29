// Universal deep-stub sandbox: run a browser bundle in node and harvest
// every string pool / config object it materialises.
//
// Usage: node deep_probe.js <file.js> [outDir]
const fs = require('fs');
const vm = require('vm');
const path = require('path');

const srcPath = process.argv[2];
const outDir = process.argv[3] || ('/tmp/probe_' + path.basename(srcPath).replace(/\W+/g, '_'));
fs.mkdirSync(outDir, { recursive: true });
const code = fs.readFileSync(srcPath, 'utf8');

// A callable proxy that answers every property access with another proxy and
// every call with a fresh proxy. Real values are served for a few key names.
function makeStub(tag) {
  const target = function () { return makeStub(tag + '()'); };
  const handler = {
    get(t, prop) {
      if (prop === Symbol.toPrimitive || prop === 'toString') return () => '';
      if (prop === Symbol.iterator) return function* () {};
      if (prop === 'valueOf') return () => 0;
      if (prop === 'then') return undefined;          // don't look thenable
      if (prop === 'length') return 0;
      if (prop === 'constructor') return Object;
      return makeStub(tag + '.' + String(prop));
    },
    set() { return true; },
    apply() { return makeStub(tag + '()'); },
    construct() { return makeStub('new ' + tag); },
    has() { return true; },
  };
  return new Proxy(target, handler);
}

const realStrings = [];
const seen = new Set();

// Collect string arrays as they are created by patching Array.
const OrigArray = Array;
const sandbox = {
  console: { log(){}, warn(){}, error(){}, info(){}, debug(){}, trace(){} },
  TextDecoder, TextEncoder, Buffer, URL, URLSearchParams,
  setTimeout, clearTimeout, setInterval, clearInterval,
  process: { env: {} },
  crypto: { getRandomValues: (a) => { for (let i = 0; i < a.length; i++) a[i] = (i * 37) & 255; return a; } },
};
sandbox.globalThis = sandbox;
sandbox.window = sandbox;
sandbox.self = sandbox;
sandbox.top = sandbox;
sandbox.parent = sandbox;
sandbox.navigator = { userAgent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36',
                      language: 'en-US', languages: ['en-US'], platform: 'Linux x86_64', vendor: 'Google Inc.' };
sandbox.screen = { width: 1920, height: 1080, availWidth: 1920, availHeight: 1040, colorDepth: 24, pixelDepth: 24 };
sandbox.innerWidth = 1920; sandbox.innerHeight = 1080;
sandbox.outerWidth = 1920; sandbox.outerHeight = 1080;
sandbox.devicePixelRatio = 1;
sandbox.location = { href: 'https://example.invalid/', protocol: 'https:', host: 'example.invalid',
                     hostname: 'example.invalid', port: '', pathname: '/', search: '', hash: '', origin: 'https://example.invalid' };
sandbox.history = { replaceState(){}, pushState(){}, back(){}, go(){} };
sandbox.localStorage = { getItem: () => null, setItem(){}, removeItem(){}, clear(){}, key: () => null, length: 0 };
sandbox.sessionStorage = sandbox.localStorage;
sandbox.addEventListener = () => {};
sandbox.removeEventListener = () => {};
sandbox.dispatchEvent = () => true;
sandbox.requestAnimationFrame = (f) => { try { f(0); } catch (e) {} return 1; };
sandbox.cancelAnimationFrame = () => {};
sandbox.getComputedStyle = () => makeStub('css');
sandbox.matchMedia = () => ({ matches: false, addListener(){}, removeListener(){} });
sandbox.performance = { now: () => Date.now(), timing: {}, mark(){}, measure(){} };
sandbox.fetch = () => Promise.resolve(makeStub('resp'));
sandbox.XMLHttpRequest = function () { return makeStub('xhr'); };
sandbox.WebSocket = function () { return makeStub('ws'); };
sandbox.btoa = (s) => Buffer.from(String(s), 'binary').toString('base64');
sandbox.atob = (s) => Buffer.from(String(s), 'base64').toString('binary');
sandbox.Image = function () { return makeStub('img'); };
sandbox.ImageData = function () {};
sandbox.Worker = function () { return makeStub('worker'); };
sandbox.RTCPeerConnection = function () { return makeStub('rtc'); };
sandbox.MediaStream = function () { return makeStub('ms'); };
sandbox.AudioContext = function () { return makeStub('audio'); };
sandbox.Notification = function () { return makeStub('notif'); };
sandbox.alert = () => {}; sandbox.confirm = () => false; sandbox.prompt = () => null;

const docStub = makeStub('document');
sandbox.document = new Proxy(docStub, {
  get(t, prop) {
    if (prop === 'readyState') return 'complete';
    if (prop === 'cookie') return '';
    if (prop === 'referrer') return '';
    if (prop === 'URL') return 'https://example.invalid/';
    if (prop === 'location') return sandbox.location;
    return makeStub('document.' + String(prop));
  },
});
sandbox.window.document = sandbox.document;

// Interception: on every property read of the sandbox, if the value is a
// big string array, record it. We do this by scanning after execution AND by
// patching the source to export its own top-level consts.
let ran = false, err = null;
try {
  vm.createContext(sandbox);
  vm.runInContext(code, sandbox, { timeout: 30000 });
  ran = true;
} catch (e) { err = e; }

// Second pass: textual extraction of every [..., "long string", ...] literal
// plus every base64-looking literal -- catches pools that never got evaluated.
const litRe = /"((?:[^"\\]|\\.){12,})"/g;
let m, literals = [];
while ((m = litRe.exec(code)) !== null) {
  let v;
  try { v = JSON.parse('"' + m[1] + '"'); } catch (e) { continue; }
  if (typeof v === 'string') literals.push(v);
}

const decodeCandidates = [];
for (const s of literals) {
  if (/^[A-Za-z0-9+/]{40,}={0,2}$/.test(s)) {
    const buf = Buffer.from(s, 'base64');
    const txt = buf.toString('utf8');
    if (/^[[{]/.test(txt.trim()) || /[\u4e00-\u9fff]/.test(txt)) {
      decodeCandidates.push({ b64: s, text: txt });
    }
  }
}

const out = {
  file: srcPath,
  bytes: code.length,
  ranWholeModule: ran,
  moduleError: err ? String(err.message) : null,
  stringLiterals: literals.length,
  base64DecodedCandidates: decodeCandidates.length,
  pools: [],
};
fs.writeFileSync(path.join(outDir, 'literals.json'), JSON.stringify(literals));
fs.writeFileSync(path.join(outDir, 'decoded_b64.json'), JSON.stringify(decodeCandidates));

// Walk the sandbox for string arrays.
function harvest(obj, depth, prefix, outArr) {
  if (!obj || depth > 4 || outArr.length > 40) return;
  let keys;
  try { keys = Object.keys(obj); } catch (e) { return; }
  for (const k of keys) {
    if (k === 'globalThis' || k === 'window' || k === 'self' || k === 'top' || k === 'parent') continue;
    let v;
    try { v = obj[k]; } catch (e) { continue; }
    if (Array.isArray(v)) {
      if (v.length > 30 && v.slice(0, 50).every(x => typeof x === 'string')) {
        outArr.push({ name: prefix + k, len: v.length, sample: v.slice(0, 5) });
      }
    } else if (v && typeof v === 'object') {
      try { harvest(v, depth + 1, prefix + k + '.', outArr); } catch (e) {}
    }
  }
}
try { harvest(sandbox, 0, '', out.pools); } catch (e) {}

fs.writeFileSync(path.join(outDir, 'report.json'), JSON.stringify(out, null, 2));
console.log(JSON.stringify(out, null, 2));
console.log('outDir: ' + outDir);
