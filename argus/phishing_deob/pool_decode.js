// Decode a VM-obfuscator string pool by RUNNING the real accessor code.
// Usage: node pool_decode.js <file.js> [outPrefix]
const fs = require('fs');
const vm = require('vm');
const path = require('path');

const srcPath = process.argv[2];
const outPrefix = process.argv[3] || (srcPath.replace(/\.js$/, '') + '_pool');
const code = fs.readFileSync(srcPath, 'utf8');

// 1) locate the pool declaration and the accessor that indexes it
const declMatch = code.match(/(?:const|let|var)\s+(\w+)\s*=\s*\[/);
if (!declMatch) { console.error('no array decl found'); process.exit(2); }
const poolName = declMatch[1];

// find the pool's full extent by bracket matching from the opening '['
const openIdx = code.indexOf('[', declMatch.index);
let depth = 0, closeIdx = -1, inStr = false, q = '';
for (let i = openIdx; i < code.length; i++) {
  const ch = code[i];
  if (inStr) {
    if (ch === '\\') { i++; continue; }
    if (ch === q) inStr = false;
    continue;
  }
  if (ch === '"' || ch === "'" || ch === '`') { inStr = true; q = ch; continue; }
  if (ch === '[') depth++;
  else if (ch === ']') { depth--; if (depth === 0) { closeIdx = i; break; } }
}
const poolLiteral = code.slice(openIdx, closeIdx + 1);
let pool;
try { pool = vm.runInNewContext(poolLiteral); }
catch (e) { console.error('pool eval failed: ' + e.message); process.exit(3); }

// 2) slice the code right after the pool to find the shuffle/rotation helper
//    VM obfuscators use a IIFE that rotates the array until a checksum matches.
const after = code.slice(closeIdx + 1, closeIdx + 20000);

// 3) Build a sandbox where the whole module header (pool + rotator) is real code,
//    and we expose the rotator's resolved array. We run progressively larger prefixes
//    and harvest whatever the runtime exposes on the global/scope object.
function tryPrefix(endOffset) {
  const prefix = code.slice(0, endOffset);
  const ctx = { console, TextDecoder, TextEncoder, Buffer, setTimeout, clearTimeout };
  ctx.globalThis = ctx;
  ctx.window = ctx;
  try {
    return vm.runInNewContext(prefix, ctx, { timeout: 8000 });
  } catch (e) { return null; }
}

// Walk forward in chunks: after each chunk, look for a big string array that is
// NOT the original one (i.e. it has been rotated/decoded).
function findRotatedPool() {
  const step = 4000;
  const limit = Math.min(code.length, openIdx + 120000);
  for (let end = closeIdx + step; end < limit; end += step) {
    tryPrefix(end);
    // after execution, walk ctx for arrays of strings
    // (we re-run to grab the ctx object, not just the return value)
  }
  return null;
}

// Simpler + robust: instrument the module. We append a probe that scans
// the scope for string arrays via a Proxy-free brute force over known names.
const probe = `
;(function(){
  var found = [];
  function scan(obj, depth, prefix){
    if (!obj || depth > 3) return;
    var keys;
    try { keys = Object.keys(obj); } catch(e){ return; }
    for (var i=0;i<keys.length;i++){
      var k = keys[i];
      var v;
      try { v = obj[k]; } catch(e){ continue; }
      if (Array.isArray(v) && v.length > 50) {
        var allStr = v.length < 5 || (typeof v[0] === 'string');
        if (allStr) found.push({name: prefix+k, len: v.length, arr: v});
      } else if (v && typeof v === 'object' && depth < 2) {
        scan(v, depth+1, prefix+k+'.');
      }
    }
  }
  scan(this, 0, '');
  scan(typeof globalThis!=='undefined'?globalThis:this, 0, 'g.');
  globalThis.__FOUND__ = found;
})();
`;

// The module likely is an IIFE; run whole thing then probe from outside is useless.
// Instead: run whole module in a context, then probe that context.
const ctx = { console, TextDecoder, TextEncoder, Buffer, setTimeout, clearTimeout,
              setInterval, clearInterval, URL, URLSearchParams };
ctx.globalThis = ctx; ctx.window = ctx; ctx.self = ctx;
ctx.localStorage = { getItem: () => null, setItem: () => {}, removeItem: () => {}, clear: () => {} };
ctx.sessionStorage = ctx.localStorage;
ctx.document = {
  createElement: () => ({ style: {}, setAttribute(){}, appendChild(){}, addEventListener(){}, remove(){} }),
  getElementById: () => null, querySelector: () => null, querySelectorAll: () => [],
  body: { appendChild(){}, style: {}, addEventListener(){}, remove(){}, innerHTML: '', children: [] },
  head: { appendChild(){}, addEventListener(){} },
  documentElement: { style: {} },
  addEventListener: () => {},
  createEvent: () => ({ initEvent(){} }),
  readyState: 'complete',
};
ctx.navigator = { userAgent: 'Mozilla/5.0', language: 'en-US', languages: ['en-US'] };
ctx.screen = { width: 1920, height: 1080, availWidth: 1920, availHeight: 1040, colorDepth: 24 };
ctx.location = { href: 'https://x/', protocol: 'https:', hostname: 'x', host: 'x', pathname: '/', search: '', hash: '' };
ctx.history = { replaceState(){}, pushState(){} };
ctx.XMLHttpRequest = function(){ this.open=()=>{}; this.send=()=>{}; this.setRequestHeader=()=>{}; };
ctx.fetch = () => Promise.resolve({ ok:false, text:()=>Promise.resolve(''), json:()=>Promise.resolve({}) });
ctx.addEventListener = () => {};
ctx.requestAnimationFrame = (f) => setTimeout(f, 16);
ctx.innerWidth = 1920; ctx.innerHeight = 1080; ctx.outerWidth = 1920; ctx.outerHeight = 1080;
ctx.devicePixelRatio = 1;
ctx.Image = function(){}; ctx.ImageData = function(){};
ctx.MutationObserver = function(){ this.observe=()=>{}; this.disconnect=()=>{}; };
ctx.IntersectionObserver = function(){ this.observe=()=>{}; this.disconnect=()=>{}; };
ctx.WebSocket = function(){ this.send=()=>{}; this.close=()=>{}; this.addEventListener=()=>{}; };
ctx.btoa = (s) => Buffer.from(s, 'binary').toString('base64');
ctx.atob = (s) => Buffer.from(s, 'base64').toString('binary');

let ran = false, err = null;
try { vm.runInNewContext(code + probe, ctx, { timeout: 20000 }); ran = true; }
catch (e) { err = e; }

const found = ctx.__FOUND__ || [];
if (!found.length) {
  console.error('no string array exposed; ran=' + ran + ' err=' + (err && err.message));
  process.exit(4);
}

found.sort((a, b) => b.len - a.len);
for (const f of found) {
  const out = outPrefix + '_' + f.name.replace(/\W+/g, '_') + '.json';
  fs.writeFileSync(out, JSON.stringify(f.arr, null, 0));
  console.log('POOL ' + f.name + ' len=' + f.len + ' -> ' + out);
  // print a sample of interesting strings
  const hits = f.arr.filter(s => typeof s === 'string' &&
      /https?:|\/[a-z]+\/|token|key|secret|project|tg|ws|api|redirect|collect|exfil/i.test(s));
  console.log('  interesting: ' + hits.length + ' / ' + f.len);
  hits.slice(0, 40).forEach(s => console.log('   | ' + s));
}
