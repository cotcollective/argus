// Decode vmb_502379 pools: base64 blobs XOR'd with the _$K key array.
// Usage: node vmb_decode.js <file.js> [outPrefix]
const fs = require('fs');
const vm = require('vm');

const srcPath = process.argv[2];
const outPrefix = process.argv[3] || (srcPath.replace(/\.js$/, '') + '_vmb');
const code = fs.readFileSync(srcPath, 'utf8');

// Grab the R blobs and the K key from the header (no full-module execution).
const rMatch = code.match(/\._\$R\s*=\s*\[([\s\S]*?)\]/);
const kMatch = code.match(/\._\$K\s*=\s*\[([\s\S]*?)\]/);
if (!rMatch || !kMatch) { console.error('no _$R / _$K header found'); process.exit(2); }

const blobs = vm.runInNewContext('[' + rMatch[1] + ']');
const key = vm.runInNewContext('[' + kMatch[1] + ']');

console.log('blobs: ' + blobs.length + '  key len: ' + key.length);

// blob0 + blob1 are concatenated in the header join, then decoded.
const b64 = blobs.join('');
const raw = Buffer.from(b64, 'base64');
console.log('decoded bytes: ' + raw.length);

// XOR round: the obfuscator XORs with key[i % key.length]; we try the
// straightforward pass first and check whether the result is JSON.
function xorPass(buf, k, offset) {
  const out = Buffer.alloc(buf.length);
  for (let i = 0; i < buf.length; i++) out[i] = buf[i] ^ k[(i + offset) % k.length];
  return out;
}

let best = null;
for (let off = 0; off < key.length; off++) {
  const cand = xorPass(raw, key, off);
  const head = cand.slice(0, 24).toString('latin1');
  if (head.trimStart().startsWith('[') || head.trimStart().startsWith('{') || head.trimStart().startsWith('"')) {
    const s = cand.toString('utf8');
    try {
      const parsed = JSON.parse(s);
      best = { off, parsed, s };
      break;
    } catch (e) { /* keep scanning */ }
  }
}

if (!best) {
  console.error('no offset produced parseable JSON; dumping first 80 bytes raw');
  console.error(JSON.stringify(raw.slice(0, 80).toString('latin1')));
  process.exit(3);
}

console.log('SUCCESS with key offset ' + best.off);
const parsed = best.parsed;
const arr = Array.isArray(parsed) ? parsed : null;
if (!arr) { console.error('parsed but not an array: ' + typeof parsed); process.exit(4); }

console.log('POOL LEN: ' + arr.length);
fs.writeFileSync(outPrefix + '_pool.json', JSON.stringify(arr));
console.log('saved -> ' + outPrefix + '_pool.json');

const re = /https?:|\/[a-z0-9_-]+\/|token|secret|project|tg|ws|api|collect|exfil|redirect|\.com|\.top|key/i;
const hits = arr.filter(x => typeof x === 'string' && re.test(x));
console.log('interesting strings: ' + hits.length + ' / ' + arr.length);
hits.forEach(s => console.log(' | ' + s));
