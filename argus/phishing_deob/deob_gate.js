// Gate reproductible pour la signature PhaaS v3.14 (West263).
// Verifie les marqueurs comportementaux sur un bundle capture, sans le rejouer.
//
// Usage: node deob_gate.js <file.js>
// Exit 0 = signature confirmee, exit 1 = non (ou bundle illisible).
const fs = require('fs');
const path = require('path');

// Les marqueurs sont choisis pour etre NON fragmentables par l'obfuscateur:
// ce sont des NOMS de proprietes et des motifs de structure, pas des chaines
// de contenu (les contenus sont splittes en t(0,105) pour echapper a
// l'extraction statique). Chaque marqueur est un signal de comportement.
const MARKERS = [
  ['telegram_webapp',   /Telegram/,                         'Telegram WebApp bridge'],
  ['edge_ua_filter',    /Edg/,                             'filtre UA Edge/iOS'],
  ['messenger_fb',      /fban|fbav|messenger/,             'detection app Facebook'],
  ['clickshare',        /clickshare/,                      'module clickshare'],
  ['jp_domains',        /jpDomains/,                       'liste de domaines JP'],
  ['toast_popup',       /toast_popup_texts/,               'textes de popup'],
  ['postmessage',       /postMessage/,                     'canal postMessage (resize)'],
  ['project_key_obj',   /project:o,pjkey/,                 'objet {project, pjkey}'],
  ['run_progress',      /runProgress/,                     'machine a etats runProgress'],
  ['comment_panel',     /comment_panel/,                   'panneau commentaires (leurre)'],
  ['review_breathe',    /review-btn-breathe/,              'keyframes leurre "review"'],
  ['storage_key',       /getKey|setKey/,                   'cle de stockage persistee'],
];

const file = process.argv[2];
if (!file) { console.error('usage: node deob_gate.js <file.js>'); process.exit(2); }

let code;
try { code = fs.readFileSync(file, 'utf8'); } catch (e) {
  console.error('unreadable: ' + e.message);
  process.exit(2);            // distinct de 1: l'entree est invalide, pas le verdict
}

// Reject inputs that are not text before doing any work. A binary blob or an
// empty file is a caller error, not a "not confirmed" verdict -- conflating
// them would make a broken pipeline look like a clean negative result.
if (code.length === 0) {
  console.error('empty file: nothing to analyse');
  process.exit(2);
}
if (code.includes('\u0000')) {
  console.error('binary file (NUL byte detected): not analysable');
  process.exit(2);
}

// Meme extraction que deep_probe.js: tous les litteraux de chaine >= 12 chars.
const litRe = /"((?:[^"\\]|\\.){12,})"/g;
const literals = [];
let m;
while ((m = litRe.exec(code)) !== null) {
  let v;
  try { v = JSON.parse('"' + m[1] + '"'); } catch (e) { continue; }
  if (typeof v === 'string') literals.push(v);
}

const results = MARKERS.map(([id, re, desc]) => {
  const hits = literals.filter(s => re.test(s));
  return { id, desc, hit: hits.length > 0, count: hits.length, evidence: hits[0] ? hits[0].slice(0, 90) : null };
});

const passed = results.filter(r => r.hit).length;
const out = {
  file: path.basename(file),
  bytes: code.length,
  literals: literals.length,
  markersHit: passed,
  markersTotal: MARKERS.length,
  confirmed: passed >= 10,          // seuil: 10/12 (tolerance aux variantes de build)
  results,
};
fs.writeFileSync(path.join(path.dirname(file), 'deob_gate_' + out.file + '.json'), JSON.stringify(out, null, 2));

console.log('DEOB GATE  ' + out.file);
console.log('  literals: ' + out.literals + '   markers: ' + passed + '/' + MARKERS.length);
for (const r of results) {
  console.log('  ' + (r.hit ? 'HIT ' : 'MISS') + '  ' + r.id.padEnd(18) + ' (' + r.count + ')  ' + r.desc);
}
console.log('  VERDICT: ' + (out.confirmed ? 'CONFIRMED' : 'NOT CONFIRMED'));
process.exit(out.confirmed ? 0 : 1);
