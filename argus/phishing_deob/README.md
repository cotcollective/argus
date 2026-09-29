# Phishing deob — PhaaS v3.14 (West263)

Outils d'analyse statique du kit PhaaS v3.14. Aucune requête n'est émise vers
les cibles : on travaille sur des bundles déjà capturés.

## Les outils

| Fichier | Rôle | Statut |
|---|---|---|
| `deob_gate.js` | **Gate reproductible.** Vérifie les 12 marqueurs comportementaux sur un bundle. Exit 0 = confirmé, 1 = non. | opérationnel, c'est le point d'entrée |
| `deep_probe.js` | Exécute le bundle dans un sandbox node à stubs profonds, extrait tous les littéraux et les blobs base64. | opérationnel |
| `pool_decode.js` | Exécute le module et exporte les tableaux de chaînes exposés au scope. | partiel — le pool est fermé dans une closure |
| `hook_decode.js` | Instrumente `String.prototype` / `JSON.parse` / `Array.push` dans le sandbox pour capter les chaînes résolues à l'exécution. | partiel — le payload attend une interaction utilisateur |
| `vmb_decode.js` | Décode les pools `vmb_502379._$R` (blobs base64) avec la clé `_$K`. | non applicable — l'algo n'est pas un XOR simple |

## Utiliser le gate

```bash
node argus/phishing_deob/deob_gate.js /chemin/vers/bundle.js
```

Sortie : `markers: N/12` puis `VERDICT: CONFIRMED|NOT CONFIRMED`.
Un rapport JSON est écrit à côté du bundle (`deob_gate_<nom>.json`).

## Pourquoi des marqueurs de comportement et pas de contenu

L'obfuscateur fragmente les chaînes de contenu pour échapper à l'extraction
statique : `"https://exemple/" + t(0,105) + "/chemin"` n'apparaît jamais en
entier dans le source. Toute extraction de contenu se heurte à ce mur.

Les 12 marqueurs retenus sont donc des **noms de propriétés et des motifs de
structure** — `clickshare`, `jpDomains`, `toast_popup_texts`, `project:o,pjkey`,
la keyframe leurre `review-btn-breathe` — que l'obfuscateur ne fragmente pas
parce que les property names ne passent pas par le décodeur de chaînes.

Conséquence : le gate mesure l'appartenance à une **famille de build**, pas à
une campagne. C'est la bonne granularité — c'est ce qu'on veut détecter.

## Validation du gate

| Bundle | Marqueur | Verdict |
|---|---|---|
| `v3_14_app.js` (cas de référence) | 12/12 | CONFIRMED |
| `galavs_app.js` (même famille) | 12/12 | CONFIRMED |
| `cashapp_app.js` (autre obfuscateur, pool 4750) | 6/12 | NOT CONFIRMED |
| HTML statique | 0/12 | NOT CONFIRMED |

Les contrôles négatifs sont ce qui rend le gate crédible : un test qui passe sur
tout ne teste rien. Le seuil est fixé à 10/12 pour absorber les variantes de
build sans perdre la discrimination.

### Taux de faux positif sur JS légitime

40 bundles réels (jQuery, TypeScript compiler, pyright 3,1 Mo, playwright,
xterm) passés au gate :

```
score max observe sur du JS legitime : 2/12
distribution : 2/12 -> 3   |   1/12 -> 8   |   0/12 -> 29
faux positifs (>=10/12)     : 0
```

Écart de 6× entre le max de la classe négative (2/12) et le seuil (10/12).
Le plus gros bundle du corpus (3,1 Mo) plafonne à 2/12 : le gate ne dégrade
pas avec la taille, parce qu'il compte des sous-chaînes de noms de propriétés
et non des occurrences pondérées par la fréquence.

### Cas négatif dur : un kit concurrent

Un kit rival qui **reconstruit le même leurre social-engineering** (review
carousel, toast, comment panel) et embarque les mêmes briques publiques
(pont Telegram WebApp, détecteur Facebook, `postMessage`, `localStorage`) :

| Cas rival | Score | Verdict |
|---|---|---|
| kit Telegram générique | 0/12 | NOT CONFIRMED |
| kit rival avec leurre décoré | 3/12 | NOT CONFIRMED |

C'est le test qui valide la granularité : les marqueurs discriminent
**l'opérateur**, pas la catégorie « kit de phishing Telegram ».

### Codes de sortie

| Code | Signification |
|---|---|
| 0 | famille confirmée |
| 1 | non confirmé (verdict négatif légitime) |
| 2 | entrée invalide (fichier absent, vide, binaire, argument manquant) |

Le 2 est distinct du 1 délibérément : un fichier vide doit échouer bruyamment
en CI, pas ressembler à un résultat négatif propre.

## Limites connues

- Le payload principal du kit ne s'exécute qu'après une interaction (clic,
  changement d'orientation). Les chaînes d'exfiltration restent donc inaccessibles
  en analyse statique — les 4 outils n'en récupèrent aucune.
- `hook_decode.js` capte 289 chaînes mais 1 seule exploitable : le reste du
  contenu passe par des chemins non instrumentés.
- Le décodage complet du pool exigerait d'émuler le click-path dans le sandbox,
  ce qui n'est pas implémenté.
