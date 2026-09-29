#!/usr/bin/env python3
"""Famille-hunt: remonte tout l'arbre de sous-domaines d'une campagne a partir de la
signature PhaaS (West263 + pattern de token path + pas de MX).

Les domaines de depart sont lus depuis la signature JSON -- pas de liste en dur ici,
donc ajouter un cas = editer la signature, jamais le code.

Sources: crt.sh (multi-query), CertSpotter API.
Lecture seule, aucune requete vers les cibles.
"""
import json
import os
import subprocess

SIG_PATH = os.path.join(os.path.dirname(__file__), "..", "phishing_signatures", "phaas_v3_14.json")


def load_seed_domains():
    with open(SIG_PATH, encoding="utf-8") as handle:
        sig = json.load(handle)
    return sorted(set(sig.get("confirmed_domains", [])))


def curl_json(url, timeout=40):
    try:
        out = subprocess.run(
            ["curl", "-s", "-m", str(timeout), url],
            capture_output=True, text=True, timeout=timeout + 5,
        )
        return json.loads(out.stdout)
    except Exception:
        return None


def crtsh_names(domain):
    rows = curl_json("https://crt.sh/?q=%25." + domain + "&output=json")
    if not rows:
        rows = curl_json("https://crt.sh/?q=" + domain + "&output=json")
    if not rows:
        return [], "crt.sh vide/rate"
    names = set()
    for row in rows:
        for raw in row.get("name_value", "").split("\n"):
            clean = raw.strip().lower().lstrip("*")
            if clean.endswith(domain):
                names.add(clean)
    return sorted(names), "OK"


def main():
    seeds = load_seed_domains()
    print("=" * 76)
    print("PHASE 0 PASSIF - CERT TRANSPARENCY - sous-domaines de campagne")
    print("seeds: " + str(len(seeds)) + " (depuis la signature)")
    print("=" * 76)

    found = {}
    for domain in seeds:
        names, src = crtsh_names(domain)
        found[domain] = sorted(names)
        line = "  " + domain.ljust(28) + " -> " + str(len(names)).rjust(3) + " certs/subs | " + src
        print(line)
        for name in names[:8]:
            print("      " + name)
        if len(names) > 8:
            print("      ... + " + str(len(names) - 8) + " autres")

    all_names = set()
    for values in found.values():
        all_names.update(values)
    print("")
    print("=== TOTAL noms uniques vus en CT: " + str(len(all_names)) + " ===")
    for name in sorted(all_names):
        print("  " + name)

    with open("/tmp/west263_ct_names.json", "w", encoding="utf-8") as handle:
        json.dump(found, handle, indent=1)
    print("")
    print("saved -> /tmp/west263_ct_names.json")


if __name__ == "__main__":
    main()