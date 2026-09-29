"""Phishing kit recon module — kit-family fingerprint, not geo-labels.

Recon passif -> loader gate -> static JS decode -> crypto key extraction -> family match.
Case bootstrap + full worked example live in the private case archive (not in this repo).
"""

import base64
import hashlib
import json
import os
import random
import re
import string
import time
import urllib.error
import urllib.request

from argus.core.base import BaseModule, Finding
from argus.core.registry import Registry

UA_MOBILE = ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
             "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1")
UA_DESKTOP = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

# gate/decoy/boomerang markers seen in the wild
GATE_MARKERS = [r"availWidth\s*>\s*availHeight", r"availHeight\s*>\s*availWidth",
                r"top\.location\.href", r"location\.replace", r"document\.cookie"]
DECOY_PATHS = ["/emit/404", "/404", "/stop"]
PLATFORM_MAP_PAT = r"\{\s*whatsapp\s*:\s*\"ws\"\s*,\s*messenger\s*:\s*\"ms\""

# well-known obfuscator fingerprints
OBF_MARKERS = {
    "javascript-obfuscator": [r"javascript-obfuscator", r"_0x[a-f0-9]{4,6}\b"],
    "vm-custom": [r"vmb_\d+", r"\._\$R\b", r"\._\$K\b"],
    "jsfuck": [r"\[\]\[!\+\[\]\]"],
}

CF_TEMPLATE_SHA = "8fa3036c68bfcbd32365f6225d24333264093b7cd38d306e106b4dbdc934fd5b"


def _http(url, ua="mobile", timeout=30, method="GET", headers=None,
          proxy=None, max_bytes=2_000_000):
    """Generic HTTP. ua in {mobile, desktop, custom-string}. Returns (status, body, headers)."""
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    uagent = "custom" if ua not in ("mobile", "desktop") else ua
    real_ua = {"mobile": UA_MOBILE, "desktop": UA_DESKTOP}.get(uagent, ua)
    if proxy:
        handler = urllib.request.ProxyHandler({"http": proxy, "https": proxy})
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), handler)
    else:
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
    h = {"User-Agent": real_ua, "Accept": "*/*"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, headers=h, method=method)
    try:
        with opener.open(req, timeout=timeout) as r:
            body = r.read(max_bytes)
            return r.status, body, dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, (e.read(max_bytes) if e.fp else b""), dict(e.headers or {})
    except Exception as e:
        return -1, str(e).encode(), {}


def _is_gate_script(body: bytes) -> bool:
    """Cheap test: does the body look like a JS gate, not real content?"""
    if len(body) > 20_000:
        return False
    txt = body.decode("utf-8", "replace").lower()
    return any(re.search(p, txt) for p in GATE_MARKERS) and "<img" not in txt


def _decode_jsstrings_pool(js: bytes) -> list[str]:
    """Decode the obfuscateur string pool IN SOURCE ORDER (index-preserving).
    Returns list aligned to the pool indexes the wrappers use (2 shapes supported).
    Non-decodable entries are kept as '' so the indexing stays truthful."""
    txt = js.decode("utf-8", "replace")
    pool: list[str] = []
    ALPHA = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/="
    STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    tr = str.maketrans(ALPHA, STD)

    def b64s(s):
        t = s.translate(tr) + "=" * ((4 - len(s) % 4) % 4)
        try:
            raw = base64.b64decode(t)
        except Exception:
            return None
        try:
            d = raw.decode("utf-8")
        except Exception:
            d = raw.decode("latin-1")
        return d if (d and sum(ch.isprintable() for ch in d) / max(1, len(d)) > 0.8) else ""

    # shape (b): VM custom pool — const t=[...] big array (index-preserving)
    m2 = re.search(r"(?:const|var|let)\s+t\s*=\s*\[", txt)
    i = m2.start() if m2 else -1
    if i >= 0:
        j = txt.find("];", i)
        block = txt[i:j + 2]
        strings = re.findall(r'"([^"]*)"', block)
        pool = [b64s(s) or "" for s in strings]
        if pool:
            return pool
    # shape (a): javascript-obfuscator array _0x..., also index-preserving
    for m in re.finditer(r"\[(?:\"(?:[^\"\\\\]|\\\\.)*\",?\s*){20,}\]", txt):
        strings = re.findall(r'"([^"]*)"', m.group(0))
        p = [b64s(s) or "" for s in strings]
        if len(p) > 500:
            return p
    return pool


def _extract_static_keys(pool: list[str], js: bytes) -> list[str]:
    """Find constant-key candidates: fragments whose CONCAT is a secret key.
    (In today's kit: 'box_project_sec'+'ret_key_2025' = box_project_secret_key_2025)"""
    keys = set()
    for s in pool:
        if re.search(r"(?i)(key|secret|salt)", s) and 5 <= len(s) <= 48 and " " not in s:
            keys.add(s)
    # concatenation pattern from deob: n(2066)+n(1738) style — resolve via pool is complex;
    # instead: mark fragments that compose a known-style key (sec..ret, key..2025, etc.)
    txt = js.decode("utf-8", "replace")
    lit = set(m.group(1) for m in re.finditer(r'[a-zA-Z]\((\d{1,4})\)', txt[:200_000]))
    return sorted(keys)[:30]


def _ephemeral_token_check(url: str, n: int = 3, proxy=None) -> dict:
    """Fetch the same URL n times with same UA; compare bodies. Distinguish
    static page vs per-request token regeneration."""
    bodies = []
    for _ in range(n):
        st, body, _ = _http(url, ua="mobile", proxy=proxy)
        bodies.append(hashlib.sha256(body).hexdigest()[:16])
    uniq = set(bodies)
    return {"fetches": n, "unique_bodies": len(uniq),
            "ephemeral": len(uniq) > 1, "hashes": bodies[:6]}


def _resolve_wrapper_concats(js: bytes, pool: list[str]) -> list[str]:
    """Resolve  n(2066)+n(1738)  style wrapper concats.
    Mapping (validated on phaas_v3.14): wrapper says c(arg-K), pool master c(x)=raw[x-295],
    AND the raw array is ROTATED by k (checksum-derivable). Effective index = arg-K-295+k.
    We sweep (K, k) and validate key-like composed fragments."""
    txt = js.decode("utf-8", "replace")
    cand = set()
    N = len(pool)
    for m in re.finditer(r"\w+\((\d{1,4})\)\+\w+\((\d{1,4})\)", txt):
        a, b = int(m.group(1)), int(m.group(2))
        for K in range(60, 1000):
            for w in (295, 0):
                for k in (289, 0):     # known rotation constants (checksum-solver output)
                    ia = a - K - w + k
                    ib = b - K - w + k
                    if 0 <= ia < N and 0 <= ib < N and pool[ia] and pool[ib]:
                        comb = pool[ia] + pool[ib]
                        if 10 <= len(comb) <= 64 and re.fullmatch(r"(?i)[a-z0-9_]+", comb) \
                           and re.search(r"(?i)key|secret", comb):
                            cand.add(comb)
    # prioritize: length desc (longer composite = more specific) then alpha
    combs = sorted(cand, key=lambda s: (-len(s), s))[:50]
    # drop key-candidates that are just CSS/JS noise (contain css-like patterns)
    combs = [c for c in combs if not re.search(r"(keydown|keyframe|getKey|backgroundColor|webkit|measureText)", c)]
    # dedupe by suffix: 'ret_key_2025X' variants collapse to base
    final = []
    for c in combs:
        if not any(c.endswith(f) or f.endswith(c) for f in final):
            final.append(c)
    return final[:30]


def _correlate(pool: list[str], js: bytes, gate: dict, extra_text: str = "") -> tuple[str, float, list]:
    """Match against known kit families (seed: phaas_v3.14)."""
    txt = js.decode("utf-8", "replace") + "\n" + extra_text
    pool_txt = "\n".join(pool).lower()
    score = 0.0
    markers_hit = []
    # family phaas_v3.14 markers
    for marker, name, pts in [
        ("box_project_secret_key", "static-key box_project_secret_key", 0.30),
        ("vmb_", "obfuscateur VM custom", 0.15),
        ("beetools", "tracker BeeTools", 0.10),
        ("hm_lvt_", "cookies Baidu Tongji", 0.10),
        (".{3}[a-z0-9]{4}/[0-9a-f]{26}", "token format (path embed)", 0.05),
        ("comment_panel", "faux commentaires live", 0.10),
        ("toufangID", "trafic payant chinois", 0.10),
        ("/v1/api/?appid=", "exfil relatif", 0.10),
    ]:
        if marker.lower() in pool_txt or marker.lower() in txt.lower():
            score += pts
            markers_hit.append(name)
    fam = "phaas_v3.14" if score >= 0.5 else ("unknown" if score < 0.3 else "phaas-adjacent")
    return fam, min(score, 0.95), markers_hit


@Registry.register
class PhishingKitModule(BaseModule):
    name = "phishing"
    description = ("Phishing kit recon: gate/decoy detection, ephemeral tokens, "
                   "obfuscateur VM + string-pool decode, crypto keys, family match")
    input_type = "url"

    def run(self, target: str, **kw) -> list[Finding]:
        findings: list[Finding] = []
        proxy = kw.get("proxy")
        url = target if target.startswith("http") else "https://" + target
        host = re.sub(r"^[a-z]+://([^/]+).*", r"\1", url)

        # --- PHASE 0 PASSIF ---
        import socket
        try:
            ip = socket.gethostbyname(host)
            findings.append(Finding(self.name, target, "phase0_dns_a", ip))
        except Exception as e:
            findings.append(Finding(self.name, target, "phase0_dns_a", f"ERR {e}"))
        st, body, hdrs = _http(f"https://{host}/robots.txt", ua="mobile", proxy=proxy)
        rb_sha = hashlib.sha256(body).hexdigest()
        is_cf_template = rb_sha == CF_TEMPLATE_SHA
        findings.append(Finding(self.name, target, "phase0_robots",
                                f"HTTP {st} sha={rb_sha[:12]}",
                                {"cloudflare_template": is_cf_template}))
        # security.txt / llms.txt
        for pathf in ["/llms.txt", "/.well-known/security.txt"]:
            st2, b2, _ = _http(url.rstrip("/") + pathf, ua="mobile", proxy=proxy)
            if st2 in (200, 403):
                findings.append(Finding(self.name, target, f"phase0_{pathf}", f"HTTP {st2}"))

        # --- PHASE 1 LOADER ---
        st, body, hdrs = _http(url, ua="mobile", proxy=proxy)
        findings.append(Finding(self.name, target, "phase1_fetch", f"HTTP {st} {len(body)}o"))
        if st == 200:
            gate = {
                "is_js_gate": _is_gate_script(body),
                "platform_map": bool(re.search(PLATFORM_MAP_PAT, body.decode("utf-8", "replace"))),
                "decoy": any(d in body.decode("utf-8", "replace") for d in DECOY_PATHS),
            }
            if gate["is_js_gate"]:
                for k, v in gate.items():
                    if v:
                        findings.append(Finding(self.name, target, f"phase1_gate_{k}", str(v)))
                # extract redirect target: PREFER top.location.href (gate) over meta og:image
                lbody = body.decode("utf-8", "replace")
                m = re.search(r'top\.location\.href\s*=\s*"([^"]+)"', lbody)
                if not m:
                    m = re.search(r'location\.href\s*=\s*"(https?://[^"]+)"', lbody)
                if m and m.group(1) not in url:
                    findings.append(Finding(self.name, target, "phase1_redirect_target", m.group(1)))
                    # FOLLOW the redirect: the real kit lives there (boomerang chain)
                    redir = m.group(1)
                    st_r, body_r, _ = _http(redir, ua="mobile", proxy=proxy)
                    findings.append(Finding(self.name, target, "phase1_redirect_fetch",
                                            f"HTTP {st_r} {len(body_r)}o"))
                    if st_r == 200:
                        body = body_r  # analyse the shell SPA instead of the loader
                        url = redir
                        host = re.sub(r"^[a-z]+://([^/]+).*", r"\1", redir)
                        findings.append(Finding(self.name, target, "phase1_gate_decoy",
                                                "boomerang: kit on second node"))

            # --- ephemeral token test ---
            ep = _ephemeral_token_check(url, proxy=proxy)
            findings.append(Finding(self.name, target, "phase1_tokens",
                                    "ephemeral" if ep["ephemeral"] else "static-or-single",
                                    ep))

        # --- PHASE 3 STATIC JS ---
        js_urls = re.findall(r"src=[\"'](/static/js/[^\"']+)[\"']", body.decode("utf-8", "replace"))
        pool_total = []
        js_bodies = []          # raw bundles accumulated for correlation
        all_key_cands: set[str] = set()
        for ju in js_urls[:4]:
            absu = ju if ju.startswith("http") else f"https://{host}{ju}"
            st3, b3, _ = _http(absu, ua="mobile", proxy=proxy)
            if st3 != 200 or len(b3) < 500:
                continue
            findings.append(Finding(self.name, target, "phase3_bundle", f"{len(b3)}o {ju}"))
            js_bodies.append(b3)
            pool = _decode_jsstrings_pool(b3)
            if pool:
                pool_total.extend(pool)
                findings.append(Finding(self.name, target, "phase3_pool_decoded",
                                        f"{len(pool)} strings (alphabet pivote)"))
            keys = _extract_static_keys(pool, b3)
            wkeys = _resolve_wrapper_concats(b3, pool)
            all_key_cands.update(keys + wkeys)
            for k in (keys + wkeys)[:8]:
                findings.append(Finding(self.name, target, "phase3_static_key_candidate", k))
        # --- PHASE 4 CORREL --- (raw js accumulated + pool + resolved key candidates)
        key_cands = " ".join(sorted(all_key_cands))
        if js_bodies or pool_total:
            fam, score, hits = _correlate(pool_total, b"".join(js_bodies) if js_bodies else body,
                                          locals().get("gate", {}), extra_text=key_cands)
            findings.append(Finding(self.name, target, "phase4_family",
                                    f"{fam} conf={score:.2f}", {"markers": hits}))
            findings.append(Finding(self.name, target, "phase4_final_confidence",
                                    f"{score:.2f}", {"family": fam, "markers_count": len(hits)}))
        return findings