#!/usr/bin/env python3
"""p2_browser.py — ESCALADE probe (conditional branch from p3).

Allume le navigateur fingerprint-locked UNIQUEMENT si la phase statique n'a pas
extrait la config complète (bundles conditionnels, config opaque, anti-curl).
Trace chaque connexion hôte via le proxy CONNECT tracer (mitm_log.py) → Tor.

Usage standalone:
    python3 p2_browser.py <url> [--proxy http://127.0.0.1:8888] [--camofox http://localhost:9377] [--portrait 390x844]

Output: JSON findings list (compatible avec le module Argus).
"""
import json
import re
import sys
import time
import urllib.error
import urllib.request

DEFAULT_PROXY = "http://127.0.0.1:8888"
DEFAULT_CAMOFOX = "http://localhost:9377"


def _camofox(method: str, path: str, body: dict | None = None, base: str = DEFAULT_CAMOFOX) -> dict | list | str:
    url = base + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=180) as r:
            txt = r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}", "body": e.read().decode("utf-8", "replace")[:300]}
    try:
        return json.loads(txt)
    except Exception:
        return txt


def probe(url: str, proxy: str = DEFAULT_PROXY, camofox: str = DEFAULT_CAMOFOX,
          viewport: tuple[int, int] = (390, 844), hold_s: int = 20) -> list[dict]:
    findings: list[dict] = []
    ua = ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
          "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1")

    # 0) infra preflight
    health = _camofox("GET", "/health", base=camofox)
    if not (isinstance(health, dict) and health.get("ok")):
        return [{"key": "p2_browser_preflight", "value": f"camofox down @ {camofox}",
                 "extra": health if isinstance(health, dict) else {}}]
    tracer_up = _sock_up(proxy)
    findings.append({"key": "p2_preflight", "value": f"camofox ok, tracer={'up' if tracer_up else 'DOWN'}"})
    if not tracer_up:
        findings.append({"key": "p2_warning", "value": "proxy traceur down → connexions non loggées (le kit voit quand même le navigateur)"})

    # 1) create tab (portrait)
    r = _camofox("POST", "/tabs", {"userId": "argus-p2", "sessionKey": "f", "url": url,
                                   "userAgent": ua})
    tab = None
    if isinstance(r, dict) and r.get("tabId"):
        tab = r["tabId"]
        findings.append({"key": "p2_tab_created", "value": tab})
        # set viewport portrait (layout + screen spoofing handled by server patch)
        vp = _camofox("POST", f"/tabs/{tab}/viewport", {"userId": "argus-p2",
                                                        "width": viewport[0], "height": viewport[1]})
        findings.append({"key": "p2_viewport", "value": str(vp if not isinstance(vp, dict) else vp.get('ok', vp))})
    else:
        rerr = r.get("error") if isinstance(r, dict) else "unknown"
        findings.append({"key": "p2_tab_error", "value": str(rerr)})
        # SSL_ERROR_UNKNOWN = retry once (Tor circuit fresh)
        if "SSL" in str(rerr):
            time.sleep(10)
            r = _camofox("POST", "/tabs", {"userId": "argus-p2", "sessionKey": "f2", "url": url,
                                           "userAgent": ua})
            if isinstance(r, dict) and r.get("tabId"):
                tab = r["tabId"]
                findings.append({"key": "p2_tab_retry_ok", "value": tab})

    # 2) hold — let the kit run its gates / exfil attempts
    time.sleep(hold_s)

    # 3) collect final state
    if tab:
        tabs = _camofox("GET", "/tabs?userId=argus-p2")
        for t in (tabs.get("tabs", []) if isinstance(tabs, dict) else []):
            if t.get("tabId") == tab:
                findings.append({"key": "p2_final_url", "value": t.get("url", "?"),
                                 "extra": {"title": t.get("title", "")}})
                final = t.get("url", "")
                if "/emit/404" in final or "/404" in final:
                    findings.append({"key": "p2_boomerang_confirmed", "value": final})
    return findings


def _sock_up(proxy: str) -> bool:
    m = re.match(r"http://([^:/]+):(\d+)", proxy)
    if not m:
        return False
    import socket
    try:
        s = socket.create_connection((m.group(1), int(m.group(2))), timeout=5)
        s.close()
        return True
    except Exception:
        return False


if __name__ == "__main__":
    url = sys.argv[1]
    proxy = DEFAULT_PROXY
    camo = DEFAULT_CAMOFOX
    if "--proxy" in sys.argv:
        proxy = sys.argv[sys.argv.index("--proxy") + 1]
    if "--camofox" in sys.argv:
        camo = sys.argv[sys.argv.index("--camofox") + 1]
    res = probe(url, proxy=proxy, camofox=camo)
    print(json.dumps(res, indent=1, ensure_ascii=False))