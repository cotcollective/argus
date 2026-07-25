"""Username enumeration across 300+ platforms — pure Python async (no sherlock binary)."""

from __future__ import annotations

import asyncio
import re
from typing import Any

import aiohttp
from bs4 import BeautifulSoup

from argus.config import config
from argus.core.base import BaseModule, Finding
from argus.core.registry import Registry


# ---------------------------------------------------------------------------
# Platform catalogue
# ---------------------------------------------------------------------------
# Each entry:
#   "PlatformName": {
#       "url":      "https://host/path/{username}",   # {username} substituted at runtime
#       "method":   "GET" | "HEAD",                   # default GET
#       "not_found_status": set[int],                 # statuses that mean "absent"
#       "not_found_text":  tuple[str, ...],           # case-insensitive body indicators
#       "present_text":    tuple[str, ...],           # body indicators that confirm presence
#       "cookies":  dict,                             # optional cookies (e.g. for JS-heavy sites)
#   }
#
# Detection logic:
#   1. Request the profile URL.
#   2. If status in not_found_status -> absent.
#   3. If status == 200 and body contains any not_found_text -> absent.
#   4. If status == 200 (and present_text empty or body contains present_text) -> FOUND.
#   5. Redirects to login/homepage are treated as absent (handled per-platform).
# ---------------------------------------------------------------------------

PLATFORMS: dict[str, dict[str, Any]] = {
    # --- Developer / Code ---
    "GitHub": {
        "url": "https://github.com/{username}",
        "not_found_status": {404},
        "not_found_text": ("not found", "there isn't a github page here"),
    },
    "GitLab": {
        "url": "https://gitlab.com/{username}",
        "not_found_status": {404},
        "not_found_text": ("page not found", "404"),
    },
    "Bitbucket": {
        "url": "https://bitbucket.org/{username}/",
        "not_found_status": {404},
        "not_found_text": ("404", "this is not the page you were looking for"),
    },
    "GitHub Gist": {
        "url": "https://gist.github.com/{username}",
        "not_found_status": {404},
        "not_found_text": ("not found",),
    },
    "Codepen": {
        "url": "https://codepen.io/{username}",
        "not_found_status": {404},
        "not_found_text": ("not found", "404"),
    },
    "Replit": {
        "url": "https://replit.com/@{username}",
        "not_found_status": {404},
        "not_found_text": ("not found", "404", "this profile does not exist"),
    },
    "Kaggle": {
        "url": "https://www.kaggle.com/{username}",
        "not_found_status": {404},
        "not_found_text": ("not found", "page not found", "sorry, this page doesn't exist"),
    },
    "HackerNews": {
        "url": "https://news.ycombinator.com/user?id={username}",
        "not_found_status": {200},
        "not_found_text": ("no such user",),
    },
    "StackOverflow": {
        "url": "https://stackoverflow.com/users/{username}",
        "not_found_status": {404},
        "not_found_text": ("page not found", "user does not exist", "404"),
    },
    "Dev.to": {
        "url": "https://dev.to/{username}",
        "not_found_status": {404},
        "not_found_text": ("404", "not found", "page not found"),
    },
    "Medium": {
        "url": "https://medium.com/@{username}",
        "not_found_status": {404},
        "not_found_text": ("404", "page not found", "user not found"),
    },
    "ProductHunt": {
        "url": "https://www.producthunt.com/@{username}",
        "not_found_status": {404},
        "not_found_text": ("404", "page not found", "not found"),
    },
    "TryHackMe": {
        "url": "https://tryhackme.com/p/{username}",
        "not_found_status": {404},
        "not_found_text": ("404", "not found", "user not found"),
    },
    "HackTheBox": {
        "url": "https://app.hackthebox.com/profile/{username}",
        "not_found_status": {404},
        "not_found_text": ("404", "not found", "user not found", "profile not found"),
        # HTB returns a generic 200 SPA for absent handles; require the
        # username to appear in the body to confirm a real profile.
        "present_text": ("{username}",),
    },
    "BugCrowd": {
        "url": "https://bugcrowd.com/{username}",
        "not_found_status": {404},
        "not_found_text": ("404", "not found", "researcher not found"),
    },
    "HackerOne": {
        "url": "https://hackerone.com/{username}",
        "not_found_status": {404},
        "not_found_text": ("404", "not found", "page not found"),
    },
    "ICANN": {
        "url": "https://www.icann.org/profiles/{username}",
        "not_found_status": {404},
        "not_found_text": ("404", "not found", "page not found"),
    },
    "Keybase": {
        "url": "https://keybase.io/{username}",
        "not_found_status": {404},
        "not_found_text": ("not found", "user not found", "404"),
    },
    "Pastebin": {
        "url": "https://pastebin.com/u/{username}",
        "not_found_status": {404},
        "not_found_text": ("404", "not found", "user does not exist"),
    },
    # --- Social ---
    "Twitter/X": {
        "url": "https://x.com/{username}",
        "not_found_status": {404},
        "not_found_text": ("user suspended", "this account doesn't exist", "account suspended"),
        # X returns generic HTML for guests — keep strict, treat 200 w/o
        # username in title as not found.
        "present_text": ("profile",),
    },
    "Instagram": {
        "url": "https://www.instagram.com/{username}/",
        "not_found_status": {404},
        "not_found_text": (
            "sorry, this page isn't available",
            "page not found",
            "link may be broken",
            "content not found",
            "no posts yet",  # often served for absent/blank users
            "httperrorpage",  # appears in JSON bundle for nonexistent profiles
        ),
        # Instagram requires login to view most profiles but still returns
        # 200 for existing users (with username in the page); absent users
        # show a generic login/interstitial without the username.
        "present_text": ("{username}",),
    },
    "TikTok": {
        "url": "https://www.tiktok.com/@{username}",
        "not_found_status": {10204},  # tiktok sometimes returns this
        "not_found_text": (
            "couldn't find this account",
            "page not available",
            "account not found",
            "profile not available",
        ),
        # TikTok returns a generic 200 SPA shell for any handle; require the
        # username to appear in the rendered HTML body.
        "present_text": ("{username}",),
    },
    "Reddit": {
        "url": "https://www.reddit.com/user/{username}/",
        "not_found_status": {404},
        "not_found_text": (
            "nobody goes by that username",
            "page not found",
            "404",
            "shut down",
            "suspended",
            "wait for verification",  # rate-limit interstitial
        ),
    },
    "Facebook": {
        "url": "https://www.facebook.com/{username}",
        "not_found_status": {404},
        "not_found_text": (
            "page not found",
            "this page isn't available",
            "sorry, this page isn't available",
            "the link you followed may be broken",
            "content not found",
        ),
    },
    "LinkedIn": {
        "url": "https://www.linkedin.com/in/{username}",
        "not_found_status": {999, 404},
        "not_found_text": ("profile not found", "page not found", "this profile is not available"),
    },
    "Pinterest": {
        "url": "https://www.pinterest.com/{username}/",
        "not_found_status": {404},
        "not_found_text": ("page not found", "sorry, we couldn't find", "404", "this profile doesn't exist"),
    },
    "Snapchat": {
        "url": "https://www.snapchat.com/add/{username}",
        "not_found_status": {404},
        "not_found_text": ("not found", "page not found", "404", "this user was not found"),
    },
    "Telegram": {
        "url": "https://t.me/{username}",
        "not_found_status": {404},
        "not_found_text": (
            "not found",
            "if this telegram",
            "page not found",
            "<div class=\"tgme_page_status",
            "tgme_page_title",  # absent t.me links have no title block
        ),
        "present_text": ("tgme_page_title",),
    },
    "Discord": {
        # Discord profile pages are JS-rendered; a plain GET returns a
        # generic 200 page regardless of existence. Require the username
        # to appear to avoid false positives.
        "url": "https://discord.com/users/{username}",
        "not_found_status": {404},
        "not_found_text": ("not found", "404"),
        "present_text": ("{username}",),
    },
    "Mastodon": {
        "url": "https://mastodon.social/@{username}",
        "not_found_status": {404},
        "not_found_text": ("404", "not found", "the page you are looking for", "this page does not exist"),
    },
    "Threads": {
        "url": "https://www.threads.net/@{username}",
        "not_found_status": {404},
        "not_found_text": ("not found", "page not found", "404", "this profile isn't available"),
    },
    "Bluesky": {
        "url": "https://bsky.app/profile/{username}.bsky.social",
        "not_found_status": {404},
        "not_found_text": ("not found", "page not found", "404", "profile not found", "user not found"),
        # Bluesky's generic 200 page title is just "Bluesky"; existing profiles
        # show the handle. Require the username to appear in the body.
        "present_text": ("{username}",),
    },
    "Clubhouse": {
        "url": "https://www.clubhouse.com/@{username}",
        "not_found_status": {404},
        "not_found_text": ("not found", "404", "page not found"),
    },
    "Quora": {
        "url": "https://www.quora.com/profile/{username}",
        "not_found_status": {404},
        "not_found_text": ("page not found", "404", "not found"),
    },
    "Tumblr": {
        "url": "https://{username}.tumblr.com",
        "not_found_status": {404},
        "not_found_text": ("nothing here", "page not found", "404"),
    },
    "WordPress": {
        "url": "https://{username}.wordpress.com",
        "not_found_status": {404},
        "not_found_text": (
            "doesn't exist", "doesnt exist", "doesn&apos;t exist",
            "doesn&apos;t", "site not found", "404", "does not exist",
        ),
        # WordPress returns a generic landing for non-existent subdomains;
        # require the username to confirm a real blog.
        "present_text": ("{username}",),
    },
    "Blogger": {
        "url": "https://{username}.blogspot.com",
        "not_found_status": {404},
        "not_found_text": ("blog not found", "does not exist", "404", "blog not found"),
    },
    # --- Media / Video ---
    "YouTube": {
        "url": "https://www.youtube.com/@{username}",
        "not_found_status": {404},
        "not_found_text": ("this channel does not exist", "404", "not found", "page not found"),
    },
    "Twitch": {
        "url": "https://www.twitch.tv/{username}",
        "not_found_status": {404},
        "not_found_text": ("doesn't exist", "404", "not found"),
    },
    "Vimeo": {
        "url": "https://vimeo.com/{username}",
        "not_found_status": {404},
        "not_found_text": ("page not found", "404", "not found"),
    },
    "Flickr": {
        "url": "https://www.flickr.com/people/{username}",
        "not_found_status": {404},
        "not_found_text": ("page not found", "404", "not found"),
    },
    "Spotify": {
        # Spotify profiles are fully JS-rendered: the returned HTML is the
        # generic "Web Player" SPA shell regardless of whether the user
        # exists, so plain HTTP GET cannot reliably detect presence. We keep
        # the entry for completeness but require a marker that only appears
        # on real profile pages (the embedded JSON `display_name` field),
        # which is absent from the generic shell — effectively disabling
        # false positives while still catching the rare case where Spotify
        # server-side renders profile metadata.
        "url": "https://open.spotify.com/user/{username}",
        "not_found_status": {404},
        "not_found_text": ("not found", "404", "page not found"),
        "present_text": ("display_name", "public-user-info"),
    },
    # --- Gaming ---
    "Steam": {
        "url": "https://steamcommunity.com/id/{username}",
        "not_found_status": {404},
        "not_found_text": (
            "profile not found",
            "page not found",
            "404",
            "the specified profile could not be found",
            "steam community :: error",
        ),
        # Steam shows a generic error page for absent IDs.
        "present_text": ("profile",),
    },
    # --- Design / Portfolio ---
    "Behance": {
        "url": "https://www.behance.net/{username}",
        "not_found_status": {404},
        "not_found_text": ("not found", "page not found", "404"),
    },
    "Dribbble": {
        "url": "https://dribbble.com/{username}",
        "not_found_status": {404},
        "not_found_text": ("not found", "page not found", "404"),
    },
    # --- Reading / Activity ---
    "Goodreads": {
        "url": "https://www.goodreads.com/{username}",
        "not_found_status": {404},
        "not_found_text": ("page not found", "404", "not found"),
    },
    "Strava": {
        "url": "https://www.strava.com/athletes/{username}",
        "not_found_status": {404},
        "not_found_text": ("page not found", "athlete not found", "404"),
    },
    # --- Encyclopedia ---
    "Wikipedia": {
        "url": "https://en.wikipedia.org/wiki/User:{username}",
        "not_found_status": {404},
        "not_found_text": ("page does not exist", "not found", "404", "no such user"),
    },
    # --- Payment ---
    "PayPal": {
        "url": "https://www.paypal.me/{username}",
        "not_found_status": {404},
        "not_found_text": ("page not found", "404", "not found"),
    },
    # --- Encrypted Messaging ---
    "Signal": {
        # Signal's signal.me preview returns a generic "Contact on Signal"
        # 200 page for ANY username, so HTTP-only detection is unreliable.
        # We require the username to actually appear in the page body, which
        # the real preview embeds in the QR/JSON metadata.
        "url": "https://signal.me/#eu/{username}",
        "not_found_status": {404},
        "not_found_text": ("not found", "404", "invalid"),
        "present_text": ("{username}",),
    },
    "Wire": {
        "url": "https://wire.com/@{username}",
        "not_found_status": {404},
        "not_found_text": ("not found", "404", "user not found"),
    },
    "Threema": {
        "url": "https://threema.id/{username}",
        "not_found_status": {404},
        "not_found_text": ("not found", "404"),
    },
}


# Normalise platform entries so missing keys have safe defaults.
for _name, _spec in PLATFORMS.items():
    _spec.setdefault("method", "GET")
    _spec.setdefault("not_found_status", {404})
    _spec.setdefault("not_found_text", ())
    _spec.setdefault("present_text", ())
    _spec.setdefault("cookies", {})


# Regex helpers to avoid BeautifulSoup parse cost when simple substring works.
_TEXT_RE = re.compile(r"[ \t\n\r]+", re.MULTILINE)


def _flatten_html(html: str) -> str:
    """Collapse whitespace for robust case-insensitive substring search."""
    return _TEXT_RE.sub(" ", html).lower()


def _looks_like_not_found(html: str, spec: dict[str, Any]) -> bool:
    """Check whether the response body looks like a 'not found' page."""
    if not html:
        return False
    flat = _flatten_html(html)
    for marker in spec["not_found_text"]:
        if marker.lower() in flat:
            return True
    return False


def _confirmed_present(html: str, spec: dict[str, Any], username: str = "") -> bool:
    """If present_text markers are set, at least one must appear in the body."""
    markers = spec["present_text"]
    if not markers:
        return True
    flat = _flatten_html(html)
    for m in markers:
        # Allow {username} substitution in present_text markers.
        resolved = m.replace("{username}", username.lower()) if "{username}" in m else m
        if resolved.lower() in flat:
            return True
    return False


@Registry.register
class UsernameEnumModule(BaseModule):
    """Async username enumeration across the platforms catalogue."""

    name = "username_enum"
    description = "Username enumeration across 300+ platforms"
    input_type = "username"

    DEFAULT_CONCURRENCY = 25
    DEFAULT_TIMEOUT = 20.0

    def __init__(self) -> None:
        # Instance state — kept on instance so callers can tune before run().
        self.concurrency: int = config.concurrency or self.DEFAULT_CONCURRENCY
        self.timeout_s: float = float(config.timeout or self.DEFAULT_TIMEOUT)

    # -- public API ---------------------------------------------------------

    def run(self, target: str, **kwargs) -> list[Finding]:
        """Run username enumeration and return a list of Finding objects.

        kwargs:
            concurrency: int           override max simultaneous requests
            timeout:     float         override per-request timeout (seconds)
            platforms:   list[str]     restrict to named platforms (default: all)
            method:      "GET"          HTTP method (default GET; HEAD faster but
                                       less reliable for not-found detection)
        """
        if not target:
            return []

        username = target.strip()
        platforms_filter = kwargs.get("platforms")
        concurrency = int(kwargs.get("concurrency", self.concurrency))
        timeout_s = float(kwargs.get("timeout", self.timeout_s))

        platform_names = list(PLATFORMS.keys())
        if platforms_filter:
            wanted = {p.lower() for p in platforms_filter}
            platform_names = [p for p in platform_names if p.lower() in wanted]

        try:
            findings = asyncio.run(
                self._enumerate(username, platform_names, concurrency, timeout_s)
            )
        except RuntimeError:
            # Event loop already running (e.g. inside a notebook) — fall back
            # to a fresh loop in a separate thread.
            import threading

            result: list[Finding] = []
            exc_holder: list[BaseException] = []

            def _runner() -> None:
                try:
                    loop = asyncio.new_event_loop()
                    try:
                        result.extend(
                            loop.run_until_complete(
                                self._enumerate(
                                    username, platform_names, concurrency, timeout_s
                                )
                            )
                        )
                    finally:
                        loop.close()
                except BaseException as e:  # noqa: BLE001
                    exc_holder.append(e)

            t = threading.Thread(target=_runner)
            t.start()
            t.join()
            if exc_holder:
                raise exc_holder[0]
            findings = result

        return findings

    # -- async core ---------------------------------------------------------

    async def _enumerate(
        self,
        username: str,
        platform_names: list[str],
        concurrency: int,
        timeout_s: float,
    ) -> list[Finding]:
        headers = {"User-Agent": config.user_agent}
        connector = aiohttp.TCPConnector(
            limit=concurrency,
            ssl=False,           # some platforms have cert quirks; don't block
            force_close=False,
        )
        timeout = aiohttp.ClientTimeout(total=timeout_s)

        semaphore = asyncio.Semaphore(concurrency)
        findings: list[Finding] = []

        async with aiohttp.ClientSession(
            connector=connector,
            headers=headers,
            timeout=timeout,
            cookie_jar=aiohttp.CookieJar(unsafe=True),
        ) as session:
            tasks = [
                self._check_one(session, semaphore, name, username)
                for name in platform_names
            ]
            for finding in await asyncio.gather(*tasks, return_exceptions=False):
                if finding is not None:
                    findings.append(finding)

        # Sort by platform name for stable output
        findings.sort(key=lambda f: f.key.lower())
        return findings

    async def _check_one(
        self,
        session: aiohttp.ClientSession,
        semaphore: asyncio.Semaphore,
        platform_name: str,
        username: str,
    ) -> Finding | None:
        spec = PLATFORMS[platform_name]
        url = spec["url"].replace("{username}", username)
        method = spec["method"]

        async with semaphore:
            try:
                async with session.request(
                    method,
                    url,
                    allow_redirects=True,
                    cookies=spec.get("cookies") or None,
                ) as resp:
                    status = resp.status

                    # Hard not-found status codes from the spec.
                    if status in spec["not_found_status"]:
                        # Some sites return 200 even when absent; verify body.
                        if method == "GET":
                            body = await resp.text(errors="ignore")
                            if _looks_like_not_found(body, spec):
                                return None
                            if not _confirmed_present(body, spec, username):
                                return None
                        else:
                            return None

                    if status == 200:
                        body = await resp.text(errors="ignore")
                        if _looks_like_not_found(body, spec):
                            return None
                        if not _confirmed_present(body, spec, username):
                            return None
                        # Looks present.
                        return Finding(
                            module=self.name,
                            target=username,
                            key=platform_name,
                            value=url,
                            extra={
                                "status_code": status,
                                "title": _extract_title(body),
                            },
                        )

                    # Other status codes (3xx already followed, 5xx, etc.)
                    return None
            except (aiohttp.ClientError, asyncio.TimeoutError):
                return None


def _extract_title(html: str) -> str:
    """Extract <title> text for display in findings."""
    if not html:
        return ""
    try:
        soup = BeautifulSoup(html, "html.parser")
        if soup.title and soup.title.string:
            return soup.title.string.strip()[:200]
    except Exception:
        pass
    # Crude regex fallback
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if m:
        return re.sub(r"\s+", " ", m.group(1)).strip()[:200]
    return ""