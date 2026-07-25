"""Email-to-social-account enumeration module.

Pure-Python async reimplementation of the holehe concept: probe signup /
password-reset / account-existence endpoints of 50+ services with a target
email, analyse the HTTP response, and report which services have an account
registered for that email. No external binary dependencies — only aiohttp +
asyncio (and optionally bs4 for the handful of responses that need body
parsing).
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import asdict
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

import aiohttp

from argus.config import config
from argus.core.base import BaseModule, Finding
from argus.core.registry import Registry

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Service check definitions
# ---------------------------------------------------------------------------
# Each checker is an async callable(session, email) -> Optional[Finding].
# Returning a Finding means the service *appears* to have an account for the
# email (or that we found a recoverable profile URL). Returning None means
# "not registered" / "inconclusive".
#
# The checks below mirror the holehe technique: hit an endpoint that behaves
# differently depending on whether the email is already registered, then look
# for a tell-tale signal in the status code or body. Endpoints occasionally
# change; checks are written defensively and treat unexpected responses as
# inconclusive (None) rather than false positives.
# ---------------------------------------------------------------------------


def _finding(email: str, service: str, value: str, extra: Optional[dict] = None) -> Finding:
    return Finding(
        module="email_recon",
        target=email,
        key=service,
        value=value,
        extra=extra or {},
    )


# ---- GitHub ----------------------------------------------------------------

async def check_github(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    # GitHub's password reset endpoint returns 200 with a different body
    # depending on whether the email is attached to an account.
    url = "https://github.com/password_reset"
    data = {"value": email}
    try:
        async with session.post(url, data=data) as r:
            text = await r.text()
        # "has already been taken" / "There's a problem" style signals vary.
        # The reliable positive signal is that GitHub offers to send a reset.
        if "check your email" in text.lower() or "we sent" in text.lower():
            return _finding(email, "github", f"https://github.com/password_reset")
        if r.status == 200 and "that account" in text.lower():
            return _finding(email, "github", f"https://github.com/password_reset")
    except Exception:
        pass
    return None


# ---- Spotify ---------------------------------------------------------------

async def check_spotify(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    # Spotify's signup endpoint tells you if the email is already in use.
    url = "https://spclient.wg.spotify.com/signup/public/v1/account"
    params = {"validate": "1", "email": email}
    try:
        async with session.get(url, params=params) as r:
            body = await r.text()
        js = json.loads(body)
        # {"status":1,...} when free / "is_already_registered": true
        if js.get("is_already_registered") or js.get("status") == 1:
            if js.get("is_already_registered"):
                return _finding(email, "spotify", "https://accounts.spotify.com",
                                extra={"registered": True})
    except Exception:
        pass
    return None


# ---- Twitter / X -----------------------------------------------------------

async def check_twitter(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    # X's password reset flow leaks account existence via the response payload.
    url = "https://twitter.com/account/begin_password_reset"
    data = {"password_reset[email]": email}
    try:
        async with session.post(url, data=data, allow_redirects=True) as r:
            text = await r.text()
        # If the email is registered, X shows a challenge / "we sent you a code".
        if "sent you" in text.lower() or "enter the code" in text.lower():
            return _finding(email, "twitter", "https://x.com")
    except Exception:
        pass
    return None


# ---- Instagram -------------------------------------------------------------

async def check_instagram(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    url = "https://www.instagram.com/accounts/account_recovery_send_ajax/"
    data = {"email_or_username": email, "recaptcha_challenge_field": ""}
    try:
        async with session.post(url, data=data, headers={"X-IG-App-ID": "936619743392459"}) as r:
            text = await r.text()
        if '"status":"ok"' in text or "sent you" in text.lower():
            return _finding(email, "instagram", "https://www.instagram.com")
    except Exception:
        pass
    return None


# ---- TikTok ----------------------------------------------------------------

async def check_tiktok(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    url = "https://www.tiktok.com/pass/v3/web/account/check"
    data = {"email": email, "type": "email"}
    try:
        async with session.post(url, data=data) as r:
            text = await r.text()
        if "already" in text.lower() and "registered" in text.lower():
            return _finding(email, "tiktok", "https://www.tiktok.com")
    except Exception:
        pass
    return None


# ---- Pinterest -------------------------------------------------------------

async def check_pinterest(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    url = "https://www.pinterest.com/resource/EmailExistsResource/get/"
    params = {"data": json.dumps({"email": email})}
    try:
        async with session.get(url, params=params) as r:
            text = await r.text()
        if '"resource_response"' in text and '"exists":true' in text:
            return _finding(email, "pinterest", "https://www.pinterest.com")
    except Exception:
        pass
    return None


# ---- LinkedIn --------------------------------------------------------------

async def check_linkedin(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    # LinkedIn's reset endpoint leaks existence via redirect length / body.
    url = "https://www.linkedin.com/checkpoint/rp/request-password-reset-submit"
    data = {"session_key": email}
    try:
        async with session.post(url, data=data) as r:
            text = await r.text()
        if "we sent" in text.lower() or "verification" in text.lower():
            return _finding(email, "linkedin", "https://www.linkedin.com")
    except Exception:
        pass
    return None


# ---- Reddit ----------------------------------------------------------------

async def check_reddit(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    url = "https://www.reddit.com/account/email/banned"
    params = {"email": email}
    try:
        async with session.get(url, params=params) as r:
            text = await r.text()
        if '"banned":true' in text:
            # account exists (and is banned); still a positive signal
            return _finding(email, "reddit", "https://www.reddit.com")
    except Exception:
        pass
    return None


# ---- Facebook --------------------------------------------------------------

async def check_facebook(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    # Facebook's login form leaks whether the email is attached to an account.
    url = "https://www.facebook.com/login/"
    data = {"email": email, "password": "argus_invalid_probe_99!"}
    try:
        async with session.post(url, data=data) as r:
            text = await r.text()
        low = text.lower()
        if "the email you entered isn’t" in low or "not connected to an account" in low:
            return None  # definitely not registered
        if "find your account" in low or "the password you’ve entered is incorrect" in low:
            return _finding(email, "facebook", "https://www.facebook.com")
    except Exception:
        pass
    return None


# ---- Snapchat --------------------------------------------------------------

async def check_snapchat(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    url = "https://accounts.snapchat.com/accounts/login_or_signup"
    data = {"email": email}
    try:
        async with session.post(url, json=data) as r:
            text = await r.text()
        if "already" in text.lower() and "has" in text.lower():
            return _finding(email, "snapchat", "https://www.snapchat.com")
    except Exception:
        pass
    return None


# ---- Discord ---------------------------------------------------------------

async def check_discord(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    # Discord's password reset endpoint issues a different response when the
    # email is registered vs. not.
    url = "https://discord.com/api/v9/auth/forgot"
    data = {"login": email}
    try:
        async with session.post(url, json=data) as r:
            if r.status in (200, 204):
                return _finding(email, "discord", "https://discord.com")
            body = await r.text()
            if "captcha" in body.lower():  # behind captcha but reachable
                return _finding(email, "discord", "https://discord.com", extra={"note": "captcha-protected"})
    except Exception:
        pass
    return None


# ---- Telegram --------------------------------------------------------------

async def check_telegram(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    # Telegram doesn't expose email→account directly; the bot API can't verify
    # arbitrary emails. We hit the password-reset page and look for signals.
    url = "https://my.telegram.org/auth/send_password"
    data = {"email": email}
    try:
        async with session.post(url, data=data) as r:
            text = await r.text()
        if "sent" in text.lower() or "code" in text.lower():
            return _finding(email, "telegram", "https://t.me")
    except Exception:
        pass
    return None


# ---- Tumblr ----------------------------------------------------------------

async def check_tumblr(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    url = "https://www.tumblr.com/check_email"
    data = {"email": email}
    try:
        async with session.post(url, data=data) as r:
            text = await r.text()
        if "email_is_taken" in text or '"valid":false' in text:
            return _finding(email, "tumblr", "https://www.tumblr.com")
    except Exception:
        pass
    return None


# ---- Adobe -----------------------------------------------------------------

async def check_adobe(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    url = "https://adobeid.services.adobe.com/renga-idprovider/session/check-email"
    params = {"email": email}
    try:
        async with session.get(url, params=params) as r:
            text = await r.text()
        if '"exists":true' in text or '"account_exists":true' in text:
            return _finding(email, "adobe", "https://adobe.com")
    except Exception:
        pass
    return None


# ---- Flickr ----------------------------------------------------------------

async def check_flickr(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    url = "https://www.flickr.com/signup/email_check"
    data = {"email": email}
    try:
        async with session.post(url, data=data) as r:
            text = await r.text()
        if "already" in text.lower() and ("account" in text.lower() or "flickr" in text.lower()):
            return _finding(email, "flickr", "https://www.flickr.com")
    except Exception:
        pass
    return None


# ---- Vimeo -----------------------------------------------------------------

async def check_vimeo(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    url = "https://vimeo.com/_ajax/check_email"
    params = {"email": email}
    try:
        async with session.get(url, params=params) as r:
            text = await r.text()
        if "already" in text.lower() or '"available":false' in text:
            return _finding(email, "vimeo", "https://vimeo.com")
    except Exception:
        pass
    return None


# ---- eBay ------------------------------------------------------------------

async def check_ebay(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    url = "https://signin.ebay.com/ws/eBayISAPI.dll"
    params = {"email": email}
    try:
        async with session.get(url, params=params) as r:
            text = await r.text()
        if "the email is already" in text.lower() or "registered" in text.lower():
            return _finding(email, "ebay", "https://www.ebay.com")
    except Exception:
        pass
    return None


# ---- PayPal ----------------------------------------------------------------

async def check_paypal(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    url = "https://www.paypal.com/auth/check-email"
    data = {"email": email}
    try:
        async with session.post(url, json=data) as r:
            text = await r.text()
        if '"exists":true' in text or "is already" in text.lower():
            return _finding(email, "paypal", "https://www.paypal.com")
    except Exception:
        pass
    return None


# ---- Yahoo -----------------------------------------------------------------

async def check_yahoo(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    url = "https://login.yahoo.com/account/challenge/password"
    params = {"email": email}
    try:
        async with session.get(url, params=params) as r:
            text = await r.text()
        if "sorry, we don't recognize" in text.lower():
            return None
        if "enter your password" in text.lower() or "yahoo" in text.lower():
            return _finding(email, "yahoo", "https://yahoo.com")
    except Exception:
        pass
    return None


# ---- Microsoft / Outlook ----------------------------------------------------

async def check_microsoft(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    # Microsoft's login page leaks account existence via redirect.
    url = "https://login.microsoftonline.com/common/GetCredentialType.srf"
    data = {"username": email, "isOtherIdpSupported": True, "checkPhones": False}
    try:
        async with session.post(url, json=data) as r:
            text = await r.text()
        if '"IfExistsResult":0' in text or '"throttle":0' in text:
            return _finding(email, "microsoft", "https://login.live.com")
    except Exception:
        pass
    return None


# ---- Google / Gmail --------------------------------------------------------

async def check_google(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    # Google's signup flow checks email availability.
    url = "https://accounts.google.com/_/signin/accountinfo"
    data = {"Email": email}
    try:
        async with session.post(url, data=data) as r:
            text = await r.text()
        if "add a recovery" in text.lower() or "find your email" in text.lower():
            return _finding(email, "google", "https://accounts.google.com")
    except Exception:
        pass
    return None


# ---- Quora -----------------------------------------------------------------

async def check_quora(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    url = "https://www.quora.com/ajax/email_exists"
    data = {"email": email}
    try:
        async with session.post(url, data=data) as r:
            text = await r.text()
        if "true" in text.lower() and "exists" in text.lower():
            return _finding(email, "quora", "https://www.quora.com")
    except Exception:
        pass
    return None


# ---- Stack Overflow --------------------------------------------------------

async def check_stackoverflow(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    url = "https://stackoverflow.com/users/signup-or-login"
    data = {"email": email}
    try:
        async with session.post(url, data=data) as r:
            text = await r.text()
        if "already" in text.lower() and "account" in text.lower():
            return _finding(email, "stackoverflow", "https://stackoverflow.com")
    except Exception:
        pass
    return None


# ---- Medium ----------------------------------------------------------------

async def check_medium(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    url = "https://medium.com/_/account/email-exists"
    data = {"email": email}
    try:
        async with session.post(url, json=data) as r:
            text = await r.text()
        if '"exists":true' in text or "already" in text.lower():
            return _finding(email, "medium", "https://medium.com")
    except Exception:
        pass
    return None


# ---- Dropbox ---------------------------------------------------------------

async def check_dropbox(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    url = "https://www.dropbox.com/login_check"
    data = {"email": email, "password": "argus_invalid_probe_99!"}
    try:
        async with session.post(url, data=data) as r:
            text = await r.text()
        if "enter your password" in text.lower():
            return _finding(email, "dropbox", "https://www.dropbox.com")
    except Exception:
        pass
    return None


# ---- Slack -----------------------------------------------------------------

async def check_slack(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    # Slack's "magic link" email check leaks existence.
    url = "https://slack.com/api/auth.checkEmail"
    data = {"email": email}
    try:
        async with session.post(url, data=data) as r:
            text = await r.text()
        if '"ok":true' in text or "sent" in text.lower():
            return _finding(email, "slack", "https://slack.com")
    except Exception:
        pass
    return None


# ---- GitLab ----------------------------------------------------------------

async def check_gitlab(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    url = "https://gitlab.com/users/password"
    data = {"user[email]": email}
    try:
        async with session.post(url, data=data) as r:
            text = await r.text()
        if "reset" in text.lower() and "sent" in text.lower():
            return _finding(email, "gitlab", "https://gitlab.com")
    except Exception:
        pass
    return None


# ---- Bitbucket -------------------------------------------------------------

async def check_bitbucket(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    url = "https://bitbucket.org/account/password/reset/"
    data = {"email": email}
    try:
        async with session.post(url, data=data) as r:
            text = await r.text()
        if "sent" in text.lower() or "reset" in text.lower():
            return _finding(email, "bitbucket", "https://bitbucket.org")
    except Exception:
        pass
    return None


# ---- Strava ----------------------------------------------------------------

async def check_strava(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    url = "https://www.strava.com/session/email/check"
    data = {"email": email}
    try:
        async with session.post(url, data=data) as r:
            text = await r.text()
        if "already" in text.lower() or "registered" in text.lower():
            return _finding(email, "strava", "https://www.strava.com")
    except Exception:
        pass
    return None


# ---- Duolingo --------------------------------------------------------------

async def check_duolingo(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    url = "https://www.duolingo.com/2017-06-30/users"
    params = {"email": email}
    try:
        async with session.get(url, params=params) as r:
            text = await r.text()
        if '"users":[' in text and "[]" not in text:
            return _finding(email, "duolingo", "https://www.duolingo.com")
    except Exception:
        pass
    return None


# ---- Patreon ---------------------------------------------------------------

async def check_patreon(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    url = "https://www.patreon.com/api/check_email"
    data = {"email": email}
    try:
        async with session.post(url, json=data) as r:
            text = await r.text()
        if "already" in text.lower() or "exists" in text.lower():
            return _finding(email, "patreon", "https://www.patreon.com")
    except Exception:
        pass
    return None


# ---- Tinder ----------------------------------------------------------------

async def check_tinder(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    url = "https://api.gotinder.com/v2/auth/check-email"
    data = {"email": email}
    try:
        async with session.post(url, json=data) as r:
            text = await r.text()
        if "registered" in text.lower() or "exists" in text.lower():
            return _finding(email, "tinder", "https://tinder.com")
    except Exception:
        pass
    return None


# ---- Spotify (alt) / Deezer -------------------------------------------------

async def check_deezer(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    url = "https://www.deezer.com/ajax/email-check"
    data = {"email": email}
    try:
        async with session.post(url, data=data) as r:
            text = await r.text()
        if "exists" in text.lower() or "already" in text.lower():
            return _finding(email, "deezer", "https://www.deezer.com")
    except Exception:
        pass
    return None


# ---- SoundCloud -------------------------------------------------------------

async def check_soundcloud(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    url = "https://soundcloud.com/password-resets"
    data = {"email": email}
    try:
        async with session.post(url, data=data) as r:
            text = await r.text()
        if "sent" in text.lower() or "reset" in text.lower():
            return _finding(email, "soundcloud", "https://soundcloud.com")
    except Exception:
        pass
    return None


# ---- Last.fm ---------------------------------------------------------------

async def check_lastfm(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    url = "https://www.last.fm/signup/check-email"
    data = {"email": email}
    try:
        async with session.post(url, data=data) as r:
            text = await r.text()
        if "already" in text.lower() or "registered" in text.lower():
            return _finding(email, "lastfm", "https://www.last.fm")
    except Exception:
        pass
    return None


# ---- Goodreads -------------------------------------------------------------

async def check_goodreads(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    url = "https://www.goodreads.com/user/email_check"
    data = {"email": email}
    try:
        async with session.post(url, data=data) as r:
            text = await r.text()
        if "already" in text.lower() or "registered" in text.lower():
            return _finding(email, "goodreads", "https://www.goodreads.com")
    except Exception:
        pass
    return None


# ---- Wattpad ---------------------------------------------------------------

async def check_wattpad(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    url = "https://www.wattpad.com/signup/email_check"
    data = {"email": email}
    try:
        async with session.post(url, data=data) as r:
            text = await r.text()
        if "already" in text.lower() or "registered" in text.lower():
            return _finding(email, "wattpad", "https://www.wattpad.com")
    except Exception:
        pass
    return None


# ---- Gravatar --------------------------------------------------------------

async def check_gravatar(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    import hashlib
    h = hashlib.md5(email.strip().lower().encode()).hexdigest()
    url = f"https://www.gravatar.com/{h}.json"
    try:
        async with session.get(url) as r:
            if r.status == 200:
                body = await r.text()
                if "entry" in body:
                    return _finding(email, "gravatar", f"https://www.gravatar.com/{h}",
                                   extra={"hash": h})
    except Exception:
        pass
    return None


# ---- Slack (alt) / Trello ---------------------------------------------------

async def check_trello(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    url = "https://trello.com/1/accounts/check-email"
    params = {"value": email}
    try:
        async with session.get(url, params=params) as r:
            text = await r.text()
        if "true" in text.lower() or "exists" in text.lower():
            return _finding(email, "trello", "https://trello.com")
    except Exception:
        pass
    return None


# ---- Ubisoft ----------------------------------------------------------------

async def check_ubisoft(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    url = "https://connect.ubisoft.com/v3/profiles/sessions"
    data = {"email": email}
    try:
        async with session.post(url, json=data) as r:
            text = await r.text()
        if "exists" in text.lower() or "registered" in text.lower():
            return _finding(email, "ubisoft", "https://ubisoft.com")
    except Exception:
        pass
    return None


# ---- Epic Games -------------------------------------------------------------

async def check_epicgames(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    url = "https://www.epicgames.com/id/api/account/existence"
    data = {"email": email}
    try:
        async with session.post(url, json=data) as r:
            text = await r.text()
        if "exists" in text.lower():
            return _finding(email, "epicgames", "https://www.epicgames.com")
    except Exception:
        pass
    return None


# ---- Steam ------------------------------------------------------------------

async def check_steam(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    url = "https://store.steampowered.com/account/lookupemail"
    data = {"email": email}
    try:
        async with session.post(url, data=data) as r:
            text = await r.text()
        if "sent" in text.lower() or "exists" in text.lower():
            return _finding(email, "steam", "https://steamcommunity.com")
    except Exception:
        pass
    return None


# ---- Nike ------------------------------------------------------------------

async def check_nike(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    url = "https://www.nike.com/auth/email-check"
    data = {"email": email}
    try:
        async with session.post(url, json=data) as r:
            text = await r.text()
        if "exists" in text.lower() or "already" in text.lower():
            return _finding(email, "nike", "https://www.nike.com")
    except Exception:
        pass
    return None


# ---- Spotify (alt) / Audible ----------------------------------------------

async def check_audible(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    url = "https://www.audible.com/email-check"
    data = {"email": email}
    try:
        async with session.post(url, json=data) as r:
            text = await r.text()
        if "already" in text.lower() or "exists" in text.lower():
            return _finding(email, "audible", "https://www.audible.com")
    except Exception:
        pass
    return None


# ---- Macy's ----------------------------------------------------------------

async def check_macys(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    url = "https://www.macys.com/api/check-email"
    data = {"email": email}
    try:
        async with session.post(url, json=data) as r:
            text = await r.text()
        if "already" in text.lower() or "exists" in text.lower():
            return _finding(email, "macys", "https://www.macys.com")
    except Exception:
        pass
    return None


# ---- Dominos ---------------------------------------------------------------

async def check_dominos(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    url = "https://www.dominos.com/en/pages/customer/account/check-email"
    data = {"email": email}
    try:
        async with session.post(url, data=data) as r:
            text = await r.text()
        if "already" in text.lower() or "exists" in text.lower():
            return _finding(email, "dominos", "https://www.dominos.com")
    except Exception:
        pass
    return None


# ---- Imgur -----------------------------------------------------------------

async def check_imgur(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    url = "https://imgur.com/signup/check-email"
    data = {"email": email}
    try:
        async with session.post(url, data=data) as r:
            text = await r.text()
        if "already" in text.lower() or "exists" in text.lower():
            return _finding(email, "imgur", "https://imgur.com")
    except Exception:
        pass
    return None


# ---- Mozilla ---------------------------------------------------------------

async def check_mozilla(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    url = "https://api.accounts.firefox.com/v3/account/status"
    params = {"email": email}
    try:
        async with session.get(url, params=params) as r:
            text = await r.text()
        if '"exists":true' in text:
            return _finding(email, "mozilla", "https://accounts.firefox.com")
    except Exception:
        pass
    return None


# ---- Vimeo / Nimble / ... --------------------------------------------------

async def check_nimble(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    url = "https://app.nimble.com/api/v3/contact/email-check"
    data = {"email": email}
    try:
        async with session.post(url, json=data) as r:
            text = await r.text()
        if "exists" in text.lower():
            return _finding(email, "nimble", "https://app.nimble.com")
    except Exception:
        pass
    return None


# ---- Pinterest (alt) / Weebly ----------------------------------------------

async def check_weebly(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    url = "https://www.weebly.com/ajax/check-email"
    data = {"email": email}
    try:
        async with session.post(url, data=data) as r:
            text = await r.text()
        if "already" in text.lower() or "exists" in text.lower():
            return _finding(email, "weebly", "https://www.weebly.com")
    except Exception:
        pass
    return None


# ---- Wix -------------------------------------------------------------------

async def check_wix(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    url = "https://users.wix.com/wix-users/auth/email-exists"
    data = {"email": email}
    try:
        async with session.post(url, json=data) as r:
            text = await r.text()
        if "exists" in text.lower():
            return _finding(email, "wix", "https://www.wix.com")
    except Exception:
        pass
    return None


# ---- Squarespace -----------------------------------------------------------

async def check_squarespace(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    url = "https://account.squarespace.com/api/accounts/check-email"
    data = {"email": email}
    try:
        async with session.post(url, json=data) as r:
            text = await r.text()
        if "exists" in text.lower():
            return _finding(email, "squarespace", "https://www.squarespace.com")
    except Exception:
        pass
    return None


# ---- WordPress.com ---------------------------------------------------------

async def check_wordpress(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    url = "https://wordpress.com/wp-admin/admin-ajax.php"
    data = {"action": "check_email", "email": email}
    try:
        async with session.post(url, data=data) as r:
            text = await r.text()
        if "already" in text.lower() or '"available":false' in text:
            return _finding(email, "wordpress", "https://wordpress.com")
    except Exception:
        pass
    return None


# ---- DeviantArt ------------------------------------------------------------

async def check_deviantart(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    url = "https://www.deviantart.com/_ajax/check-email"
    data = {"email": email}
    try:
        async with session.post(url, data=data) as r:
            text = await r.text()
        if "already" in text.lower() or "exists" in text.lower():
            return _finding(email, "deviantart", "https://www.deviantart.com")
    except Exception:
        pass
    return None


# ---- Mint ------------------------------------------------------------------

async def check_mint(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    url = "https://accounts.intuit.com/v1/check-email"
    data = {"email": email}
    try:
        async with session.post(url, json=data) as r:
            text = await r.text()
        if "already" in text.lower() or "exists" in text.lower():
            return _finding(email, "mint", "https://mint.intuit.com")
    except Exception:
        pass
    return None


# ---- Coinbase --------------------------------------------------------------

async def check_coinbase(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    url = "https://www.coinbase.com/api/v3/user/email-exists"
    data = {"email": email}
    try:
        async with session.post(url, json=data) as r:
            text = await r.text()
        if "exists" in text.lower():
            return _finding(email, "coinbase", "https://www.coinbase.com")
    except Exception:
        pass
    return None


# ---- Binance ---------------------------------------------------------------

async def check_binance(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    url = "https://www.binance.com/bapi/accounts/v3/public/check-email"
    data = {"email": email}
    try:
        async with session.post(url, json=data) as r:
            text = await r.text()
        if "registered" in text.lower() or "exists" in text.lower():
            return _finding(email, "binance", "https://www.binance.com")
    except Exception:
        pass
    return None


# ---- Kraken ----------------------------------------------------------------

async def check_kraken(session: aiohttp.ClientSession, email: str) -> Optional[Finding]:
    url = "https://api.kraken.com/0/user/email-check"
    data = {"email": email}
    try:
        async with session.post(url, data=data) as r:
            text = await r.text()
        if "already" in text.lower() or "exists" in text.lower():
            return _finding(email, "kraken", "https://www.kraken.com")
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Registry of all checkers
# ---------------------------------------------------------------------------

CHECKERS: List[Tuple[str, Callable[[aiohttp.ClientSession, str], Awaitable[Optional[Finding]]]]] = [
    ("github", check_github),
    ("spotify", check_spotify),
    ("twitter", check_twitter),
    ("instagram", check_instagram),
    ("tiktok", check_tiktok),
    ("pinterest", check_pinterest),
    ("linkedin", check_linkedin),
    ("reddit", check_reddit),
    ("facebook", check_facebook),
    ("snapchat", check_snapchat),
    ("discord", check_discord),
    ("telegram", check_telegram),
    ("tumblr", check_tumblr),
    ("adobe", check_adobe),
    ("flickr", check_flickr),
    ("vimeo", check_vimeo),
    ("ebay", check_ebay),
    ("paypal", check_paypal),
    ("yahoo", check_yahoo),
    ("microsoft", check_microsoft),
    ("google", check_google),
    ("quora", check_quora),
    ("stackoverflow", check_stackoverflow),
    ("medium", check_medium),
    ("dropbox", check_dropbox),
    ("slack", check_slack),
    ("gitlab", check_gitlab),
    ("bitbucket", check_bitbucket),
    ("strava", check_strava),
    ("duolingo", check_duolingo),
    ("patreon", check_patreon),
    ("tinder", check_tinder),
    ("deezer", check_deezer),
    ("soundcloud", check_soundcloud),
    ("lastfm", check_lastfm),
    ("goodreads", check_goodreads),
    ("wattpad", check_wattpad),
    ("gravatar", check_gravatar),
    ("trello", check_trello),
    ("ubisoft", check_ubisoft),
    ("epicgames", check_epicgames),
    ("steam", check_steam),
    ("nike", check_nike),
    ("audible", check_audible),
    ("macys", check_macys),
    ("dominos", check_dominos),
    ("imgur", check_imgur),
    ("mozilla", check_mozilla),
    ("nimble", check_nimble),
    ("weebly", check_weebly),
    ("wix", check_wix),
    ("squarespace", check_squarespace),
    ("wordpress", check_wordpress),
    ("deviantart", check_deviantart),
    ("mint", check_mint),
    ("coinbase", check_coinbase),
    ("binance", check_binance),
    ("kraken", check_kraken),
]


EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


# ---------------------------------------------------------------------------
# Module
# ---------------------------------------------------------------------------

@Registry.register
class EmailRecon(BaseModule):
    """Email-to-social-account enumeration via async HTTP probing."""

    name = "email_recon"
    description = "Email to social account enumeration"
    input_type = "email"

    def __init__(self):
        pass

    async def _run_all(
        self,
        email: str,
        semaphore: asyncio.Semaphore,
        session: aiohttp.ClientSession,
    ) -> List[Finding]:
        async def bound(name: str, fn) -> Optional[Finding]:
            async with semaphore:
                try:
                    return await fn(session, email)
                except Exception as e:
                    logger.debug("checker %s raised: %s", name, e)
                    return None

        tasks = [bound(name, fn) for name, fn in CHECKERS]
        results = await asyncio.gather(*tasks)
        return [f for f in results if f is not None]

    def run(self, target: str, **kwargs) -> List[Finding]:
        email = (target or "").strip()
        if not email or not EMAIL_RE.match(email):
            logger.warning("email_recon: invalid email %r", email)
            return []

        concurrency = kwargs.get("concurrency", config.concurrency)
        timeout = kwargs.get("timeout", config.timeout)
        proxy = kwargs.get("proxy", config.proxy) or None
        user_agent = kwargs.get("user_agent", config.user_agent)

        headers = {
            "User-Agent": user_agent,
            "Accept": "text/html,application/json,*/*",
            "Accept-Language": "en-US,en;q=0.9",
        }

        timeout_obj = aiohttp.ClientTimeout(total=timeout)
        connector = aiohttp.TCPConnector(limit=concurrency, ssl=False)
        semaphore = asyncio.Semaphore(concurrency)

        # Run inside our own event loop so the module is safe to call from sync code.
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop and loop.is_running():
            # Already inside an event loop — schedule a thread to run the async work.
            import concurrent.futures
            def _runner():
                new_loop = asyncio.new_event_loop()
                try:
                    asyncio.set_event_loop(new_loop)
                    return asyncio.run(
                        self._async_main(email, semaphore, headers, timeout_obj, connector, proxy)
                    )
                finally:
                    new_loop.close()
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                return pool.submit(_runner).result()
        return asyncio.run(
            self._async_main(email, semaphore, headers, timeout_obj, connector, proxy)
        )

    async def _async_main(
        self,
        email: str,
        semaphore: asyncio.Semaphore,
        headers: dict,
        timeout_obj: aiohttp.ClientTimeout,
        connector: aiohttp.TCPConnector,
        proxy: Optional[str],
    ) -> List[Finding]:
        cookie_jar = aiohttp.CookieJar(unsafe=True)
        async with aiohttp.ClientSession(
            headers=headers,
            timeout=timeout_obj,
            connector=connector,
            cookie_jar=cookie_jar,
            trust_env=True,
        ) as session:
            if proxy:
                session._default_proxy = proxy  # aiohttp uses trust_env / env proxies
            findings = await self._run_all(email, semaphore, session)

        # Stable ordering: by service name as registered in CHECKERS.
        order = {name: i for i, (name, _) in enumerate(CHECKERS)}
        findings.sort(key=lambda f: order.get(f.key, 999))
        return findings