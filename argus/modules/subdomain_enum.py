"""Subdomain enumeration module — crt.sh + DNS brute force (no API key)."""

import requests
import dns.resolver
import asyncio
from argus.core.base import BaseModule, Finding
from argus.core.registry import Registry
from argus.config import config


@Registry.register
class SubdomainEnumModule(BaseModule):
    name = "subdomains"
    description = "Subdomain enumeration via crt.sh + DNS brute force"
    input_type = "domain"

    COMMON_SUBDOMAINS = [
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
        "dns", "dns1", "dns2", "api", "dev", "staging", "test", "beta", "alpha",
        "admin", "portal", "app", "apps", "m", "mobile", "secure", "login",
        "vpn", "remote", "gateway", "cloud", "shop", "store", "blog", "forum",
        "wiki", "docs", "help", "support", "status", "monitor", "git", "gitlab",
        "jenkins", "ci", "build", "deploy", "auth", "oauth", "sso", "saml",
        "cdn", "static", "assets", "media", "img", "images", "video", "stream",
        "chat", "chatbot", "ws", "wss", "socket", "realtime", "push",
        "internal", "intranet", "extranet", "office", "hq", "corp",
        "backup", "bak", "old", "new", "v2", "v3", "next", "preview",
        "sandbox", "qa", "uat", "preprod", "prod", "production",
        "db", "database", "redis", "cache", "queue", "worker",
        "analytics", "track", "metrics", "logs", "log", "elk",
        "search", "elastic", "kibana", "grafana", "prometheus",
        "webhook", "hooks", "callback", "notify", "notification",
        "upload", "download", "files", "share", "transfer",
        "panel", "cpanel", "whm", "plesk", "manage", "manager",
        " mx", "mx1", "mx2", "imap", "pop3", "webdisk", "autoconfig",
        "autodiscover", "mta", "relay", "outbound", "inbound",
        "ns", "ns3", "ns4", "master", "slave", "primary", "secondary",
        "www2", "www3", "www4", "web", "web1", "web2",
    ]

    def run(self, target: str, **kwargs) -> list[Finding]:
        findings = []
        target = target.replace("https://", "").replace("http://", "").split("/")[0]

        # Method 1: crt.sh certificate transparency
        crt_findings = self._crt_sh(target)
        findings.extend(crt_findings)

        # Method 2: DNS brute force (async)
        brute_findings = self._dns_brute(target)
        findings.extend(brute_findings)

        if not findings:
            findings.append(Finding(
                module=self.name, target=target,
                key="result", value="No subdomains found",
            ))

        return findings

    def _crt_sh(self, domain: str) -> list[Finding]:
        """Query crt.sh certificate transparency logs."""
        findings = []
        try:
            resp = requests.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                headers={"User-Agent": config.user_agent},
                timeout=config.timeout,
            )
            if resp.status_code == 200:
                seen = set()
                for entry in resp.json():
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lstrip("*.")
                        if sub and domain in sub and sub not in seen:
                            seen.add(sub)
                            findings.append(Finding(
                                module=self.name, target=domain,
                                key="subdomain", value=sub,
                                extra={"source": "crt.sh"},
                            ))
        except Exception:
            pass
        return findings

    def _dns_brute(self, domain: str) -> list[Finding]:
        """DNS brute force on common subdomain names."""
        findings = []
        seen = {f.value for f in findings}

        for sub in self.COMMON_SUBDOMAINS:
            subdomain = f"{sub}.{domain}"
            if subdomain in seen:
                continue
            try:
                answers = dns.resolver.resolve(subdomain, "A")
                ip = str(answers[0])
                findings.append(Finding(
                    module=self.name, target=domain,
                    key="subdomain", value=subdomain,
                    extra={"ip": ip, "source": "dns_brute"},
                ))
                seen.add(subdomain)
            except Exception:
                pass

        return findings