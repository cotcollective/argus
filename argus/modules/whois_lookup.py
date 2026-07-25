"""WHOIS lookup module — domain registrant and IP WHOIS info."""

import whois
from argus.core.base import BaseModule, Finding
from argus.core.registry import Registry


@Registry.register
class WhoisModule(BaseModule):
    name = "whois"
    description = "WHOIS domain and IP lookup"
    input_type = "domain"

    def run(self, target: str, **kwargs) -> list[Finding]:
        findings = []
        target = target.replace("https://", "").replace("http://", "").split("/")[0]

        try:
            w = whois.whois(target)
            fields = {
                "registrar": w.registrar,
                "creation_date": w.creation_date,
                "expiration_date": w.expiration_date,
                "name_servers": w.name_servers,
                "status": w.status,
                "emails": w.emails,
                "org": w.org,
                "country": w.country,
                "state": w.state,
            }
            for key, val in fields.items():
                if val:
                    if isinstance(val, list):
                        val = ", ".join(str(v) for v in val)
                    findings.append(Finding(
                        module=self.name, target=target,
                        key=key, value=str(val),
                    ))
            if not findings:
                findings.append(Finding(
                    module=self.name, target=target,
                    key="result", value="No WHOIS data found",
                ))
        except Exception as e:
            findings.append(Finding(
                module=self.name, target=target,
                key="error", value=str(e),
            ))

        return findings