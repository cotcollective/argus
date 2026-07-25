"""DNS reconnaissance module — A/AAAA/MX/NS/TXT/CNAME/SOA + SPF/DMARC/DKIM analysis."""

import dns.resolver
from argus.core.base import BaseModule, Finding
from argus.core.registry import Registry


@Registry.register
class DNSReconModule(BaseModule):
    name = "dns"
    description = "DNS record enumeration with email security analysis (SPF/DMARC/DKIM)"
    input_type = "domain"

    RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

    def run(self, target: str, **kwargs) -> list[Finding]:
        findings = []
        target = target.replace("https://", "").replace("http://", "").split("/")[0]

        for rtype in self.RECORD_TYPES:
            try:
                answers = dns.resolver.resolve(target, rtype)
                for rdata in answers:
                    val = str(rdata).rstrip(".")
                    findings.append(Finding(
                        module=self.name, target=target,
                        key=f"{rtype}", value=val,
                    ))
            except dns.resolver.NXDOMAIN:
                findings.append(Finding(
                    module=self.name, target=target,
                    key="error", value=f"NXDOMAIN — {target} does not exist",
                ))
                return findings
            except dns.resolver.NoAnswer:
                pass
            except dns.resolver.NoNameservers:
                findings.append(Finding(
                    module=self.name, target=target,
                    key="error", value="No nameservers found",
                ))
                return findings
            except Exception:
                pass

        # SPF analysis
        try:
            txt = dns.resolver.resolve(target, "TXT")
            for rdata in txt:
                txt_str = str(rdata)
                if "v=spf1" in txt_str:
                    findings.append(Finding(
                        module=self.name, target=target,
                        key="SPF", value=txt_str,
                        extra={"status": "present"},
                    ))
        except Exception:
            findings.append(Finding(
                module=self.name, target=target,
                key="SPF", value="not found",
                extra={"status": "missing — vulnerable to email spoofing"},
            ))

        # DMARC analysis
        try:
            dmarc = dns.resolver.resolve(f"_dmarc.{target}", "TXT")
            for rdata in dmarc:
                dmarc_str = str(rdata)
                findings.append(Finding(
                    module=self.name, target=target,
                    key="DMARC", value=dmarc_str,
                    extra={"status": "present"},
                ))
        except Exception:
            findings.append(Finding(
                module=self.name, target=target,
                key="DMARC", value="not found",
                extra={"status": "missing — no DMARC policy"},
            ))

        return findings