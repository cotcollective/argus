"""Paste search module — searches psbdmp.ws (free, no API key)."""

import requests
from argus.core.base import BaseModule, Finding
from argus.core.registry import Registry
from argus.config import config


@Registry.register
class PasteSearchModule(BaseModule):
    name = "paste"
    description = "Search Pastebin dumps via psbdmp.ws (free, no API key)"
    input_type = "auto"

    def run(self, target: str, **kwargs) -> list[Finding]:
        findings = []
        try:
            resp = requests.get(
                f"https://psbdmp.ws/api/search/{target}",
                headers={"User-Agent": config.user_agent},
                timeout=config.timeout,
            )
            if resp.status_code == 200:
                data = resp.json()
                dumps = data.get("data", [])
                for dump in dumps[:20]:
                    paste_id = dump.get("id", "")
                    findings.append(Finding(
                        module=self.name, target=target,
                        key="paste", value=f"https://pastebin.com/{paste_id}",
                        extra={
                            "date": dump.get("date"),
                            "content_preview": (dump.get("content", "") or "")[:200],
                        },
                    ))
                if not dumps:
                    findings.append(Finding(
                        module=self.name, target=target,
                        key="result", value="No paste dumps found",
                    ))
            else:
                findings.append(Finding(
                    module=self.name, target=target,
                    key="error", value=f"psbdmp.ws returned {resp.status_code}",
                ))
        except Exception as e:
            findings.append(Finding(
                module=self.name, target=target,
                key="error", value=str(e),
            ))

        return findings