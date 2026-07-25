"""Base module interface for all Argus modules."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional
import json
import time


@dataclass
class Finding:
    """A single finding from a module run."""
    module: str
    target: str
    key: str          # e.g. "spotify", "github", "port_443"
    value: str        # e.g. "https://open.spotify.com/user/target"
    extra: dict = field(default_factory=dict)  # additional context
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "module": self.module,
            "target": self.target,
            "key": self.key,
            "value": self.value,
            "extra": self.extra,
            "timestamp": self.timestamp,
        }


class BaseModule(ABC):
    """Abstract base class for all Argus modules."""

    name: str = "base"
    description: str = "Base module"
    input_type: str = "auto"  # "email", "username", "domain", "ip", "url", "phone", "auto"

    @abstractmethod
    def run(self, target: str, **kwargs) -> list[Finding]:
        """Execute the module against a target. Return list of findings."""
        ...

    def to_json(self, target: str, **kwargs) -> str:
        """Run module and return JSON output."""
        findings = self.run(target, **kwargs)
        return json.dumps([f.to_dict() for f in findings], indent=2)

    def to_markdown(self, target: str, **kwargs) -> str:
        """Run module and return Markdown output."""
        findings = self.run(target, **kwargs)
        if not findings:
            return f"### {self.name}\n\nNo findings for `{target}`.\n"
        lines = [f"### {self.name}\n", f"Target: `{target}`\n", f"Findings: {len(findings)}\n"]
        for f in findings:
            lines.append(f"- **{f.key}**: {f.value}")
            if f.extra:
                for k, v in f.extra.items():
                    lines.append(f"  - {k}: {v}")
        return "\n".join(lines) + "\n"