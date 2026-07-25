"""Report builder for Argus investigations."""

import json
import time
from pathlib import Path
from typing import List
from argus.core.base import Finding
from argus.config import config


class ReportBuilder:
    """Build Markdown and JSON reports from findings."""

    def __init__(self, report_dir: str = None):
        self.report_dir = Path(report_dir or config.report_dir)
        self.report_dir.mkdir(parents=True, exist_ok=True)

    def build_markdown(self, target: str, findings: List[Finding], module_runs: list = None) -> str:
        lines = [
            f"# Argus Investigation Report",
            f"",
            f"**Target**: `{target}`",
            f"**Date**: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Findings**: {len(findings)}",
            f"",
            "---",
            f"",
        ]
        # Group by module
        by_module = {}
        for f in findings:
            by_module.setdefault(f.module, []).append(f)
        for mod_name in sorted(by_module.keys()):
            lines.append(f"## {mod_name}")
            lines.append("")
            for f in by_module[mod_name]:
                lines.append(f"- **{f.key}**: {f.value}")
                if f.extra:
                    for k, v in f.extra.items():
                        lines.append(f"  - {k}: {v}")
            lines.append("")

        if module_runs:
            lines.append("---")
            lines.append("")
            lines.append("## Module Execution Log")
            lines.append("")
            for run in module_runs:
                status = "OK" if run.get("findings") is not None else "ERROR"
                lines.append(f"- {run['module']}({run['target']}) [{status}] — {run.get('count', 0)} findings")
            lines.append("")

        return "\n".join(lines)

    def build_json(self, target: str, findings: List[Finding]) -> str:
        return json.dumps({
            "target": target,
            "timestamp": time.time(),
            "findings_count": len(findings),
            "findings": [f.to_dict() for f in findings],
        }, indent=2)

    def save(self, target: str, findings: List[Finding], module_runs: list = None) -> Path:
        ts = time.strftime("%Y%m%d_%H%M%S")
        safe_target = target.replace("@", "_at_").replace("/", "_").replace(":", "_")
        md_path = self.report_dir / f"{ts}_{safe_target}_report.md"
        json_path = self.report_dir / f"{ts}_{safe_target}_report.json"

        md_path.write_text(self.build_markdown(target, findings, module_runs))
        json_path.write_text(self.build_json(target, findings))

        return md_path