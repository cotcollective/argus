"""Network reconnaissance module — nmap + banner grab (replaces Shodan/Censys)."""

import shutil
import subprocess
import xml.etree.ElementTree as ET
from typing import List

from argus.core.base import BaseModule, Finding
from argus.core.registry import Registry


@Registry.register
class NetworkReconModule(BaseModule):
    """Local network reconnaissance via nmap.

    Replaces cloud Shodan/Censys lookups with on-box nmap service/version
    detection plus default-script banner grabbing. Parses the XML output
    stream (-oX -) so no temp files are required.
    """

    name: str = "network_recon"
    description: str = "Network reconnaissance via nmap + banner grab (replaces Shodan/Censys)"
    input_type: str = "ip"

    # Map scan_type kwarg -> nmap flag(s).
    _SCAN_TYPES = {
        "fast": ["-T4"],
        "stealth": ["-sS"],
        "version": ["-sV"],
    }

    def run(self, target: str, **kwargs) -> List[Finding]:
        """Run an nmap scan against ``target`` and return a list of Findings.

        kwargs:
            ports (str):        port spec for -p (e.g. "1-1000", "80,443").
            scan_type (str):    one of 'fast' | 'stealth' | 'version'.
            script_scan (bool): if True, append --script (default scripts).
        """
        # Graceful fallback when nmap is not installed.
        if shutil.which("nmap") is None:
            return [Finding(
                module=self.name,
                target=target,
                key="error",
                value="nmap not installed",
                extra={"hint": "Install nmap: apt install nmap (Debian/Ubuntu)"},
            )]

        cmd = self._build_cmd(target, **kwargs)

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=kwargs.get("timeout", 600),
            )
        except subprocess.TimeoutExpired:
            return [Finding(
                module=self.name,
                target=target,
                key="error",
                value=f"nmap timed out after {kwargs.get('timeout', 600)}s",
                extra={"command": " ".join(cmd)},
            )]
        except Exception as exc:
            return [Finding(
                module=self.name,
                target=target,
                key="error",
                value=f"nmap failed: {exc}",
                extra={"command": " ".join(cmd)},
            )]

        if proc.returncode not in (0, 1):
            # nmap returns 1 for "host down" / no open ports — still valid XML.
            return [Finding(
                module=self.name,
                target=target,
                key="error",
                value=f"nmap exit {proc.returncode}: {proc.stderr.strip()[:500]}",
                extra={"command": " ".join(cmd)},
            )]

        return self._parse_xml(proc.stdout, target, " ".join(cmd))

    # ------------------------------------------------------------------ #
    # internals
    # ------------------------------------------------------------------ #

    def _build_cmd(self, target: str, **kwargs) -> List[str]:
        """Assemble the nmap command line from kwargs."""
        cmd = ["nmap", "-sV", "-sC", "--open", "-oX", "-", target]

        ports = kwargs.get("ports")
        if ports:
            # Replace --top-ports 1000 default with explicit port spec.
            cmd[1:1] = ["-p", str(ports)]
        else:
            cmd[1:1] = ["--top-ports", "1000"]

        scan_type = kwargs.get("scan_type")
        if scan_type and scan_type in self._SCAN_TYPES:
            flags = self._SCAN_TYPES[scan_type]
            # Skip 'version' since -sV is already in the base command.
            if scan_type != "version":
                cmd[1:1] = flags

        if kwargs.get("script_scan"):
            # --script with no arg == default script set (equivalent to -sC);
            # include it explicitly so callers can request it independently.
            cmd[1:1] = ["--script"]

        return cmd

    def _parse_xml(self, xml_str: str, target: str, command: str) -> List[Finding]:
        """Parse nmap XML stream into Findings."""
        findings: List[Finding] = []

        if not xml_str or not xml_str.strip():
            return [Finding(
                module=self.name,
                target=target,
                key="error",
                value="nmap produced no output",
                extra={"command": command},
            )]

        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError as exc:
            return [Finding(
                module=self.name,
                target=target,
                key="error",
                value=f"XML parse error: {exc}",
                extra={"command": command, "snippet": xml_str[:500]},
            )]

        # Walk every host element (nmaprun may contain multiple hosts).
        for host in root.findall(".//host"):
            ostype = self._host_ostype(host)

            for port_el in host.findall(".//port"):
                portid = port_el.get("portid")
                if not portid:
                    continue

                state_el = port_el.find("state")
                state = state_el.get("state") if state_el is not None else "unknown"
                if state != "open":
                    continue

                service_el = port_el.find("service")
                service = (service_el.get("name") if service_el is not None else "unknown") or "unknown"
                product = (service_el.get("product") if service_el is not None else "") or ""
                version = (service_el.get("version") if service_el is not None else "") or ""
                banner = (service_el.get("extrainfo") if service_el is not None else "") or ""

                # Pull the first script output as banner text if present.
                script_el = port_el.find("script")
                if script_el is not None:
                    script_out = script_el.get("output") or ""
                    if script_out:
                        banner = f"{banner} {script_out}".strip() if banner else script_out

                extra = {
                    "product": product,
                    "version": version,
                    "banner": banner,
                    "ostype": ostype,
                }
                # Drop empty extra fields for cleaner output.
                extra = {k: v for k, v in extra.items() if v}

                findings.append(Finding(
                    module=self.name,
                    target=target,
                    key=f"port_{portid}",
                    value=f"{service} on port {portid}",
                    extra=extra,
                ))

        if not findings:
            return [Finding(
                module=self.name,
                target=target,
                key="no_open_ports",
                value="No open ports detected",
                extra={"command": command},
            )]

        return findings

    @staticmethod
    def _host_ostype(host: ET.Element) -> str:
        """Extract OS guess from a host element, if present."""
        os_el = host.find(".//osmatch")
        if os_el is not None:
            return os_el.get("name") or ""
        # Some scans lack -O; fall back to service-level ostype hints.
        osc_el = host.find(".//osclass")
        if osc_el is not None:
            return osc_el.get("osfamily") or ""
        return ""