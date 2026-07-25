"""Web crawler module — cariddi wrapper (crawl + secret hunt + endpoint discovery + error detection)."""

import json
import os
import shutil
import subprocess
from typing import List, Optional

from argus.config import config
from argus.core.base import BaseModule, Finding
from argus.core.registry import Registry


@Registry.register
class CrawlerModule(BaseModule):
    """Web crawler + secret hunter + endpoint discovery, backed by the cariddi Go binary.

    cariddi (https://github.com/edoardottt/cariddi) crawls a target URL and emits
    JSON-lines output — one JSON object per crawled page — with fields for url,
    method, status_code, content_type, content_length, words, lines, plus optional
    ``secrets`` / ``errors`` / ``infos`` / ``attacks`` arrays and endpoint match
    metadata when the corresponding hunt flags are enabled.

    This module shells out to the configured cariddi binary, skips the ASCII art
    banner that precedes the JSON stream, parses each line, and returns a flat
    list of ``Finding`` objects keyed by finding type.
    """

    name: str = "crawler"
    description: str = "Web crawler + secret hunter + endpoint discovery (cariddi wrapper)"
    input_type: str = "url"

    # Cariddi's banner is ~12 lines of ASCII art + version + URL + separator.
    _BANNER_MAX_LINES = 14

    def run(self, target: str, **kwargs) -> List[Finding]:
        """Crawl ``target`` with cariddi and return a list of Findings.

        kwargs:
            secrets (bool):     hunt for secrets (-s). Default True.
            endpoints (bool):   hunt for juicy endpoints (-e). Default True.
            errors (bool):     hunt for errors (-err). Default True.
            intensive (bool):   crawl searching for resources matching 2nd level domain (-intensive). Default False.
            depth (int):        max crawl depth from initial URL (-md).
            delay (int):        delay in seconds between pages (-d).
            timeout (int):     subprocess timeout in seconds (default 600).
        """
        cariddi = self._resolve_binary()
        if cariddi is None:
            return [Finding(
                module=self.name,
                target=target,
                key="error",
                value=f"cariddi binary not found at {config.cariddi_path}",
                extra={"hint": "Set ARGUS_CARIDDI or install cariddi and set ARGUS_CARIDDI env var"},
            )]

        cmd = self._build_cmd(cariddi, target, **kwargs)

        timeout = kwargs.get("timeout", 600)
        try:
            # cariddi reads target URLs from stdin, not as positional args
            proc = subprocess.run(
                cmd,
                input=target,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return [Finding(
                module=self.name,
                target=target,
                key="error",
                value=f"cariddi timed out after {timeout}s",
                extra={"command": " ".join(cmd)},
            )]
        except FileNotFoundError as exc:
            return [Finding(
                module=self.name,
                target=target,
                key="error",
                value=f"cariddi failed to launch: {exc}",
                extra={"command": " ".join(cmd)},
            )]
        except Exception as exc:
            return [Finding(
                module=self.name,
                target=target,
                key="error",
                value=f"cariddi failed: {exc}",
                extra={"command": " ".join(cmd)},
            )]

        return self._parse_output(proc.stdout, proc.stderr, target, " ".join(cmd))

    # ------------------------------------------------------------------ #
    # internals
    # ------------------------------------------------------------------ #

    def _resolve_binary(self) -> Optional[str]:
        """Resolve the cariddi binary path, falling back to PATH lookup."""
        path = config.cariddi_path
        if path and os.path.isfile(path) and os.access(path, os.X_OK):
            return path
        # Fallback: look on PATH
        return shutil.which("cariddi")

    def _build_cmd(self, cariddi: str, target: str, **kwargs) -> List[str]:
        """Assemble the cariddi command line from kwargs + config."""
        cmd: List[str] = [cariddi]

        # Hunt flags (kwargs, all default True).
        if kwargs.get("secrets", True):
            cmd.append("-s")
        if kwargs.get("endpoints", True):
            cmd.append("-e")
        if kwargs.get("errors", True):
            cmd.append("-err")

        # Intensive crawl (kwargs, default False).
        if kwargs.get("intensive", False):
            cmd.append("-intensive")

        # Always emit JSON to stdout and randomize user agent.
        cmd.extend(["-json", "-rua"])

        # Concurrency from config.
        cmd.extend(["-c", str(config.concurrency)])

        # Delay between pages (-d).
        delay = kwargs.get("delay")
        if delay is not None:
            cmd.extend(["-d", str(delay)])

        # Max crawl depth (-md).
        depth = kwargs.get("depth")
        if depth is not None:
            cmd.extend(["-md", str(depth)])

        # Proxy from config.
        if config.proxy:
            cmd.extend(["-proxy", config.proxy])

        # Timeout per-request (cariddi -t, seconds). Use Argus config.timeout if set,
        # but don't override a caller-provided ``timeout`` kwarg that means subprocess
        # timeout — keep cariddi's own -t separate to avoid confusion. Only pass -t
        # if explicitly provided via the ``req_timeout`` kwarg.
        req_timeout = kwargs.get("req_timeout")
        if req_timeout is not None:
            cmd.extend(["-t", str(req_timeout)])

        # Target — cariddi accepts a single URL as a positional argument.
        cmd.append(target)
        return cmd

    def _parse_output(
        self,
        stdout: str,
        stderr: str,
        target: str,
        command: str,
    ) -> List[Finding]:
        """Parse cariddi's JSON-lines stdout, skipping the ASCII art banner."""
        findings: List[Finding] = []

        if not stdout or not stdout.strip():
            # No output — cariddi either found nothing or printed only a banner.
            # Surface stderr if present so failures aren't silent.
            err_tail = (stderr or "").strip()[:500]
            if err_tail:
                return [Finding(
                    module=self.name,
                    target=target,
                    key="error",
                    value=f"cariddi produced no JSON output: {err_tail}",
                    extra={"command": command, "stderr": err_tail},
                )]
            return [Finding(
                module=self.name,
                target=target,
                key="no_findings",
                value="cariddi produced no output (target may be unreachable or empty)",
                extra={"command": command},
            )]

        # cariddi prints an ASCII art banner (~12 lines) but no JSON when the
        # target is unreachable / yields nothing. Detect that case up front so
        # callers get a clear "no_findings" instead of an empty list.
        has_any_json = any(
            line.lstrip().startswith("{") for line in stdout.splitlines()
        )
        if not has_any_json:
            err_tail = (stderr or "").strip()[:500]
            msg = "cariddi produced only a banner (no JSON results — target unreachable or empty)"
            extra = {"command": command}
            if err_tail:
                extra["stderr"] = err_tail
            return [Finding(
                module=self.name,
                target=target,
                key="no_findings",
                value=msg,
                extra=extra,
            )]

        # cariddi prints an ASCII art banner (~12 lines) before JSON. We detect
        # banner lines as non-JSON (don't start with '{' or '['). We skip leading
        # non-JSON lines, then parse every subsequent line that starts with '{'.
        saw_json = False
        banner_lines = 0
        for raw in stdout.splitlines():
            stripped = raw.strip()
            if not stripped:
                continue

            if not stripped.startswith("{"):
                # Non-JSON line. Before any JSON we tolerate up to _BANNER_MAX_LINES
                # banner lines; after JSON starts, treat stray non-JSON as debug
                # noise and skip it (cariddi can print progress messages).
                if not saw_json:
                    banner_lines += 1
                    if banner_lines > self._BANNER_MAX_LINES:
                        # Excessive non-JSON prelude — record once as a warning.
                        findings.append(Finding(
                            module=self.name,
                            target=target,
                            key="error",
                            value=f"cariddi emitted {banner_lines} non-JSON lines before JSON (unexpected)",
                            extra={"command": command, "first_line": stripped[:200]},
                        ))
                        return findings
                continue

            saw_json = True
            try:
                obj = json.loads(stripped)
            except json.JSONDecodeError as exc:
                # Skip malformed JSON lines rather than aborting the whole run.
                findings.append(Finding(
                    module=self.name,
                    target=target,
                    key="error",
                    value=f"JSON parse error: {exc}",
                    extra={"command": command, "line": stripped[:200]},
                ))
                continue

            findings.extend(self._obj_to_findings(obj, target))

        if not findings and saw_json:
            findings.append(Finding(
                module=self.name,
                target=target,
                key="no_findings",
                value="cariddi crawled but found no secrets/endpoints/errors",
                extra={"command": command},
            ))

        return findings

    def _obj_to_findings(self, obj: dict, target: str) -> List[Finding]:
        """Convert a single cariddi JSON object into one or more Findings.

        A cariddi result object describes one crawled page and may carry
        additional ``secrets`` / ``errors`` / ``infos`` / ``attacks`` arrays
        plus endpoint match metadata. We emit:
          - one ``url`` finding per page (always),
          - one ``secret`` finding per secret match,
          - one ``error`` finding per error match,
          - one ``endpoint`` finding if endpoint parameters are present,
          - one ``info`` finding per info match.
        """
        out: List[Finding] = []
        url = obj.get("url", "") or ""
        method = obj.get("method", "") or ""
        status_code = obj.get("status_code", 0) or 0
        content_type = obj.get("content_type", "") or ""
        content_length = obj.get("content_length", 0) or 0

        # Base extra dict shared by all findings derived from this object.
        base_extra = {}
        if status_code:
            base_extra["status_code"] = status_code
        if content_type:
            base_extra["content_type"] = content_type
        if method:
            base_extra["method"] = method
        if content_length:
            base_extra["content_length"] = content_length

        # --- Secrets ------------------------------------------------------ #
        secrets = obj.get("secrets") or []
        # secrets can be a list of {name, match, severity} objects or strings.
        for secret in secrets:
            if isinstance(secret, dict):
                sname = secret.get("name", "unknown") or "unknown"
                smatch = secret.get("match", "") or url or ""
                sseverity = secret.get("severity", "") or ""
                sline = secret.get("line", 0) or 0
                extra = dict(base_extra)
                if sseverity:
                    extra["severity"] = sseverity
                if sline:
                    extra["line"] = sline
                extra["secret_name"] = sname
                out.append(Finding(
                    module=self.name,
                    target=target,
                    key="secret",
                    value=smatch,
                    extra=extra,
                ))
            elif isinstance(secret, str) and secret:
                extra = dict(base_extra)
                out.append(Finding(
                    module=self.name,
                    target=target,
                    key="secret",
                    value=secret,
                    extra=extra,
                ))

        # --- Errors ------------------------------------------------------- #
        errors = obj.get("errors") or []
        for err in errors:
            if isinstance(err, dict):
                ematch = err.get("match", "") or url or ""
                ename = err.get("name", "") or ""
                extra = dict(base_extra)
                if ename:
                    extra["error_name"] = ename
                out.append(Finding(
                    module=self.name,
                    target=target,
                    key="error",
                    value=ematch,
                    extra=extra,
                ))
            elif isinstance(err, str) and err:
                out.append(Finding(
                    module=self.name,
                    target=target,
                    key="error",
                    value=err,
                    extra=dict(base_extra),
                ))

        # --- Infos ------------------------------------------------------- #
        infos = obj.get("infos") or []
        for info in infos:
            if isinstance(info, dict):
                imatch = info.get("match", "") or url or ""
                iname = info.get("name", "") or ""
                extra = dict(base_extra)
                if iname:
                    extra["info_name"] = iname
                out.append(Finding(
                    module=self.name,
                    target=target,
                    key="info",
                    value=imatch,
                    extra=extra,
                ))
            elif isinstance(info, str) and info:
                out.append(Finding(
                    module=self.name,
                    target=target,
                    key="info",
                    value=info,
                    extra=dict(base_extra),
                ))

        # --- Endpoint (cariddi emits endpoint match data on the page obj) - #
        # cariddi flags endpoints via a "matches" array (regex hits) and/or a
        # "parameters" array (juicy parameter names). When present, emit one
        # endpoint finding per matched parameter/regex.
        matches = obj.get("matches") or []
        parameters = obj.get("parameters") or []
        endpoint_signals = []
        if isinstance(matches, list):
            endpoint_signals.extend([m for m in matches if m])
        if isinstance(parameters, list):
            endpoint_signals.extend([p for p in parameters if p])

        if endpoint_signals:
            for sig in endpoint_signals:
                if isinstance(sig, dict):
                    sval = sig.get("match") or sig.get("name") or sig.get("pattern") or url
                    extra = dict(base_extra)
                    if sig.get("name"):
                        extra["endpoint_name"] = sig.get("name")
                    out.append(Finding(
                        module=self.name,
                        target=target,
                        key="endpoint",
                        value=sval if isinstance(sval, str) else url,
                        extra=extra,
                    ))
                elif isinstance(sig, str) and sig:
                    out.append(Finding(
                        module=self.name,
                        target=target,
                        key="endpoint",
                        value=sig,
                        extra=dict(base_extra),
                    ))
        elif obj.get("endpoint") or obj.get("filetype") or obj.get("extension"):
            # Fallback: some cariddi versions put endpoint info as top-level
            # fields. Emit a single endpoint finding keyed by the page URL.
            extra = dict(base_extra)
            if obj.get("filetype"):
                extra["filetype"] = obj["filetype"]
            if obj.get("extension"):
                extra["extension"] = obj["extension"]
            out.append(Finding(
                module=self.name,
                target=target,
                key="endpoint",
                value=url,
                extra=extra,
            ))

        # --- Always emit a url finding for the crawled page (unless we
        # already emitted something richer for it) ----------------------- #
        if url and not any(f.key == "url" and f.value == url for f in out):
            out.append(Finding(
                module=self.name,
                target=target,
                key="url",
                value=url,
                extra=dict(base_extra),
            ))

        return out