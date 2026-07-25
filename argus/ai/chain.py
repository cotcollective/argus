"""AI chaining layer — Ollama tool-chaining agent for investigations."""

import json
import requests
from rich.console import Console

from argus.core.registry import Registry, auto_discover
from argus.core.report import ReportBuilder
from argus.config import config

console = Console()

SYSTEM_PROMPT = """You are Argus, an OSINT investigation agent. You have access to the following tools:

{tools_description}

When investigating a target, you must:
1. Analyze the input target (email, username, domain, IP, URL, phone)
2. Select which tools to run based on the target type
3. Chain tools on findings (e.g. email → username pivot → platform enum, domain → subdomains → DNS)
4. Output a structured investigation plan as JSON

Available tools and their input types:
- email_recon (input: email) — find social accounts linked to an email
- username_enum (input: username) — find profiles across 50+ platforms
- subdomains (input: domain) — enumerate subdomains
- crawler (input: url) — crawl website, hunt for secrets/endpoints
- network_recon (input: ip) — nmap port scan + service detection
- dns (input: domain) — DNS records + SPF/DMARC analysis
- whois (input: domain) — domain registrant info
- breach (input: email) — check local breach DB
- github (input: username) — GitHub profile, repos, commit emails
- phone (input: phone) — phone number intelligence
- ipgeo (input: ip) — IP geolocation
- dorks (input: auto) — generate Google dork URLs
- paste (input: auto) — search paste dumps

Respond with a JSON array of tool calls to execute:
[{{"tool": "tool_name", "target": "target_value"}}]

Example: investigating "john@example.com"
[
  {{"tool": "email_recon", "target": "john@example.com"}},
  {{"tool": "breach", "target": "john@example.com"}},
  {{"tool": "dorks", "target": "john@example.com"}},
  {{"tool": "paste", "target": "john@example.com"}}
]

Then if email_recon finds username "john99", next round:
[
  {{"tool": "username_enum", "target": "john99"}},
  {{"tool": "github", "target": "john99"}}
]

Be thorough but efficient. Don't run tools that don't match the input type."""


def _call_ollama(messages: list, model: str = None) -> str:
    """Call Ollama API for AI chaining."""
    model = model or config.ollama_model
    try:
        resp = requests.post(
            f"{config.ollama_host}/api/chat",
            json={
                "model": model,
                "messages": messages,
                "stream": False,
                "format": "json",
                "options": {"temperature": 0.3, "num_predict": 2048},
            },
            timeout=120,
        )
        data = resp.json()
        return data.get("message", {}).get("content", "")
    except Exception as e:
        return f'{{"error": "{e}"}}'


def _detect_input_type(target: str) -> str:
    """Auto-detect input type."""
    target = target.strip()
    if "@" in target and "." in target.split("@")[-1]:
        return "email"
    if target.startswith("http://") or target.startswith("https://"):
        return "url"
    parts = target.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return "ip"
    if target.startswith("+") and target[1:].replace("-", "").replace(" ", "").isdigit():
        return "phone"
    return "username"


def investigate(target: str, max_rounds: int = 3):
    """Run an AI-chained investigation on a target."""
    auto_discover()

    console.print(f"\n[bold green]Argus Investigation[/] — {target}\n")

    all_findings = []
    module_runs = []

    # Build tools description
    tools_desc = "\n".join(
        f"- {name}: {Registry.get(name).description} (input: {Registry.get(name).input_type})"
        for name in Registry.names()
    )

    system_msg = SYSTEM_PROMPT.format(tools_description=tools_desc)
    messages = [
        {"role": "system", "content": system_msg},
        {"role": "user", "content": f"Investigate: {target}"},
    ]

    for round_num in range(1, max_rounds + 1):
        console.print(f"[dim]Round {round_num} — AI selecting tools...[/]")

        # Ask AI which tools to run
        response_text = _call_ollama(messages)

        # Parse tool calls
        try:
            # Strip markdown code fences if present
            clean = response_text.strip()
            if clean.startswith("```"):
                clean = clean.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
            parsed = json.loads(clean)
            # Normalize: if model returns a single dict, wrap in list
            if isinstance(parsed, dict):
                parsed = [parsed]
            tool_calls = parsed
        except json.JSONDecodeError:
            console.print(f"[yellow]AI response not parseable as JSON. Ending.[/]")
            break

        if not isinstance(tool_calls, list) or not tool_calls:
            console.print(f"[dim]No more tools to run. Investigation complete.[/]")
            break

        # Execute tools
        for tc in tool_calls:
            tool_name = tc.get("tool")
            tool_target = tc.get("target", target)

            if tool_name not in Registry.names():
                console.print(f"[red]Unknown tool: {tool_name}[/]")
                continue

            console.print(f"  [cyan]→ {tool_name}({tool_target})[/]")
            mod = Registry.get(tool_name)
            try:
                findings = mod.run(tool_target)
                console.print(f"    [green]{len(findings)} findings[/]")
                all_findings.extend(findings)
                module_runs.append({
                    "module": tool_name,
                    "target": tool_target,
                    "count": len(findings),
                })
            except Exception as e:
                console.print(f"    [red]Error: {e}[/]")
                module_runs.append({
                    "module": tool_name,
                    "target": tool_target,
                    "error": str(e),
                })

        # Feed findings back to AI for next round
        findings_summary = json.dumps(
            [{"key": f.key, "value": f.value[:200]} for f in all_findings[-20:]],
            indent=2,
        )
        messages.append({"role": "assistant", "content": response_text})
        messages.append({
            "role": "user",
            "content": f"Findings so far:\n{findings_summary}\n\nBased on these findings, what tools should I run next? Respond with JSON array of tool calls, or empty array if investigation is complete.",
        })

    # Generate report
    report_builder = ReportBuilder()
    report_path = report_builder.save(target, all_findings, module_runs)
    console.print(f"\n[bold green]Investigation complete![/]")
    console.print(f"Total findings: {len(all_findings)}")
    console.print(f"Report saved: {report_path}")