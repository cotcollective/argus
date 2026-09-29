"""Argus CLI — Click-based CLI + prompt-toolkit REPL."""

import sys
import json
import click
from rich.console import Console
from rich.table import Table

from argus.core.registry import Registry, auto_discover
from argus.core.report import ReportBuilder
from argus.config import config

console = Console()


def _detect_input_type(target: str) -> str:
    """Auto-detect input type from target string."""
    target = target.strip()
    if "@" in target and "." in target.split("@")[-1]:
        return "email"
    if target.startswith("http://") or target.startswith("https://"):
        return "url"
    if target.replace(".", "").replace("-", "").isdigit() and target.count(".") >= 3:
        return "ip"
    if target.startswith("+") or target.replace("+", "").replace("-", "").replace(" ", "").isdigit():
        if len(target.replace("+", "").replace("-", "").replace(" ", "")) >= 10:
            return "phone"
    return "username"


def _run_module(name: str, target: str, json_out: bool = False, md_out: bool = False) -> None:
    """Run a single module and print results."""
    mod = Registry.get(name)
    if not mod:
        console.print(f"[red]Module '{name}' not found. Available: {Registry.names()}[/]")
        return
    try:
        if json_out:
            click.echo(mod.to_json(target))
        elif md_out:
            click.echo(mod.to_markdown(target))
        else:
            findings = mod.run(target)
            if not findings:
                console.print(f"[yellow]No findings for {target}[/]")
                return
            table = Table(title=f"Argus — {mod.name} — {target}")
            table.add_column("Key", style="cyan")
            table.add_column("Value", style="white")
            table.add_column("Extra", style="dim")
            for f in findings:
                extra_str = ", ".join(f"{k}={v}" for k, v in f.extra.items()) if f.extra else ""
                table.add_row(f.key, f.value[:120], extra_str[:80])
            console.print(table)
    except Exception as e:
        console.print(f"[red]Error: {e}[/]")


@click.group(invoke_without_command=True)
@click.option("--json", "json_out", is_flag=True, help="JSON output")
@click.option("--md", "md_out", is_flag=True, help="Markdown output")
@click.option("--provider", default=None, help="AI provider (ollama)")
@click.option("--ollama-model", default=None, help="Ollama model")
@click.pass_context
def main(ctx, json_out, md_out, provider, ollama_model):
    """Argus — Local-first OSINT framework. The giant with a hundred eyes."""
    auto_discover()
    if ctx.invoked_subcommand is None:
        _repl()


def _repl():
    """Interactive REPL."""
    from prompt_toolkit import PromptSession
    session = PromptSession()
    console.print("[bold green]Argus[/] — Local-first OSINT framework")
    console.print(f"Modules: {', '.join(Registry.names())}")
    console.print("Type 'help' for commands, 'exit' to quit.\n")

    while True:
        try:
            user_input = session.prompt("argus> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not user_input:
            continue
        if user_input in ("exit", "quit"):
            break
        if user_input == "help":
            console.print("Commands:")
            console.print("  investigate <target>  — AI-chained investigation")
            console.print("  <module> <target>       — Run single module")
            console.print("  modules                  — List modules")
            console.print("  exit                     — Quit")
            continue
        if user_input == "modules":
            for name in Registry.names():
                mod = Registry.get(name)
                console.print(f"  {name:15} {mod.description}")
            continue
        if user_input.startswith("investigate "):
            target = user_input[12:].strip()
            from argus.ai.chain import investigate
            investigate(target)
            continue

        parts = user_input.split(None, 1)
        if len(parts) == 2:
            mod_name, target = parts
            if mod_name in Registry.names():
                _run_module(mod_name, target)
            else:
                console.print(f"[red]Unknown module: {mod_name}[/]")
        else:
            console.print("[yellow]Usage: <module> <target>[/]")

    console.print("[dim]Goodbye.[/]")


# CLI commands
@main.command()
@click.argument("target")
@click.option("--json", "json_out", is_flag=True)
def email(target, json_out):
    """Email to social account enumeration."""
    _run_module("email_recon", target, json_out=json_out)


@main.command()
@click.argument("target")
@click.option("--json", "json_out", is_flag=True)
def username(target, json_out):
    """Username enumeration across platforms."""
    _run_module("username_enum", target, json_out=json_out)


@main.command()
@click.argument("target")
@click.option("--json", "json_out", is_flag=True)
def subdomains(target, json_out):
    """Subdomain enumeration."""
    _run_module("subdomains", target, json_out=json_out)


@main.command()
@click.argument("target")
@click.option("--json", "json_out", is_flag=True)
@click.option("--proxy", default=None, help="Proxy URL (e.g. socks5h://127.0.0.1:9050)")
def phishing(target, json_out, proxy):
    """Phishing kit recon — gates, ephemeral tokens, obfuscateur, crypto keys, family match."""
    if proxy:
        import socket as _s
        orig = _s.socket
        try:
            import socks  # PySocks if present
            _s.setdefaultproxy if False else None
            socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 9050, rdns=True) if proxy.startswith("socks") else None
            _s.socket = socks.socksocket
        except Exception:
            pass
    _run_module("phishing", target, json_out=json_out)


@main.command()
@click.argument("target")
@click.option("--json", "json_out", is_flag=True)
def crawl(target, json_out):
    """Web crawler + secret hunter (cariddi wrapper)."""
    _run_module("crawler", target, json_out=json_out)


@main.command()
@click.argument("target")
@click.option("--json", "json_out", is_flag=True)
def dns(target, json_out):
    """DNS record enumeration."""
    _run_module("dns", target, json_out=json_out)


@main.command()
@click.argument("target")
@click.option("--json", "json_out", is_flag=True)
def whois(target, json_out):
    """WHOIS lookup."""
    _run_module("whois", target, json_out=json_out)


@main.command()
@click.argument("target")
@click.option("--ports", default=None, help="Port range (e.g. 1-1000)")
@click.option("--json", "json_out", is_flag=True)
def network(target, ports, json_out):
    """Network recon via nmap."""
    _run_module("network_recon", target, json_out=json_out)


@main.command()
@click.argument("target")
@click.option("--json", "json_out", is_flag=True)
def ipgeo(target, json_out):
    """IP geolocation."""
    _run_module("ipgeo", target, json_out=json_out)


@main.command()
@click.argument("target")
@click.option("--json", "json_out", is_flag=True)
def github(target, json_out):
    """GitHub OSINT."""
    _run_module("github", target, json_out=json_out)


@main.command()
@click.argument("target")
@click.option("--json", "json_out", is_flag=True)
def dorks(target, json_out):
    """Generate Google dork URLs."""
    _run_module("dorks", target, json_out=json_out)


@main.command()
@click.argument("target")
@click.option("--json", "json_out", is_flag=True)
def paste(target, json_out):
    """Search paste dumps."""
    _run_module("paste", target, json_out=json_out)


@main.command()
@click.argument("target")
@click.option("--json", "json_out", is_flag=True)
def breach(target, json_out):
    """Check local breach DB."""
    _run_module("breach", target, json_out=json_out)


@main.command()
@click.argument("target")
@click.option("--json", "json_out", is_flag=True)
def phone(target, json_out):
    """Phone number intelligence."""
    _run_module("phone", target, json_out=json_out)


@main.command()
@click.argument("target")
def investigate(target):
    """AI-chained investigation via Ollama."""
    from argus.ai.chain import investigate
    investigate(target)


@main.command()
def mcp():
    """Start MCP server."""
    from argus.mcp_server import run_mcp
    run_mcp()


@main.command()
def modules():
    """List all available modules."""
    auto_discover()
    for name in Registry.names():
        mod = Registry.get(name)
        console.print(f"  {name:15} {mod.description}")


if __name__ == "__main__":
    main()