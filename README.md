<div align="center">

```
    ___    ____  ________  _______
   /   |  / __ \/ ____/ / / / ___/
  / /| | / /_/ / / __/ / / /\__ \ 
 / ___ |/ _, _/ /_/ / /_/ /___/ / 
/_/  |_/_/ |_|\____/\____//____/  
                                  
          The giant with a hundred eyes. All-seeing.
          100% local. Zero API keys. Zero cloud.
```

# Argus

### Local-First OSINT Framework

**13 modules. 100% open source. Zero API keys. Zero cloud dependencies.**

[![License: MIT](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue?style=flat-square)](https://www.python.org/)
[![MCP Compatible](https://img.shields.io/badge/MCP-compatible-blueviolet?style=flat-square)](https://modelcontextprotocol.io/)

<p align="center">
  <em>AI issues hard-stop tool calls. Your code executes real binaries. Hallucinated findings are structurally impossible.</em>
</p>

---

</div>

## What is this?

Argus is an OSINT (Open Source Intelligence) investigation framework that runs **entirely on your machine**. No API keys, no cloud services, no telemetry. Every module uses open-source tools and free endpoints.

The AI agent chains tools automatically — describe your target in plain English, Argus decides which tools to run and chains findings across modules. Powered by [Ollama](https://ollama.ai) for local inference.

## Modules

| Module | What it does | Replaces | API Key? |
|--------|-------------|----------|---------|
| `email_recon` | Email → 58 social services | holehe | ❌ |
| `username_enum` | Username → 52 platforms | sherlock | ❌ |
| `subdomains` | Domain → subdomains (crt.sh + DNS brute) | sublist3r | ❌ |
| `crawler` | Crawl URLs, hunt secrets/endpoints/errors | Bright Data | ❌ |
| `network_recon` | nmap port scan + banner grab | Shodan + Censys | ❌ |
| `dns` | DNS records + SPF/DMARC analysis | — | ❌ |
| `whois` | Domain registrant info | — | ❌ |
| `breach` | Query local breach database (you supply the data) | HIBP API ($$$) | ❌ |
| `github` | GitHub profile, repos, commit emails | — | ❌* |
| `phone` | Phone carrier, location, line type | phoneinfoga | ❌ |
| `ipgeo` | IP geolocation (GeoLite2 local DB) | IP2Location API ($$$) | ❌ |
| `dorks` | Generate 12 Google dork URLs | Bright Data SERP | ❌ |
| `paste` | Search paste dumps (psbdmp.ws) | — | ❌ |
| `phishing` | Phishing kit recon: gate/decoy detection, ephemeral tokens, obfuscateur VM + string-pool decode, crypto key extraction, kit-family match, conditional browser escalation (fingerprint-locked) | urlscan.io + any.run + any.run sandbox | ❌ |

*GitHub: 60 req/min free without token, 5000 with optional token.

> **Note on breach_check:** This module queries a **local** SQLite database that you populate yourself. It does not crawl the dark web, access Telegram channels, or query HIBP's backend. If you need comprehensive breach data, [HIBP](https://haveibeenpwned.com) and [intelx](https://intelx.io) are the right tools. The breach module is for researchers who already have breach compilations and want to query them locally without sending emails to a third-party API.

## Quick Start

```bash
# Install
git clone https://github.com/cotcollective/argus.git
cd argus
python3 -m venv venv --copies
./venv/bin/pip install -e .

# Run a single module
./venv/bin/argus dns example.com
./venv/bin/argus whois github.com
./venv/bin/argus subdomains target.com
./venv/bin/argus crawl https://target.com
./venus/bin/argus github username
./venv/bin/argus ipgeo 8.8.8.8
./venv/bin/argus dorks target@email.com
./venv/bin/argus paste target@email.com
./venv/bin/argus email target@example.com
./venv/bin/argus username johndoe
./venv/bin/argus phone +15145551234
./venv/bin/argus breach email@example.com
./venv/bin/argus network 10.0.0.1

# AI-chained investigation (requires Ollama)
./venv/bin/argus investigate "investigate johndoe@gmail.com"

# Interactive REPL
./venv/bin/argus

# JSON output
./venv/bin/argus dns example.com --json

# List all modules
./venv/bin/argus modules
```

## AI Chaining

Argus uses [Ollama](https://ollama.ai) for local AI-powered tool chaining. The AI agent:

1. **Analyzes** your target (email, username, domain, IP, URL, phone)
2. **Selects** which modules to run based on input type
3. **Chains** modules on findings (email → breach → username pivot → platform enum)
4. **Generates** a Markdown + JSON report automatically

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull a model (qwen2.5:7b recommended — native tool-calling support)
ollama pull qwen2.5:7b

# Run an investigation
./venv/bin/argus investigate "investigate the domain github.com"
./venv/bin/argus investigate "who is edoardottt?"
./venv/bin/argus investigate "find everything about john@example.com"
```

No Claude, no Anthropic API, no OpenAI. 100% local inference.

## MCP Server

Argus exposes all 13 modules as [MCP](https://modelcontextprotocol.io/) tools. Connect it to any MCP-compatible client (Hermes Agent, Claude Code, Cursor, etc.):

```yaml
# Hermes Agent config (~/.hermes/config.yaml)
mcp_servers:
  argus:
    command: "/path/to/venv/bin/python3"
    args: ["-m", "argus.mcp_server"]
    timeout: 300
```

After restart, tools appear as `mcp_argus_dns`, `mcp_argus_whois`, `mcp_argus_crawler`, etc.

## Architecture

```
argus/
  cli.py              # Click CLI + prompt-toolkit REPL
  config.py           # Environment-based configuration
  core/
    base.py           # BaseModule ABC + Finding dataclass
    registry.py       # Module registry + auto-discovery
    report.py          # Markdown + JSON report builder
  modules/
    email_recon.py     # 58 services, async, pure Python
    username_enum.py   # 52 platforms, async, pure Python
    subdomain_enum.py  # crt.sh + DNS brute force
    crawler.py         # cariddi Go binary wrapper
    network_recon.py   # nmap XML parser
    dns_recon.py       # dnspython + SPF/DMARC/DKIM
    whois_lookup.py    # python-whois
    breach_check.py    # local SQLite DB
    github_recon.py    # GitHub REST API
    phone_recon.py     # libphonenumber
    ip_geolocation.py  # GeoLite2 + ipinfo.io fallback
    dork_generator.py  # 12 dork URL templates
    paste_search.py    # psbdmp.ws API
  ai/
    chain.py           # Ollama tool-chaining agent
  mcp_server.py        # MCP server (stdio transport)
```

## Optional Enhancements

<details>
<summary>📦 GeoLite2 (100% offline IP geolocation)</summary>

```bash
# Free MaxMind account: https://www.maxmind.com/en/geolite2/signup
# Download GeoLite2-City.mmdb, place at ~/.argus/
./venv/bin/pip install maxminddb
```
</details>

<details>
<summary>📦 Breach Database (local breach compilation)</summary>

```bash
sqlite3 ~/.argus/breaches.db \
  "CREATE TABLE breaches (email TEXT, breach_name TEXT, date TEXT, data_classes TEXT)"
# Import breach compilations via your preferred method
```
</details>

<details>
<summary>📦 Phone full analysis</summary>

```bash
./venv/bin/pip install phonenumbers
```
</details>

<details>
<summary>📦 Cariddi (web crawler engine)</summary>

```bash
# cariddi is the crawler engine (optional — crawler module won't work without it)
git clone https://github.com/edoardottt/cariddi.git
cd cariddi && go get ./... && go build -o /usr/local/bin/cariddi ./cmd/cariddi/
# Or set ARGUS_CARIDDI env var to the binary path
```
</details>

## Configuration

All config via environment variables (all optional):

| Variable | Default | Description |
|----------|---------|-------------|
| `ARGUS_OLLAMA_HOST` | `http://127.0.0.1:11434` | Ollama API host |
| `ARGUS_OLLAMA_MODEL` | `qwen2.5:7b` | Ollama model for AI chaining |
| `ARGUS_CARIDDI` | `cariddi` | Path to cariddi binary |
| `ARGUS_GEOLITE2_DB` | `~/.argus/GeoLite2-City.mmdb` | MaxMind GeoLite2 database path |
| `ARGUS_BREACH_DB` | `~/.argus/breaches.db` | Local breach SQLite database |
| `ARGUS_REPORT_DIR` | `./reports` | Report output directory |
| `ARGUS_GITHUB_TOKEN` | (none) | GitHub token (raises rate limit to 5000/hr) |
| `ARGUS_PROXY` | (none) | HTTP proxy URL |
| `ARGUS_CONCURRENCY` | `20` | Concurrent request limit |
| `ARGUS_TIMEOUT` | `30` | HTTP request timeout (seconds) |

## Integration with other tools

Argus complements offensive security tools:

- **[T3MP3ST](https://github.com/elder-plinius/T3MP3ST)** — red-team harness for CVE hunting, CTF, exploit chains
- **[cariddi](https://github.com/edoardottt/cariddi)** — the crawler engine inside Argus
- **[nmap](https://nmap.org/)** — the network scanner inside Argus

**Natural chain**: Argus cartographie la target → T3MP3ST attaque.

## Philosophy

- **Local-first**: Everything runs on your machine. No cloud calls except target websites.
- **Zero API keys**: Every module works without paid API keys. Replace HIBP, Shodan, Censys, IP2Location with local equivalents.
- **No hallucination**: AI proposes tool calls, code executes real binaries. Findings are real.
- **Modular**: Each module is independent. Run standalone or chained via AI.
- **Open source**: MIT license. Built on open-source tools.

## Legal Disclaimer

> **Argus is intended for legal and authorized use only.**
>
> Users are solely responsible for ensuring their use complies with all applicable laws and regulations. The authors accept no liability for misuse.
>
> Argus is an OSINT (Open Source Intelligence) framework designed for security researchers, penetration testers, bug bounty hunters, and analysts conducting authorized investigations using publicly available information.
>
> **Do not use Argus to:**
> - Stalk, harass, or intimidate individuals
> - Access systems or data without explicit authorization
> - Violate terms of service of any platform
> - Conduct unauthorized surveillance
>
> Always obtain proper authorization before investigating any target. When in doubt, consult legal counsel.

## Credits

**Argus** is built by the [COT Collective](https://github.com/cotcollective) with AI collaboration.

Powered by:
- [cariddi](https://github.com/edoardottt/cariddi) by @edoardottt — web crawler + secret hunter
- [dnspython](https://www.dnspython.org/) — DNS toolkit
- [python-whois](https://github.com/richardpenman/whois) — WHOIS lookup
- [Ollama](https://ollama.ai/) — local LLM inference
- [MCP](https://modelcontextprotocol.io/) — Model Context Protocol

## License

MIT — see [LICENSE](LICENSE) file.