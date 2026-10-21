# MCP Warden

A security scanner for Model Context Protocol (MCP) servers.

MCP servers hand AI agents real tools: read files, fetch URLs, run commands.
A vulnerable server turns the agent into a confused deputy, executing an
attacker's intent with the server's privileges. MCP Warden audits the server
code *before* deployment, confirms what it can with safe local probes, and
issues a scored report with concrete remediation for every finding.

## The rules

Seven weakness classes, each with an ID, severity, and remediation text:

| ID | Severity | What it detects |
|----|----------|-----------------|
| MW001 | High | Tool parameter reaches a file open with no allowlist or root confinement |
| MW002 | High | Sensitive capability gated on mere truthiness of a token, never verified |
| MW003 | High | URL from user or config input passed to an HTTP fetch with no host check (SSRF class) |
| MW004 | Medium | Tool handler mutates process global state (`os.chdir`, `sys.path`, `os.environ`) |
| MW005 | Medium | Weak host validation: `netloc` compared instead of `hostname`, or substring matching on the raw URL |
| MW006 | Critical | Tool input interpolated into a shell command string (command injection) |
| MW007 | High | TLS verification disabled (`verify=False`, unverified contexts, `CERT_NONE`) |

## Install

Python 3.11 or newer. No third party dependencies; the scanner is standard
library only (`ast`, `json`, `subprocess`, `argparse`).

```bash
git clone https://github.com/coldrazer/mcp-warden.git
cd mcp-warden
pip install -e .
```

Or run without installing:

```bash
PYTHONPATH=src python -m mcpwarden scan <target>
```

## Usage

```bash
mcpwarden scan path/to/server.py
mcpwarden scan path/to/server.py --format json -o report.json
mcpwarden scan path/to/server.py --format html -o dashboard.html
mcpwarden scan path/to/server.py --probe        # local dynamic confirmation
mcpwarden scan path/to/servers/                # scan a whole directory
```

Exit code is 1 when findings exist, 0 when the target is clean.

The HTML dashboard is a single self contained file: React 18 plus htm render
the embedded scan JSON with severity and rule filters, search, expandable
finding rows with evidence and remediation, a Findings / Rule Coverage tab
switch, an animated score ring, and KPI cards.

## Scoring

Every server starts at 100. Each finding subtracts its severity weight
(critical 25, high 15, medium 8, low 3), floored at 0. Grades: A 90+,
B 75+, C 60+, D 40+, F below 40.

## Demo results on the bundled fixtures

`examples/vuln_server.py` plants all seven weakness classes on purpose:

```
$ mcpwarden scan examples/vuln_server.py
Score: 0/100  Grade: F
Files scanned: 1   Tools detected: 7   Findings: 10
By severity: critical: 1, high: 6, medium: 3
```

`examples/safe_server.py` is the hardened equivalent:

```
$ mcpwarden scan examples/safe_server.py
Score: 100/100  Grade: A
No findings. All seven rules are clean.
```

Probe mode confirms the traversal live against the local fixture only:

```
$ mcpwarden scan examples/vuln_server.py --probe
Probe: confirmed
```

## Open source used

Per the event rules, everything third party is declared here: the scanner
itself uses only the Python standard library. The generated HTML dashboard
loads React 18, ReactDOM 18, and htm 3 from the unpkg CDN at view time and
embeds the scan results as JSON; no build step, no transpiler. The pytest
suite is the only dev dependency.

## Layout

```
src/mcpwarden/
  __main__.py    CLI: scan TARGET [--format text|json|html] [--probe]
  engine.py      target walking, per file scanning, tool detection
  detectors.py   the seven AST rule detectors
  rules.py       rule catalog, severities, weights
  score.py       100 point scoring and letter grades
  report.py      text, JSON, and HTML dashboard rendering
  probe.py       local only stdio probe for traversal confirmation
examples/
  vuln_server.py deliberately vulnerable MCP style server (all 7 classes)
  safe_server.py hardened equivalent (zero findings)
tests/           pytest suite: every rule fires on vuln, none on safe
docs/
  ARCHITECTURE.md  threat model and pipeline diagram
  DEVPOST.md       submission pitch text
  DEMO-SCRIPT.md   3 to 5 minute video narration
```

## License

MIT. See LICENSE.
