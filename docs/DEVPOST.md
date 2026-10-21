# Devpost submission: MCP Warden

## Project name

MCP Warden

## Tagline

A security scanner that audits MCP servers before a vulnerable tool turns your AI agent into a confused deputy.

## Pitch and overview

AI agents are only as safe as the tools they can call. A Model Context
Protocol server hands an agent real capabilities: read files, fetch URLs,
run commands. If that server has a path traversal bug, a shell injection,
or an authentication check that accepts any nonempty string, then anyone
who can influence a tool parameter owns the host the server runs on. The
agent becomes a confused deputy, executing an attacker's intent with the
server's privileges.

MCP Warden audits the server code before deployment. Point it at a Python
file or directory and it runs seven AST detectors over the source, scores
the server from 100, and renders a report with exact evidence lines and
remediation for every finding:

* MW001 unvalidated file paths in tool handlers (traversal)
* MW002 token presence auth gating (any nonempty string passes)
* MW003 unvalidated remote references resolved into HTTP fetches (SSRF class)
* MW004 global state mutation inside handlers (`os.chdir`, `sys.path`, `os.environ`)
* MW005 weak URL host validation (`netloc` compared instead of `hostname`, substring matching)
* MW006 shell execution with interpolated input (command injection)
* MW007 TLS verification disabled

The weakness classes come from a real audit of a production MCP server,
reimplemented here as original detection code written during this event.

Three report formats cover three audiences: terminal text for the
developer, JSON for CI pipelines, and a single file HTML dashboard for
the security review. The dashboard is a real React 18 app (no build step,
CDN plus htm) with severity and rule filters, full text search,
expandable finding rows showing the offending code and the fix, a Findings
versus Rule Coverage tab switch, an animated score ring with the letter
grade, and KPI cards.

Probe mode goes one step further when the static result needs proof: it
spawns the target over stdio, performs the MCP handshake, and fires
traversal payloads at path like tools, aimed at a canary file the probe
creates and deletes itself. Local fixtures only, never anything remote.

On the bundled vulnerable fixture the scanner fires all seven rules, 11
findings, score 0/100 grade F, and probe mode confirms the traversal
live. On the hardened fixture it reports zero findings, 100/100 grade A,
with the dashboard rendering a clean pass state.

## Built with

Python 3 (standard library only: `ast`, `json`, `subprocess`,
`argparse`), React 18, htm, pytest. The scanner itself has zero third
party runtime dependencies.

## Try it

```bash
git clone https://github.com/coldrazer/mcp-warden.git
cd mcp-warden
pip install -e .
mcpwarden scan examples/vuln_server.py --format html -o report.html
```

All code in this repository was written during the event window.
