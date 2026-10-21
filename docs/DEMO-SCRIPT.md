# MCP Warden demo script (3 to 5 minutes)

Total target: about 4 minutes. Beats are timed for a screen recording
with terminal on the left and the HTML dashboard on the right.

## Beat 1 — The problem (0:00 to 0:45)

"AI agents are only as safe as the tools they can call. An MCP server
gives an agent real capabilities: read files, fetch URLs, run commands.
If that server has a path traversal bug or a shell injection, anyone who
can influence a tool parameter owns the machine it runs on. The agent
becomes a confused deputy. MCP Warden audits the server code before it
ever deploys."

Show: the vulnerable fixture open in an editor, scrolled slowly past
`tool_read_file`, `tool_run`, `tool_get_secret`.

## Beat 2 — The scan (0:45 to 1:45)

"Point it at the server. Seven detectors walk the AST looking for the
weakness classes: unvalidated file paths, token presence auth gating,
unvalidated remote references, global state mutation in handlers, weak
host validation, shell interpolation, and disabled TLS."

Run: `mcpwarden scan examples/vuln_server.py`

Read the terminal output aloud as it appears: "Score zero out of one
hundred, grade F. Ten findings. One critical, six high, three medium.
Every rule fired."

## Beat 3 — The dashboard (1:45 to 3:00)

"Same scan, HTML dashboard. One self contained file, a real React app."

Open `dashboard-vuln.html`. Point at the score ring animating to F, the
KPI cards, then: click the critical chip, one row left, MW006. Expand it:
"There is the evidence, the exact line, and the remediation." Switch to
the Rule Coverage tab: "All seven rules, fired counts, what each one
means and how to fix it." Type "chdir" in search: "Full text search
across files, rules, and messages."

## Beat 4 — Proof, not just flags (3:00 to 3:40)

"Static findings are claims. Probe mode proves the traversal."

Run: `mcpwarden scan examples/vuln_server.py --probe`

"Probe: confirmed. It spawned the server over stdio, did the MCP
handshake, and read a canary file outside the fixture root with a
traversal payload. Local fixtures only, nothing remote, the canary is
created and deleted by the probe itself."

## Beat 5 — The clean side (3:40 to 4:20)

"And the hardened version of the same server."

Run: `mcpwarden scan examples/safe_server.py`

"Score one hundred, grade A, zero findings." Open
`dashboard-safe.html`: "The dashboard renders a clean pass state, and
Rule Coverage shows all seven rules green."

## Close (4:20 to 4:30)

"MCP Warden. Audit the server before the agent trusts it."
