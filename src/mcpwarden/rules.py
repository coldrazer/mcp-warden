"""Rule catalog for MCP Warden: id, name, severity, and remediation text."""

RULES = [
    {
        "id": "MW001",
        "name": "Unvalidated file path in tool handler",
        "severity": "high",
        "description": (
            "A tool parameter flows into a file open call with no allowlist "
            "and no confinement of the resolved path under an expected root. "
            "An agent or caller can request paths outside the intended directory."
        ),
        "remediation": (
            "Resolve the path and require it to stay under an allowlisted root "
            "directory (for example pathlib resolve plus is_relative_to), or "
            "map the parameter through an explicit allowlist of permitted files."
        ),
    },
    {
        "id": "MW002",
        "name": "Token presence auth gating",
        "severity": "high",
        "description": (
            "Access to a sensitive capability is granted on the mere truthiness "
            "of a token variable instead of a real verification call. Any "
            "nonempty string passes the gate."
        ),
        "remediation": (
            "Verify the token with a real check on every call: compare against "
            "the expected secret with hmac.compare_digest, validate a signature, "
            "or call the issuing authority. Never treat a nonempty token as proof."
        ),
    },
    {
        "id": "MW003",
        "name": "Remote reference resolution without validation",
        "severity": "high",
        "description": (
            "A URL taken from user or config input is passed straight into an "
            "HTTP fetch. A crafted reference can make the server request "
            "internal or attacker controlled endpoints (SSRF class)."
        ),
        "remediation": (
            "Parse the URL, check the hostname against an explicit allowlist, "
            "reject non http(s) schemes, and consider blocking private IP ranges "
            "before any fetch."
        ),
    },
    {
        "id": "MW004",
        "name": "Global state mutation in tool handler",
        "severity": "medium",
        "description": (
            "A tool handler mutates process global state such as the working "
            "directory, sys.path, or the environment. In a concurrent server "
            "this races across requests and can escape the intended sandbox."
        ),
        "remediation": (
            "Keep handlers stateless. Use absolute paths, pass configuration "
            "explicitly, and never call os.chdir or rewrite sys.path or "
            "os.environ from inside a tool handler."
        ),
    },
    {
        "id": "MW005",
        "name": "Weak URL host validation",
        "severity": "medium",
        "description": (
            "Host checks compare urlparse netloc instead of hostname, or match "
            "hosts with substring tests on the raw URL string. Ports, userinfo, "
            "and crafted prefixes slip past both patterns."
        ),
        "remediation": (
            "Compare the parsed hostname for exact equality, or test membership "
            "in an explicit allowlist of hostnames. Never use substring matching "
            "on the URL string."
        ),
    },
    {
        "id": "MW006",
        "name": "Shell execution with interpolated input",
        "severity": "critical",
        "description": (
            "Tool input is interpolated into a shell command string run with a "
            "shell. This is direct command injection: a crafted parameter runs "
            "arbitrary commands as the server user."
        ),
        "remediation": (
            "Never build shell strings from input. Pass argument lists to "
            "subprocess with shell disabled, and validate any parameter against "
            "an allowlist before use."
        ),
    },
    {
        "id": "MW007",
        "name": "TLS verification disabled",
        "severity": "high",
        "description": (
            "TLS certificate verification is turned off for outbound HTTPS. "
            "Connections become trivially interceptable by anyone on the path."
        ),
        "remediation": (
            "Leave verification enabled. Pin certificates or install the needed "
            "CA bundle instead of disabling the check."
        ),
    },
]

RULE_BY_ID = {r["id"]: r for r in RULES}

SEVERITY_WEIGHTS = {"critical": 25, "high": 15, "medium": 8, "low": 3}
