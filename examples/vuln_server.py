"""Deliberately vulnerable MCP style server.

Test fixture for MCP Warden. Every one of the seven MW weakness classes
is planted below on purpose. Do not use as a reference for real code.
Runs over stdio with a minimal JSON-RPC loop so probe mode can exercise
it locally.
"""

import json
import os
import ssl
import subprocess
import sys
from urllib.parse import urlparse
from urllib.request import urlopen

ADMIN_SECRET = "super-secret-value"
WEBHOOKS = {"alerts": "http://webhooks.internal.example/alerts"}


def tool_read_file(path):
    with open(path) as handle:  # MW001: tool parameter into open(), no validation
        return handle.read()


def tool_get_secret(api_token):
    if api_token:  # MW002: truthiness of the token grants access, never verified
        return {"admin": True, "secret": ADMIN_SECRET}
    raise PermissionError("denied")


def tool_post_webhook(name, payload):
    url = WEBHOOKS[name]
    with urlopen(url, data=json.dumps(payload).encode()) as response:  # MW003: config URL fetched with no host check
        return response.status


def tool_set_workspace(directory):
    os.chdir(directory)  # MW004: handler mutates process global state
    return os.getcwd()


def tool_check_host(url):
    parsed = urlparse(url)
    trusted = False
    if parsed.netloc == "api.example.com":  # MW005: netloc compared instead of hostname
        trusted = True
    if "trusted.example" in url:  # MW005: substring match on the raw URL
        trusted = True
    return {"trusted": trusted}


def tool_run(cmd):
    proc = subprocess.run("ls " + cmd, shell=True, capture_output=True, text=True)  # MW006: shell injection
    return proc.stdout


def tool_fetch(url):
    context = ssl._create_unverified_context()  # MW007: unverified context
    context.check_hostname = False  # MW007: hostname checking off
    context.verify_mode = ssl.CERT_NONE  # MW007: no peer verification
    with urlopen(url, context=context) as response:
        return response.read(200).decode("utf-8", "replace")


TOOLS = {
    "read_file": tool_read_file,
    "get_secret": tool_get_secret,
    "post_webhook": tool_post_webhook,
    "set_workspace": tool_set_workspace,
    "check_host": tool_check_host,
    "run": tool_run,
    "fetch": tool_fetch,
}


def _handle(line):
    request = json.loads(line)
    method = request.get("method")
    rid = request.get("id")
    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": rid,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "vuln-server", "version": "0.1"},
            },
        }
    if method == "notifications/initialized":
        return None
    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": rid,
            "result": {
                "tools": [
                    {"name": name, "inputSchema": {"type": "object"}}
                    for name in TOOLS
                ]
            },
        }
    if method == "tools/call":
        name = request["params"]["name"]
        arguments = request["params"].get("arguments", {})
        try:
            output = TOOLS[name](**arguments)
            return {
                "jsonrpc": "2.0",
                "id": rid,
                "result": {"content": [{"type": "text", "text": str(output)}]},
            }
        except Exception as exc:  # noqa: BLE001 - fixture only
            return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32000, "message": str(exc)}}
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "unknown method"}}


def serve_stdio():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        response = _handle(line)
        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    serve_stdio()
