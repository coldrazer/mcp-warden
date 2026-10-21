"""Probe mode: safe, local-only dynamic confirmation.

Spawns a target Python file as a stdio MCP server, performs the MCP
handshake, lists tools, and calls path like parameters with traversal
payloads aimed at a canary file created just for the probe. The target
is always a local file; nothing here touches any remote system.
"""

import json
import os
import secrets
import select
import subprocess
import sys
import tempfile
import time
from pathlib import Path

CANARY_PREFIX = "mcpwarden-canary-"
_PATH_PARAM_NAMES = ("path", "file", "filepath", "filename", "file_path")


def _send(proc, obj):
    proc.stdin.write(json.dumps(obj) + "\n")
    proc.stdin.flush()


def _read_response(proc, want_id, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        ready, _, _ = select.select([proc.stdout], [], [], max(0.1, deadline - time.time()))
        if not ready:
            continue
        line = proc.stdout.readline()
        if not line:
            return None
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if message.get("id") == want_id:
            return message
    return None


def _response_text(message):
    if not message:
        return ""
    result = message.get("result") or {}
    content = result.get("content") or []
    texts = [c.get("text", "") for c in content if isinstance(c, dict)]
    return "\n".join(texts)


def probe_target(target, timeout=8):
    """Probe a local Python file. Returns a JSON-serializable dict."""
    path = Path(target)
    if not path.is_file() or path.suffix != ".py":
        return {"status": "skipped", "detail": "probe mode needs a single Python file target"}
    token = CANARY_PREFIX + secrets.token_hex(8)
    tmpdir = Path(tempfile.mkdtemp(prefix="mcpwarden-probe-"))
    canary = tmpdir / "canary.txt"
    canary.write_text("probe canary %s\n" % token)
    fixture_dir = str(path.parent)
    rel = os.path.relpath(str(canary), fixture_dir)
    payloads = [str(canary), "../" * 8 + rel]

    proc = subprocess.Popen(
        [sys.executable, str(path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1,
    )
    outcome = {"status": "error", "detail": "probe did not complete"}
    try:
        _send(proc, {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "mcp-warden-probe", "version": "0.1.0"},
            },
        })
        if _read_response(proc, 1, timeout) is None:
            return {"status": "error", "detail": "no initialize response from target"}
        _send(proc, {"jsonrpc": "2.0", "method": "notifications/initialized"})
        _send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        tools_msg = _read_response(proc, 2, timeout)
        tools = ((tools_msg or {}).get("result") or {}).get("tools") or []
        path_tool = None
        for tool in tools:
            name = tool.get("name", "")
            if "read" in name.lower() or "file" in name.lower():
                path_tool = name
                break
        if not path_tool:
            return {"status": "not-applicable", "detail": "no path-like tool advertised by target"}
        for param in _PATH_PARAM_NAMES:
            for payload in payloads:
                _send(proc, {
                    "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                    "params": {"name": path_tool, "arguments": {param: payload}},
                })
                message = _read_response(proc, 3, timeout)
                text = _response_text(message)
                if token in text:
                    outcome = {
                        "status": "confirmed",
                        "tool": path_tool,
                        "parameter": param,
                        "payload": payload,
                        "detail": "traversal payload read the probe canary outside the fixture root",
                    }
                    return outcome
        outcome = {
            "status": "not-confirmed",
            "tool": path_tool,
            "detail": "path-like tool refused or contained the traversal payloads",
        }
        return outcome
    finally:
        try:
            proc.kill()
        except OSError:
            pass
        try:
            canary.unlink()
            tmpdir.rmdir()
        except OSError:
            pass
