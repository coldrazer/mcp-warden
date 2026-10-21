"""Hardened MCP style server.

Clean fixture for MCP Warden: the same tool surface as the vulnerable
fixture, with every weakness class fixed. The scanner must report zero
findings on this file.
"""

import hmac
import json
import os
import ssl
import subprocess
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import urlopen

DATA_ROOT = Path("/tmp/mcpwarden_safe_data")
ALLOWED_HOSTS = {"api.example.com", "hooks.example.com"}
ALLOWED_COMMANDS = {"list": ["ls", "-la"]}
EXPECTED_TOKEN = os.environ.get("WARDEN_TOKEN", "dev-token")


def tool(func):
    """Mark a function as an MCP tool."""
    func._is_tool = True
    return func


def _confine(path):
    target = (DATA_ROOT / path).resolve()
    if not target.is_relative_to(DATA_ROOT):
        raise PermissionError("path escapes the data root")
    return target


def verify_token(token):
    return bool(token) and hmac.compare_digest(token, EXPECTED_TOKEN)


@tool
def tool_read_file(path):
    target = _confine(path)
    return target.read_text()


@tool
def tool_get_secret(api_token):
    if not verify_token(api_token):
        raise PermissionError("denied")
    return {"admin": True}


@tool
def tool_post_webhook(url, payload):
    parsed = urlparse(url)
    if parsed.hostname not in ALLOWED_HOSTS:
        raise PermissionError("host is not allowlisted")
    with urlopen(url, data=json.dumps(payload).encode(), context=ssl.create_default_context()) as response:
        return response.status


@tool
def tool_check_host(url):
    parsed = urlparse(url)
    return {"trusted": parsed.hostname == "api.example.com"}


@tool
def tool_run(name):
    if name not in ALLOWED_COMMANDS:
        raise PermissionError("command is not allowlisted")
    proc = subprocess.run(ALLOWED_COMMANDS[name], shell=False, capture_output=True, text=True)
    return proc.stdout
