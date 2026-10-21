"""MCP Warden: a security scanner for Model Context Protocol servers.

Original implementation. Scans Python MCP server source for seven
weakness classes, scores the server, and renders text, JSON, and HTML
dashboard reports.
"""

__version__ = "0.1.0"

from .engine import scan_target, ScanResult, Finding
from .score import score_result, grade_for

__all__ = ["scan_target", "ScanResult", "Finding", "score_result", "grade_for", "__version__"]
