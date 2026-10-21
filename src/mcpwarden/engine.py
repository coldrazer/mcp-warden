"""Scan engine: walk a target, parse Python files, run detectors."""

import ast
from dataclasses import dataclass, field
from pathlib import Path

from . import detectors
from .rules import RULE_BY_ID


@dataclass
class Finding:
    rule_id: str
    rule_name: str
    severity: str
    file: str
    line: int
    col: int
    message: str
    evidence: str
    remediation: str

    def to_dict(self):
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "file": self.file,
            "line": self.line,
            "col": self.col,
            "message": self.message,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


@dataclass
class ScanResult:
    target: str
    files_scanned: list = field(default_factory=list)
    skipped_files: list = field(default_factory=list)
    tools: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    probe: dict = field(default_factory=dict)

    def to_dict(self):
        return {
            "target": self.target,
            "files_scanned": self.files_scanned,
            "skipped_files": self.skipped_files,
            "tools": self.tools,
            "findings": [f.to_dict() for f in self.findings],
            "probe": self.probe,
        }


def _tool_names(tree):
    names = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        dec_names = set()
        for dec in node.decorator_list:
            if isinstance(dec, ast.Name):
                dec_names.add(dec.id)
            elif isinstance(dec, ast.Attribute):
                dec_names.add(dec.attr)
        if "tool" in dec_names or node.name.startswith(("tool_", "handle_")):
            names.append(node.name)
    return names


def _scan_file(path):
    source = path.read_text(encoding="utf-8", errors="replace")
    tree = ast.parse(source, filename=str(path))
    findings = []
    for rule_id, detector in detectors.DETECTORS.items():
        rule = RULE_BY_ID[rule_id]
        for rid, lineno, col, message, evidence in detector(tree, source, str(path)):
            findings.append(Finding(
                rule_id=rid,
                rule_name=rule["name"],
                severity=rule["severity"],
                file=str(path),
                line=lineno,
                col=col,
                message=message,
                evidence=evidence,
                remediation=rule["remediation"],
            ))
    return findings, _tool_names(tree)


def scan_target(target):
    """Scan a file or directory of Python source. Returns ScanResult."""
    root = Path(target)
    if root.is_file():
        files = [root]
    else:
        files = sorted(p for p in root.rglob("*.py") if p.is_file())
    result = ScanResult(target=str(target))
    for path in files:
        try:
            findings, tools = _scan_file(path)
        except (SyntaxError, UnicodeDecodeError, ValueError, OSError):
            # Unparseable or unreadable files are reported as skipped,
            # never silently counted as clean and never a crash.
            result.skipped_files.append(str(path))
            continue
        result.files_scanned.append(str(path))
        result.tools.extend(t for t in tools if t not in result.tools)
        result.findings.extend(findings)
    result.findings.sort(key=lambda f: (f.severity != "critical", f.rule_id, f.file, f.line))
    return result
