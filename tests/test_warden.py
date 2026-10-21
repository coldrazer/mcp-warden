"""MCP Warden test suite."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
EXAMPLES = ROOT / "examples"
VULN = EXAMPLES / "vuln_server.py"
SAFE = EXAMPLES / "safe_server.py"

sys.path.insert(0, str(SRC))

from mcpwarden import grade_for, scan_target, score_result  # noqa: E402
from mcpwarden.report import build_payload, render_html, render_json, render_text  # noqa: E402
from mcpwarden.rules import RULES  # noqa: E402


def test_every_rule_fires_on_vuln_fixture():
    result = scan_target(VULN)
    fired = {f.rule_id for f in result.findings}
    expected = {r["id"] for r in RULES}
    assert fired == expected, "missing rules: %s" % (expected - fired)


def test_zero_findings_on_safe_fixture():
    result = scan_target(SAFE)
    assert result.findings == []


def test_vuln_scores_f_and_safe_scores_a():
    vuln = score_result(scan_target(VULN))
    safe = score_result(scan_target(SAFE))
    assert safe["score"] == 100
    assert safe["grade"] == "A"
    assert vuln["score"] < 100
    assert vuln["grade"] in ("D", "F")


def test_grade_boundaries():
    assert grade_for(100) == "A"
    assert grade_for(90) == "A"
    assert grade_for(89) == "B"
    assert grade_for(75) == "B"
    assert grade_for(74) == "C"
    assert grade_for(60) == "C"
    assert grade_for(59) == "D"
    assert grade_for(40) == "D"
    assert grade_for(39) == "F"
    assert grade_for(0) == "F"


def test_tools_detected():
    vuln = scan_target(VULN)
    assert "tool_read_file" in vuln.tools
    assert len(vuln.tools) >= 5


def _run_cli(*args):
    return subprocess.run(
        [sys.executable, "-m", "mcpwarden", "scan", *args],
        cwd=ROOT,
        env={"PYTHONPATH": str(SRC), "PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_cli_text_on_vuln_reports_findings():
    proc = _run_cli(str(VULN))
    assert proc.returncode == 1
    assert "MW006" in proc.stdout
    assert "Score:" in proc.stdout


def test_cli_text_on_safe_is_clean():
    proc = _run_cli(str(SAFE))
    assert proc.returncode == 0
    assert "No findings" in proc.stdout


def test_cli_json_is_machine_readable(tmp_path):
    out = tmp_path / "report.json"
    proc = _run_cli(str(VULN), "--format", "json", "-o", str(out))
    assert proc.returncode == 1
    payload = json.loads(out.read_text())
    assert payload["score"] < 100
    assert len(payload["findings"]) > 0
    assert set(payload["rules"]) == {r["id"] for r in RULES}


def test_cli_html_embeds_results(tmp_path):
    out = tmp_path / "report.html"
    proc = _run_cli(str(VULN), "--format", "html", "-o", str(out))
    assert proc.returncode == 1
    page = out.read_text()
    assert "MCP WARDEN" in page
    assert "react.production.min.js" in page
    assert "MW006" in page
    assert '"score"' in page


def test_cli_html_safe_fixture_shows_clean_pass(tmp_path):
    out = tmp_path / "clean.html"
    proc = _run_cli(str(SAFE), "--format", "html", "-o", str(out))
    assert proc.returncode == 0
    page = out.read_text()
    assert "Clean pass" in page


def test_render_text_lists_all_rules(tmp_path):
    result = scan_target(VULN)
    payload = build_payload(result, score_result(result))
    text = render_text(payload)
    for rule in RULES:
        assert rule["id"] in text


def test_cli_missing_target_errors_cleanly():
    proc = _run_cli(str(EXAMPLES / "does_not_exist.py"))
    assert proc.returncode == 2
    assert "target not found" in proc.stderr
    assert "Traceback" not in proc.stderr


def test_scan_skips_unparseable_and_directory_entries(tmp_path):
    (tmp_path / "broken.py").write_text("def broken(:\n")
    (tmp_path / "fake.py").mkdir()
    good = tmp_path / "good.py"
    good.write_text("x = 1\n")
    result = scan_target(tmp_path)
    assert result.files_scanned == [str(good)]
    assert result.skipped_files == [str(tmp_path / "broken.py")]


def test_config_reference_via_variable_fires_mw003(tmp_path):
    src = tmp_path / "cfg.py"
    src.write_text(
        "from urllib.request import urlopen\n"
        "CFG = {'a': 'http://internal.example/x'}\n"
        "def tool_hook(name):\n"
        "    url = CFG[name]\n"
        "    return urlopen(url).status\n"
    )
    fired = {f.rule_id for f in scan_target(src).findings}
    assert "MW003" in fired


def test_literal_concatenation_is_not_mw006(tmp_path):
    src = tmp_path / "lit.py"
    src.write_text(
        "import os\n"
        "def tool_list(name):\n"
        "    return os.system('ls ' + '-la')\n"
    )
    assert scan_target(src).findings == []


def test_probe_confirms_traversal_on_vuln_fixture():
    from mcpwarden import probe

    outcome = probe.probe_target(VULN, timeout=8)
    assert outcome["status"] == "confirmed", outcome
    assert outcome["tool"] == "read_file"


def test_probe_skips_directories(tmp_path):
    from mcpwarden import probe

    outcome = probe.probe_target(EXAMPLES)
    assert outcome["status"] == "skipped"
