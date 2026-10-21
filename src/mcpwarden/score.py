"""Scoring: severity weights, 100 point scale with floor 0, letter grades."""

from .rules import SEVERITY_WEIGHTS

GRADES = [(90, "A"), (75, "B"), (60, "C"), (40, "D"), (0, "F")]


def grade_for(score):
    for cutoff, grade in GRADES:
        if score >= cutoff:
            return grade
    return "F"


def score_result(result):
    """Attach score, grade, and per rule/severity tallies. Returns a dict."""
    total = 0
    by_severity = {}
    by_rule = {}
    for finding in result.findings:
        weight = SEVERITY_WEIGHTS.get(finding.severity, 0)
        total += weight
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
        by_rule[finding.rule_id] = by_rule.get(finding.rule_id, 0) + 1
    score = max(0, 100 - total)
    return {
        "score": score,
        "grade": grade_for(score),
        "deductions": total,
        "by_severity": by_severity,
        "by_rule": by_rule,
        "weights": SEVERITY_WEIGHTS,
    }
