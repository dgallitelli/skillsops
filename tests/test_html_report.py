"""Tests for the HTML report generator."""

from skillctl.eval.html_report import (
    generate_html_report,
    _esc,
    _grade_color,
    _pct,
    _cost_fmt,
    _bar_html,
)


class TestHelpers:
    def test_esc(self):
        assert _esc("<script>") == "&lt;script&gt;"
        assert _esc("normal") == "normal"

    def test_grade_color(self):
        assert _grade_color("A") == "#22c55e"
        assert _grade_color("F") == "#ef4444"
        assert _grade_color("Z") == "#94a3b8"

    def test_pct(self):
        assert _pct(0.95) == "95.0%"
        assert _pct(0.0) == "0.0%"

    def test_cost_fmt(self):
        assert _cost_fmt(0.001) == "$0.0010"
        assert _cost_fmt(1.5) == "$1.50"
        assert _cost_fmt(0.009) == "$0.0090"
        assert _cost_fmt(0.01) == "$0.01"

    def test_bar_html(self):
        bar = _bar_html(0.95)
        assert "22c55e" in bar  # green
        bar = _bar_html(0.3)
        assert "ef4444" in bar  # red
        bar = _bar_html(0.75)
        assert "3b82f6" in bar  # blue


class TestGenerateHtmlReport:
    def _minimal_report(self, **overrides):
        base = {
            "skill_name": "test/skill",
            "skill_path": "/tmp/skill",
            "timestamp": "2026-01-01T00:00:00Z",
            "overall_score": 0.85,
            "overall_grade": "B",
            "passed": True,
            "sections": {},
        }
        base.update(overrides)
        return base

    def test_minimal_report(self):
        html = generate_html_report(self._minimal_report())
        assert "<!DOCTYPE html>" in html
        assert "test/skill" in html
        assert "85.0%" in html

    def test_failed_report(self):
        html = generate_html_report(self._minimal_report(passed=False, overall_grade="F", overall_score=0.3))
        assert "FAILED" in html
        assert "ef4444" in html  # red for F grade

    def test_with_audit_section(self):
        html = generate_html_report(
            self._minimal_report(
                sections={
                    "audit": {
                        "score": 90,
                        "grade": "A",
                        "critical": 0,
                        "warning": 1,
                        "info": 2,
                        "findings": [
                            {"severity": "WARNING", "code": "STR-001", "title": "Missing file", "file_path": "x.md"}
                        ],
                    }
                }
            )
        )
        assert "Security Audit" in html
        assert "STR-001" in html
        assert "90/100" in html

    def test_with_audit_error(self):
        html = generate_html_report(self._minimal_report(sections={"audit": {"error": "something broke"}}))
        assert "something broke" in html

    def test_with_audit_skipped(self):
        html = generate_html_report(self._minimal_report(sections={"audit": {"skipped": True}}))
        assert "Skipped" in html

    def test_with_functional_section(self):
        html = generate_html_report(
            self._minimal_report(
                sections={
                    "functional": {
                        "overall": 0.82,
                        "grade": "B",
                        "passed": True,
                        "scores": {"outcome": 0.9, "process": 0.8, "style": 0.7, "efficiency": 0.6, "overall": 0.82},
                    }
                }
            )
        )
        assert "Functional Evaluation" in html
        assert "Outcome" in html

    def test_with_functional_cost_efficiency(self):
        html = generate_html_report(
            self._minimal_report(
                sections={
                    "functional": {
                        "overall": 0.8,
                        "grade": "B",
                        "passed": True,
                        "cost_efficiency": {
                            "emoji": "✅",
                            "classification": "Good",
                            "description": "Worth it",
                            "quality_delta": 0.2,
                            "cost_delta_pct": 10.0,
                        },
                    }
                }
            )
        )
        assert "Good" in html
        assert "Worth it" in html

    def test_with_functional_estimated_cost(self):
        html = generate_html_report(
            self._minimal_report(
                sections={
                    "functional": {
                        "overall": 0.8,
                        "grade": "B",
                        "passed": True,
                        "estimated_cost": {
                            "model": "sonnet",
                            "total_cost": 0.05,
                            "with_skill_per_run": {"total_cost": 0.03},
                            "without_skill_per_run": {"total_cost": 0.02},
                        },
                    }
                }
            )
        )
        assert "Estimated Cost" in html
        assert "sonnet" in html

    def test_with_functional_skipped(self):
        html = generate_html_report(
            self._minimal_report(sections={"functional": {"skipped": True, "reason": "no evals"}})
        )
        assert "Skipped" in html
        assert "no evals" in html

    def test_with_trigger_section(self):
        html = generate_html_report(
            self._minimal_report(
                sections={
                    "trigger": {
                        "pass_rate": 0.8,
                        "grade": "B",
                        "passed": True,
                        "total_queries": 10,
                        "query_results": [
                            {"passed": True, "query": "test query", "should_trigger": True, "trigger_rate": 1.0},
                            {"passed": False, "query": "bad query", "should_trigger": False, "trigger_rate": 0.5},
                        ],
                    }
                }
            )
        )
        assert "Trigger Reliability" in html
        assert "test query" in html
        assert "80.0%" in html

    def test_with_trigger_skipped(self):
        html = generate_html_report(
            self._minimal_report(sections={"trigger": {"skipped": True, "reason": "no queries"}})
        )
        assert "no queries" in html

    def test_empty_timestamp(self):
        html = generate_html_report(self._minimal_report(timestamp=""))
        assert "<!DOCTYPE html>" in html

    def test_xss_prevention(self):
        html = generate_html_report(self._minimal_report(skill_name="<script>alert(1)</script>"))
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html
