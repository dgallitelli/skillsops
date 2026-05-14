"""Citation rendering in audit reports."""
import io

from skillctl.eval.report import format_text_report, format_github_report
from skillctl.eval.schemas import AuditReport, Finding, Severity, Category


def _report_with(citation: str | None) -> AuditReport:
    return AuditReport(
        skill_name="test",
        skill_path="/tmp/test",
        score=85,
        grade="B",
        findings=[Finding(
            code="QLT-001",
            severity=Severity.WARNING,
            category=Category.QUALITY,
            title="Demo finding",
            detail="Demo detail",
            citation=citation,
        )],
    )


def test_text_report_renders_citation_when_present():
    buf = io.StringIO()
    format_text_report(_report_with("Agent Skills spec §name"), file=buf)
    assert "Agent Skills spec §name" in buf.getvalue()


def test_text_report_omits_citation_line_when_absent():
    buf = io.StringIO()
    format_text_report(_report_with(None), file=buf)
    assert "cite" not in buf.getvalue().lower() or "Agent Skills" not in buf.getvalue()


def test_github_report_includes_citation_in_body():
    buf = io.StringIO()
    format_github_report(_report_with("Agent Skills spec §name"), file=buf)
    assert "Agent Skills spec" in buf.getvalue()
