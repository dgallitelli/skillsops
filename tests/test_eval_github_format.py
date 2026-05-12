"""Regression tests for ``skillctl eval audit --format=github``.

The format emits one GitHub Actions workflow command per finding so
findings render as inline PR annotations.  Tests cover:

- escape rules (parameter values vs message body)
- severity → level mapping
- file/line presence and absence
- INFO suppression unless --verbose
- ``::group::``/``::endgroup::`` wrapping
- multi-finding output ordering

The CLI-level integration (``skillctl eval audit ... --format=github``)
is exercised via subprocess in ``tests/test_cli_smoke.py``-style — see
``test_cli_format_github_smoke`` here.
"""

from __future__ import annotations

import io
import shutil
import subprocess
import sys
from pathlib import Path

from skillctl.eval.report import (
    _gh_escape_message,
    _gh_escape_param,
    _gh_workflow_command,
    format_github_report,
)
from skillctl.eval.schemas import AuditReport, Category, Finding, Severity


def _find_skillctl() -> str:
    """Find the skillctl binary next to the running Python interpreter,
    falling back to PATH lookup.  Mirrors ``tests/test_cli_smoke.py``."""
    bin_dir = Path(sys.executable).parent
    candidate = bin_dir / "skillctl"
    if candidate.exists():
        return str(candidate)
    found = shutil.which("skillctl")
    if found:
        return found
    raise FileNotFoundError("skillctl not on PATH — run pip install -e .")


SKILLCTL = _find_skillctl()


# ---------------------------------------------------------------------------
# Escape helpers
# ---------------------------------------------------------------------------


class TestEscapeParam:
    def test_percent_first(self):
        # Must escape ``%`` before any other replacement so the ``%XX``
        # sequences we introduce aren't double-encoded.
        assert _gh_escape_param("100% safe") == "100%25 safe"

    def test_comma(self):
        assert _gh_escape_param("a, b, c") == "a%2C b%2C c"

    def test_colon(self):
        assert _gh_escape_param("path:line") == "path%3Aline"

    def test_newlines(self):
        assert _gh_escape_param("line1\nline2") == "line1%0Aline2"
        assert _gh_escape_param("line1\rline2") == "line1%0Dline2"

    def test_combined(self):
        assert _gh_escape_param("a:b,c%d\ne") == "a%3Ab%2Cc%25d%0Ae"

    def test_empty(self):
        assert _gh_escape_param("") == ""


class TestEscapeMessage:
    def test_preserves_commas_and_colons(self):
        # In the body, commas and colons are fine — only newlines and
        # the percent escape need handling.
        assert _gh_escape_message("a:b, c") == "a:b, c"

    def test_percent(self):
        assert _gh_escape_message("100%") == "100%25"

    def test_newlines(self):
        assert _gh_escape_message("line1\nline2") == "line1%0Aline2"
        assert _gh_escape_message("line1\rline2") == "line1%0Dline2"


# ---------------------------------------------------------------------------
# Single-finding rendering
# ---------------------------------------------------------------------------


def _finding(
    code: str = "SEC-001",
    severity: Severity = Severity.CRITICAL,
    title: str = "Secret detected",
    detail: str = "An AWS access key was found",
    file_path: str | None = "skills/foo/SKILL.md",
    line_number: int | None = 42,
    fix: str | None = "Remove the secret",
) -> Finding:
    return Finding(
        code=code,
        severity=severity,
        category=Category.SECURITY,
        title=title,
        detail=detail,
        file_path=file_path,
        line_number=line_number,
        fix=fix,
    )


class TestWorkflowCommand:
    def test_critical_finding_emits_error(self):
        line = _gh_workflow_command("error", _finding())
        assert line.startswith("::error ")
        assert "file=skills/foo/SKILL.md" in line
        assert "line=42" in line
        assert "title=SEC-001 Secret detected" in line
        # body
        assert line.endswith("An AWS access key was found — Fix: Remove the secret")

    def test_finding_without_line(self):
        line = _gh_workflow_command("warning", _finding(severity=Severity.WARNING, line_number=None))
        assert "file=skills/foo/SKILL.md" in line
        assert "line=" not in line

    def test_finding_without_file_drops_line_too(self):
        # GitHub silently drops `line=` without a corresponding `file=`,
        # so the renderer omits both for a finding that has no file path.
        # This matches what the user actually sees in the PR UI.
        line = _gh_workflow_command("warning", _finding(severity=Severity.WARNING, file_path=None))
        assert "file=" not in line
        assert "line=" not in line
        assert "title=SEC-001 Secret detected" in line

    def test_finding_without_fix(self):
        line = _gh_workflow_command("notice", _finding(severity=Severity.INFO, fix=None))
        assert line.endswith("An AWS access key was found")
        assert "Fix:" not in line

    def test_title_with_colon_is_escaped(self):
        f = _finding(title="Secret detected: AWS")
        line = _gh_workflow_command("error", f)
        assert "title=SEC-001 Secret detected%3A AWS" in line

    def test_title_with_comma_is_escaped(self):
        f = _finding(title="Tools, declared: many")
        line = _gh_workflow_command("error", f)
        assert "title=SEC-001 Tools%2C declared%3A many" in line

    def test_body_preserves_internal_punctuation(self):
        f = _finding(detail="Found at line 5: see file.md", fix="Use env: $SECRET")
        line = _gh_workflow_command("error", f)
        # Body part lives after the closing ``::``.
        body = line.split("::", 2)[-1]
        assert "Found at line 5: see file.md" in body
        assert "Use env: $SECRET" in body

    def test_body_escapes_newlines(self):
        f = _finding(detail="line1\nline2")
        line = _gh_workflow_command("error", f)
        body = line.split("::", 2)[-1]
        assert "%0A" in body
        assert "\n" not in body


# ---------------------------------------------------------------------------
# Full-report rendering
# ---------------------------------------------------------------------------


def _report(findings: list[Finding], skill_name: str = "test-skill") -> AuditReport:
    return AuditReport(
        skill_name=skill_name,
        skill_path=f"/tmp/{skill_name}",
        score=80,
        grade="B",
        findings=findings,
    )


class TestFormatGithubReport:
    def test_group_wrapping(self):
        buf = io.StringIO()
        format_github_report(_report([_finding()]), file=buf)
        out = buf.getvalue()
        assert out.startswith("::group::Audit findings: test-skill")
        assert "::endgroup::" in out
        # ::endgroup:: must come AFTER all findings.
        assert out.index("::error") < out.index("::endgroup::")

    def test_skill_name_uses_message_escapes_only(self):
        # The group title is part of a workflow-command message body, so
        # only newlines and percent get escaped.  Colons stay literal —
        # that's correct per actions/toolkit's escapeData rules.
        buf = io.StringIO()
        format_github_report(_report([], skill_name="my:org/skill\nname"), file=buf)
        out = buf.getvalue()
        first_line = out.splitlines()[0]
        assert first_line == "::group::Audit findings: my:org/skill%0Aname"

    def test_score_summary_inside_group(self):
        # Visible inside the group so the collapsed CI log still shows a
        # quick pass/fail signal without --quiet.
        findings = [
            _finding(severity=Severity.CRITICAL, code="SEC-001"),
            _finding(severity=Severity.WARNING, code="SEC-002"),
        ]
        report = AuditReport(
            skill_name="bad-skill",
            skill_path="/tmp/bad-skill",
            score=65,
            grade="D",
            findings=findings,
        )
        buf = io.StringIO()
        format_github_report(report, file=buf)
        lines = buf.getvalue().splitlines()
        # Second line (right after the group header) is the score summary.
        assert lines[0].startswith("::group::")
        assert lines[1].startswith("FAILED")
        assert "65/100" in lines[1]
        assert "(Grade: D)" in lines[1]
        assert "1 critical" in lines[1]
        assert "1 warning" in lines[1]

    def test_score_summary_clean_run(self):
        buf = io.StringIO()
        format_github_report(_report([]), file=buf)
        lines = buf.getvalue().splitlines()
        assert lines[1].startswith("PASSED")
        assert "0 critical" in lines[1]

    def test_severity_mapping(self):
        findings = [
            _finding(severity=Severity.CRITICAL, code="SEC-001"),
            _finding(severity=Severity.WARNING, code="SEC-002"),
            _finding(severity=Severity.INFO, code="STR-008"),
        ]
        buf = io.StringIO()
        # verbose=True so INFO is rendered.
        format_github_report(_report(findings), verbose=True, file=buf)
        lines = [line for line in buf.getvalue().splitlines() if line.startswith("::")]
        # group + 3 findings + endgroup
        assert any(line.startswith("::error ") and "SEC-001" in line for line in lines)
        assert any(line.startswith("::warning ") and "SEC-002" in line for line in lines)
        assert any(line.startswith("::notice ") and "STR-008" in line for line in lines)

    def test_info_suppressed_by_default_with_aggregate_notice(self):
        findings = [
            _finding(severity=Severity.WARNING, code="SEC-002"),
            _finding(severity=Severity.INFO, code="STR-008"),
            _finding(severity=Severity.INFO, code="STR-008"),
            _finding(severity=Severity.INFO, code="STR-019"),
        ]
        buf = io.StringIO()
        format_github_report(_report(findings), file=buf)  # default verbose=False
        out = buf.getvalue()
        # The SEC-002 warning is rendered.
        assert "::warning" in out
        assert "SEC-002" in out
        # No per-INFO ::notice:: lines (those would burn the cap).
        per_finding_notices = [line for line in out.splitlines() if line.startswith("::notice ") and "title=" in line]
        assert per_finding_notices == []
        # But there is exactly ONE aggregate ::notice:: summarising the
        # suppressed INFO findings, with their codes deduplicated.
        aggregate = [line for line in out.splitlines() if line.startswith("::notice::") and "INFO" in line]
        assert len(aggregate) == 1
        # The aggregate mentions all unique codes in alphabetical order.
        assert "STR-008" in aggregate[0]
        assert "STR-019" in aggregate[0]
        assert "3 INFO findings suppressed" in aggregate[0]
        assert "--verbose" in aggregate[0]

    def test_no_aggregate_notice_when_no_info(self):
        findings = [_finding(severity=Severity.WARNING, code="SEC-002")]
        buf = io.StringIO()
        format_github_report(_report(findings), file=buf)
        # No aggregate notice when there were no INFO findings to suppress.
        assert "INFO findings suppressed" not in buf.getvalue()

    def test_no_aggregate_notice_when_verbose(self):
        findings = [_finding(severity=Severity.INFO, code="STR-008")]
        buf = io.StringIO()
        format_github_report(_report(findings), verbose=True, file=buf)
        # The INFO is rendered as its own ::notice::; no aggregate.
        assert "INFO findings suppressed" not in buf.getvalue()

    def test_info_emitted_with_verbose(self):
        findings = [_finding(severity=Severity.INFO, code="STR-008")]
        buf = io.StringIO()
        format_github_report(_report(findings), verbose=True, file=buf)
        assert "STR-008" in buf.getvalue()

    def test_empty_report(self):
        buf = io.StringIO()
        format_github_report(_report([]), file=buf)
        out = buf.getvalue().splitlines()
        # Just group + endgroup, no finding lines.
        assert out[0].startswith("::group::")
        assert out[-1] == "::endgroup::"
        finding_lines = [line for line in out if line.startswith(("::error", "::warning", "::notice"))]
        assert finding_lines == []

    def test_multiple_findings_one_line_each(self):
        findings = [_finding(severity=Severity.CRITICAL, code=f"SEC-{i:03d}", title=f"Issue {i}") for i in range(1, 6)]
        buf = io.StringIO()
        format_github_report(_report(findings), file=buf)
        finding_lines = [line for line in buf.getvalue().splitlines() if line.startswith("::error")]
        assert len(finding_lines) == 5
        # Order preserved.
        for i, line in enumerate(finding_lines, start=1):
            assert f"SEC-{i:03d}" in line


# ---------------------------------------------------------------------------
# CLI-level smoke test
# ---------------------------------------------------------------------------


class TestCliFormatGithubSmoke:
    """Run skillctl eval audit --format=github via subprocess to confirm
    the wiring (parser → dispatch → renderer) works end-to-end."""

    def test_clean_skill_emits_just_group(self, tmp_path):
        skill = tmp_path / "clean-skill"
        skill.mkdir()
        (skill / "SKILL.md").write_text(
            "---\nname: clean-skill\ndescription: A clean skill that does test things consistently\n---\n\nBody.\n"
        )
        r = subprocess.run(
            [str(SKILLCTL), "eval", "audit", str(skill), "--format=github"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0, r.stderr
        out_lines = [line for line in r.stdout.splitlines() if line.startswith("::")]
        assert out_lines[0].startswith("::group::")
        assert out_lines[-1] == "::endgroup::"
        # No findings on a clean skill, so no error/warning/notice lines.
        assert not any(line.startswith(("::error", "::warning", "::notice")) for line in out_lines)

    def test_skill_with_critical_emits_error(self, tmp_path):
        skill = tmp_path / "bad-skill"
        skill.mkdir()
        (skill / "SKILL.md").write_text(
            "---\nname: bad-skill\ndescription: A deliberately bad skill that will trip the secret scanner\n---\n\nuse this token: AKIAIOSFODNN7EXAMPLE\n"
        )
        r = subprocess.run(
            [str(SKILLCTL), "eval", "audit", str(skill), "--format=github"],
            capture_output=True,
            text=True,
        )
        # Critical finding → exit 2.
        assert r.returncode == 2, r.stdout + r.stderr
        assert "::error" in r.stdout
        assert "SEC-001" in r.stdout

    def test_quiet_routes_quiet_summary_to_stderr(self, tmp_path):
        skill = tmp_path / "clean"
        skill.mkdir()
        (skill / "SKILL.md").write_text(
            "---\nname: clean\ndescription: A clean skill that does test things consistently\n---\n\nBody.\n"
        )
        r = subprocess.run(
            [str(SKILLCTL), "eval", "audit", str(skill), "--format=github", "--quiet"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        # Workflow commands on stdout.
        assert "::group::" in r.stdout
        # The quiet one-line summary (recognisable by the path in
        # parens) goes to stderr — that's the format-specific contract
        # of `--quiet --format=github`.
        assert "PASSED" in r.stderr
        assert f"({skill})" in r.stderr  # path-in-parens is the quiet shape
        assert f"({skill})" not in r.stdout
        # The in-group score summary IS on stdout (and unconditional, not
        # tied to --quiet) — that's the score-at-a-glance for the
        # collapsed CI log.  Distinguish it by absence of the path.
        score_lines = [line for line in r.stdout.splitlines() if line.startswith(("PASSED", "FAILED"))]
        assert len(score_lines) == 1
        assert "100/100" in score_lines[0]
        assert "(Grade: A)" in score_lines[0]
