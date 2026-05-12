"""Report generation for skill evaluation."""

from __future__ import annotations

import json
import sys
from typing import TextIO

from skillctl.eval.explanations import get_explanation
from skillctl.eval.schemas import AuditReport, Finding, Severity


def format_text_report(
    report: AuditReport, verbose: bool = False, explain: bool = False, file: TextIO | None = None
) -> None:
    """Print a human-readable text report."""
    if file is None:
        file = sys.stdout

    w = 58  # Report width

    print(f"\n{'═' * w}", file=file)
    print("  Agent Skill Security Audit Report", file=file)
    print(f"{'═' * w}", file=file)
    print(f"  Skill:  {report.skill_name}", file=file)
    print(f"  Path:   {report.skill_path}", file=file)
    print(f"  Score:  {report.score}/100 (Grade: {report.grade})", file=file)
    print(f"{'─' * w}", file=file)

    # Summary counts
    c = report.critical_count
    w_count = report.warning_count
    i = report.info_count

    parts = []
    if c > 0:
        parts.append(f"🔴 CRITICAL: {c}")
    else:
        parts.append(f"✅ CRITICAL: {c}")
    parts.append(f"⚠️  WARNING: {w_count}")
    parts.append(f"ℹ️  INFO: {i}")

    print(f"  {' │ '.join(parts)}", file=file)
    print(f"{'─' * w}", file=file)

    if report.passed:
        print("  Result: ✅ PASSED (no critical findings)", file=file)
    else:
        print(f"  Result: ❌ FAILED ({c} critical finding{'s' if c != 1 else ''})", file=file)
    print(f"{'═' * w}\n", file=file)

    # Group findings by severity
    grouped: dict[str, list[Finding]] = {}
    for f in report.findings:
        grouped.setdefault(f.severity.value, []).append(f)

    # Print findings in severity order
    for severity in [Severity.CRITICAL, Severity.WARNING, Severity.INFO]:
        items = grouped.get(severity.value, [])
        if not items:
            continue

        if severity == Severity.INFO and not verbose:
            codes = ", ".join(f.code for f in items)
            noun = "finding" if len(items) == 1 else "findings"
            print(f"  ℹ️  {len(items)} INFO {noun}: {codes} (use --verbose for details)", file=file)
            continue

        for finding in items:
            icon = {"CRITICAL": "🔴", "WARNING": "⚠️ ", "INFO": "ℹ️ "}.get(severity.value, "  ")
            print(f"  {icon} [{finding.code}] {finding.title}", file=file)

            if finding.file_path:
                loc = finding.file_path
                if finding.line_number:
                    loc += f":{finding.line_number}"
                print(f"     File: {loc}", file=file)

            print(f"     {finding.detail[:200]}", file=file)

            if finding.fix:
                print(f"     Fix: {finding.fix}", file=file)

            if explain:
                explanation = get_explanation(finding.code)
                if explanation:
                    print(f"     Why it matters: {explanation}", file=file)

            print(file=file)

    # Metadata
    if verbose and report.metadata:
        print(f"{'─' * w}", file=file)
        print("  Metadata:", file=file)
        for k, v in report.metadata.items():
            print(f"    {k}: {v}", file=file)
        print(file=file)


def format_json_report(report: AuditReport, file: TextIO | None = None) -> None:
    """Print a JSON report."""
    if file is None:
        file = sys.stdout
    print(json.dumps(report.to_dict(), indent=2), file=file)


# ---------------------------------------------------------------------------
# GitHub Actions workflow-command format
# ---------------------------------------------------------------------------


# Severity → workflow command level.  ``::error::`` adds the finding to
# the workflow's failure summary in the PR UI; ``::warning::`` and
# ``::notice::`` show inline but don't affect the failure summary.  None
# of these levels affect the script's exit code on their own — that's
# what ``--fail-on-warning`` etc. are for.
_GITHUB_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.WARNING: "warning",
    Severity.INFO: "notice",
}


def _gh_escape_param(value: str) -> str:
    """Escape a workflow-command parameter value.

    Per the actions/toolkit ``escapeProperty`` rules:
    ``%`` → ``%25``, ``\\r`` → ``%0D``, ``\\n`` → ``%0A``,
    ``:`` → ``%3A``, ``,`` → ``%2C``.
    """
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A").replace(":", "%3A").replace(",", "%2C")


def _gh_escape_message(value: str) -> str:
    """Escape a workflow-command message body.

    Per ``escapeData``: only ``%``, ``\\r``, ``\\n`` need escaping;
    commas and colons are fine inside the body.
    """
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _gh_workflow_command(level: str, finding: Finding) -> str:
    """Render one workflow command line for *finding*.

    ``line=`` is emitted only when ``file_path`` is also set — GitHub
    silently drops a ``line=`` parameter without a ``file=``, so omitting
    it makes the wire format match the actual rendered behaviour.
    """
    params: list[str] = []
    if finding.file_path:
        params.append(f"file={_gh_escape_param(finding.file_path)}")
        if finding.line_number:
            params.append(f"line={finding.line_number}")
    title = _gh_escape_param(f"{finding.code} {finding.title}")
    params.append(f"title={title}")
    body_parts = [finding.detail]
    if finding.fix:
        body_parts.append(f"Fix: {finding.fix}")
    body = _gh_escape_message(" — ".join(body_parts))
    param_str = ",".join(params)
    return f"::{level} {param_str}::{body}"


def format_github_report(
    report: AuditReport,
    *,
    verbose: bool = False,
    file: TextIO | None = None,
) -> None:
    """Emit GitHub Actions workflow commands for the report's findings.

    One ``::error::`` / ``::warning::`` / ``::notice::`` line per finding
    on *file* (defaults to stdout).  When run inside a GitHub Actions
    workflow these surface as PR annotations bound to the offending
    file / line.

    Findings are wrapped in a ``::group::<skill>`` collapse so multi-skill
    audit runs stay readable in the workflow log.  A score-summary line
    is printed inside the group so the collapsed log still shows a quick
    pass/fail signal even without ``--quiet``.

    INFO findings are skipped unless *verbose* is True — mirrors the
    text-format behaviour and avoids exhausting GitHub's per-level
    annotation cap (10) with low-severity noise.  When INFO findings are
    suppressed, a single aggregated ``::notice::`` documents what the
    user isn't seeing (one notice line, regardless of how many INFO
    findings were collapsed).
    """
    if file is None:
        file = sys.stdout

    print(f"::group::Audit findings: {_gh_escape_message(report.skill_name)}", file=file)

    # Score summary inside the group — visible even when the group is
    # collapsed in the workflow log because GitHub keeps the title line.
    status = "PASSED" if report.passed else "FAILED"
    summary = (
        f"{status} — {report.score}/100 (Grade: {report.grade}) — "
        f"{report.critical_count} critical, {report.warning_count} warning, "
        f"{report.info_count} info"
    )
    print(summary, file=file)

    suppressed_info: list[Finding] = []
    for finding in report.findings:
        if finding.severity == Severity.INFO and not verbose:
            suppressed_info.append(finding)
            continue
        level = _GITHUB_LEVEL.get(finding.severity, "notice")
        print(_gh_workflow_command(level, finding), file=file)

    if suppressed_info:
        codes = sorted({f.code for f in suppressed_info})
        n = len(suppressed_info)
        noun = "finding" if n == 1 else "findings"
        msg = _gh_escape_message(f"{n} INFO {noun} suppressed ({', '.join(codes)}). Re-run with --verbose to see them.")
        # Single notice line so the cap (10 per level) isn't burned.
        print(f"::notice::{msg}", file=file)

    print("::endgroup::", file=file)
