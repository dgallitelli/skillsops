"""Authoring-quality checks for Agent Skills.

Implements the QLT-* family of rules — best-practice / discoverability /
maintainability checks ported from dgallitelli/skill-reviewer
(https://github.com/dgallitelli/skill-reviewer). Each rule's citation
links back to its upstream source (Agent Skills spec, Anthropic platform
best-practices, Claude Code docs, or community writeups).

These rules are advisory; none of them are CRITICAL — the spec-mandated
hard rules live in structure_check.py (STR-*).
"""

from __future__ import annotations

import re
from pathlib import Path

from skillctl.eval.audit.structure_check import _parse_frontmatter
from skillctl.eval.schemas import Category, Finding, Severity


# --- Citations (one per rule) ---------------------------------------------

_QLT_CITATIONS = {
    "QLT-001": "obra/superpowers writing-skills",
    "QLT-002": "platform.claude.com agent-skills/best-practices",
    "QLT-003": "obra/superpowers writing-skills (empirical finding)",
    "QLT-004": "obra/superpowers writing-skills; platform.claude.com agent-skills/best-practices",
    "QLT-005": "agentskills.io/specification §name",
    "QLT-006": "platform.claude.com agent-skills/best-practices",
    "QLT-007": "platform.claude.com agent-skills/best-practices",
    "QLT-008": "platform.claude.com agent-skills/best-practices",
    "QLT-009": "general correctness",
    "QLT-010": "platform.claude.com agent-skills/best-practices",
    "QLT-011": "platform.claude.com agent-skills/best-practices",
    "QLT-012": "platform.claude.com agent-skills/best-practices",
    "QLT-013": "platform.claude.com agent-skills/best-practices",
    "QLT-014": "code.claude.com/docs/en/skills §allowed-tools",
    "QLT-015": "obra/superpowers writing-skills",
    "QLT-016": "anthropics/skills template",
    "QLT-017": "platform.claude.com agent-skills/best-practices",
    "QLT-018": "agentskills.io/specification §body",
    "QLT-019": "platform.claude.com agent-skills/best-practices",
}


def _qlt(code: str, severity: Severity, title: str, detail: str, **kwargs) -> Finding:
    """Build a Finding pre-filled with the QLT category and citation."""
    return Finding(
        code=code,
        severity=severity,
        category=Category.QUALITY,
        title=title,
        detail=detail,
        citation=_QLT_CITATIONS[code],
        **kwargs,
    )


def _strip_code(text: str) -> str:
    """Remove fenced code blocks and inline-code spans so style checks
    don't trip on legitimate references to the very patterns they flag."""
    no_fenced = re.sub(r"```.*?```", "", text, flags=re.DOTALL)
    no_inline = re.sub(r"`[^`]*`", "", no_fenced)
    return no_inline


def check_quality(skill_path: str | Path) -> list[Finding]:
    """Run all QLT-* authoring-quality checks on a skill directory.

    Returns an empty list when SKILL.md is absent or unparseable —
    structure_check.py already reports those as STR-* CRITICAL.
    """
    skill_path = Path(skill_path)
    findings: list[Finding] = []

    skill_md = skill_path / "SKILL.md"
    if not skill_md.is_file():
        return findings

    try:
        content = skill_md.read_text(encoding="utf-8")
    except Exception:
        return findings

    frontmatter, error, body_start = _parse_frontmatter(content)
    if error or frontmatter is None:
        return findings

    body = "\n".join(content.split("\n")[body_start:])

    # Individual rule checks will be added in Tasks 5-8.
    return findings
