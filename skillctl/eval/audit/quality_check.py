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


# --- Name-quality constants -----------------------------------------------

_GENERIC_NAME_WORDS = {
    "helper", "helpers", "util", "utils", "tools", "tool", "lib",
    "common", "misc", "stuff", "doc", "docs", "data", "files",
}


# --- Regex constants ------------------------------------------------------

_USE_WHEN_RE = re.compile(r"^\s*Use when\b", re.IGNORECASE)
_WORKFLOW_VERB_RE = re.compile(
    r"\b(?:then|next|first|after|before|finally|step\s*\d|"
    r"runs?|executes?|formats?|writes?|generates?|outputs?)\b",
    re.IGNORECASE,
)
_MIN_DESCRIPTION_CHARS = 60
_WORKFLOW_VERB_THRESHOLD = 3


def _check_description_style(frontmatter: dict, skill_md: Path,
                              findings: list[Finding]) -> None:
    desc = frontmatter.get("description")
    if not isinstance(desc, str) or not desc.strip():
        return  # STR-009 already flags this

    if not _USE_WHEN_RE.match(desc):
        findings.append(_qlt(
            "QLT-001", Severity.INFO,
            "Description does not start with 'Use when ...'",
            "Community convention is to begin descriptions with 'Use when ...' "
            "so the trigger condition is the first thing a model sees.",
            file_path=str(skill_md),
            fix="Rewrite the description to start with 'Use when <triggering condition>'.",
        ))

    desc_len = len(desc.strip())
    if desc_len < _MIN_DESCRIPTION_CHARS:
        findings.append(_qlt(
            "QLT-002", Severity.WARNING,
            f"Description is shorter than {_MIN_DESCRIPTION_CHARS} chars",
            f"The description is {desc_len} chars; short descriptions don't "
            "discriminate well during skill discovery and lose to longer competitors.",
            file_path=str(skill_md),
            fix="Add specific trigger phrases and the kind of input/output the skill handles.",
        ))

    workflow_hits = len(_WORKFLOW_VERB_RE.findall(desc))
    if workflow_hits >= _WORKFLOW_VERB_THRESHOLD:
        findings.append(_qlt(
            "QLT-003", Severity.WARNING,
            "Description appears to summarise the workflow",
            f"Found {workflow_hits} step-language matches in the description. "
            "Models can shortcut past the body when descriptions describe HOW "
            "instead of WHEN to invoke the skill.",
            file_path=str(skill_md),
            fix="Move workflow steps into the SKILL.md body. The description should "
            "answer 'when does this fire?', not 'what does it do?'.",
        ))


def _check_name_quality(frontmatter: dict, skill_path: Path, skill_md: Path,
                       findings: list[Finding]) -> None:
    name = frontmatter.get("name")
    if isinstance(name, str) and name:
        parts = re.split(r"-+", name.lower())
        if any(p in _GENERIC_NAME_WORDS for p in parts):
            findings.append(_qlt(
                "QLT-004", Severity.INFO,
                f"Skill name '{name}' contains a generic word",
                "Generic words like 'helper', 'utils', 'tools', 'data' don't "
                "describe what the skill actually does and hurt discoverability.",
                file_path=str(skill_md),
                fix="Rename to a verb-first or domain-specific name "
                    "(e.g., 'csv-deduplicator' instead of 'data-helpers').",
            ))

    if "_" in skill_path.name:
        findings.append(_qlt(
            "QLT-005", Severity.INFO,
            f"Directory name '{skill_path.name}' contains an underscore",
            "The Agent Skills spec requires skill names to use hyphens, not underscores. "
            "If the frontmatter `name` is hyphenated, the directory should match.",
            file_path=str(skill_path),
            fix=f"Rename the directory using hyphens: {skill_path.name.replace('_', '-')!r}.",
        ))


def _check_body_present(body: str, skill_md: Path, findings: list[Finding]) -> None:
    if not body.strip():
        findings.append(_qlt(
            "QLT-018", Severity.WARNING,
            "SKILL.md has no body content (frontmatter only)",
            "A skill consisting only of frontmatter has no instructions for the model "
            "to follow once invoked.",
            file_path=str(skill_md),
            fix="Write the skill body — what to do, examples, and any references.",
        ))


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

    _check_description_style(frontmatter, skill_md, findings)
    _check_name_quality(frontmatter, skill_path, skill_md, findings)
    _check_body_present(body, skill_md, findings)

    return findings
