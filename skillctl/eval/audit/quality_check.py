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

_WINDOWS_PATH_RE = re.compile(r"(?:^|\s|[(])[A-Za-z0-9_./-]*\\[A-Za-z0-9_./\\-]+")
_TIME_SENSITIVE_RE = re.compile(
    r"\b(?:as of\s+\d{4}|before\s+(?:19|20)\d{2}|after\s+(?:19|20)\d{2}|"
    r"prior to\s+(?:19|20)\d{2}|in\s+(?:19|20)\d{2}\b|"
    r"deprecated\s+in\s+(?:19|20)\d{2})\b",
    re.IGNORECASE,
)
_OLD_PATTERNS_HEADING_RE = re.compile(
    r"\b(?:old patterns|history|deprecated|legacy)\b", re.IGNORECASE
)
_MCP_BARE_TOOL_RE = re.compile(r"`mcp__[a-z0-9_-]+`")
_TEMPLATE_MARKERS = (
    "insert instructions below",
    "todo: write the skill",
    "<your skill goes here>",
    "describe what this skill does",
    "your-skill-name",
    "skill name (replace this)",
)
_NEAR_SYNONYM_GROUPS = (
    ("field", "box", "control", "input"),
    ("script", "tool", "executable"),
    ("delete", "remove", "drop"),
)


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


def _check_paths_in_body(body: str, skill_md: Path, findings: list[Finding]) -> None:
    if _WINDOWS_PATH_RE.search(body):
        findings.append(_qlt(
            "QLT-007", Severity.WARNING,
            "SKILL.md references Windows-style backslash paths",
            "Backslash paths break on macOS and Linux Claude clients.",
            file_path=str(skill_md),
            fix="Use forward slashes for all paths.",
        ))


def _check_time_sensitive(body: str, skill_md: Path, findings: list[Finding]) -> None:
    sections = re.split(r"^#+\s+", body, flags=re.MULTILINE)
    for sec in sections[1:]:
        if not sec:
            continue
        first_line = sec.splitlines()[0] if sec.splitlines() else ""
        if _OLD_PATTERNS_HEADING_RE.search(first_line):
            continue
        if _TIME_SENSITIVE_RE.search(sec):
            findings.append(_qlt(
                "QLT-011", Severity.WARNING,
                f"Section '{first_line.strip()}' contains time-sensitive language",
                "Phrases like 'as of 2024' rot quickly. The body section will outlive its claim.",
                file_path=str(skill_md),
                fix="Move dated claims to a '## Old patterns' or '## History' section.",
            ))
            return  # one per skill is enough


def _check_mcp_qualification(body: str, skill_md: Path, findings: list[Finding]) -> None:
    matches = _MCP_BARE_TOOL_RE.findall(body)
    bare = [m for m in matches if m.count("__") < 2]
    if bare:
        findings.append(_qlt(
            "QLT-013", Severity.INFO,
            "MCP tool references are not fully qualified",
            f"Found unqualified references: {', '.join(bare[:3])}. "
            "Qualified MCP tool names are unambiguous and survive server renames.",
            file_path=str(skill_md),
            fix="Use the form `mcp__<server>__<tool>` for every MCP tool reference.",
        ))


def _check_template_residue(body: str, skill_md: Path, findings: list[Finding]) -> None:
    lower = _strip_code(body).lower()
    for marker in _TEMPLATE_MARKERS:
        if marker in lower:
            findings.append(_qlt(
                "QLT-016", Severity.WARNING,
                "SKILL.md body still contains template placeholder text",
                f"Template marker '{marker}' is still present — the skill was scaffolded but not filled in.",
                file_path=str(skill_md),
                fix="Replace template placeholders with the actual skill content.",
            ))
            return


def _check_concrete_examples(body: str, skill_md: Path, findings: list[Finding]) -> None:
    has_fence = "```" in body
    has_example_section = re.search(
        r"^#+\s*(?:example|examples)\b", body, re.IGNORECASE | re.MULTILINE
    ) is not None
    if not (has_fence or has_example_section):
        findings.append(_qlt(
            "QLT-017", Severity.INFO,
            "No concrete examples found in SKILL.md body",
            "No fenced code blocks or `## Example` section detected. Examples improve "
            "both discovery (model knows what triggers the skill) and correctness "
            "(model knows the expected shape of the answer).",
            file_path=str(skill_md),
            fix="Add at least one fenced code block showing real input/output, "
                "or a `## Example` section.",
        ))


def _check_consistent_terminology(body: str, skill_md: Path, findings: list[Finding]) -> None:
    lower = body.lower()
    for group in _NEAR_SYNONYM_GROUPS:
        present = [w for w in group if re.search(rf"\b{re.escape(w)}\b", lower)]
        if len(present) >= 3:
            findings.append(_qlt(
                "QLT-019", Severity.INFO,
                "Multiple near-synonyms used together",
                f"Found {', '.join(present)} in the same body. Inconsistent terminology "
                "makes the skill harder to follow.",
                file_path=str(skill_md),
                fix=f"Pick one term from {{{', '.join(present)}}} and use it throughout.",
            ))
            return


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
    _check_paths_in_body(body, skill_md, findings)
    _check_time_sensitive(body, skill_md, findings)
    _check_mcp_qualification(body, skill_md, findings)
    _check_template_residue(body, skill_md, findings)
    _check_concrete_examples(body, skill_md, findings)
    _check_consistent_terminology(body, skill_md, findings)

    return findings
