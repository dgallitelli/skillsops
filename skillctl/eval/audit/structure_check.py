"""Structure validation against agentskills.io specification.

Checks:
- SKILL.md exists and has valid YAML frontmatter
- name field: required, 1-64 chars, lowercase+hyphens, matches directory name
- name field: must not contain reserved words ('anthropic', 'claude')
- description field: required, 1-1024 chars, non-empty
- description field: must not contain XML tags
- description field: should use third person (not first/second person)
- Optional fields: license, compatibility (max 500 chars), metadata, allowed-tools
- Directory structure conventions
- Progressive disclosure (SKILL.md size, reference file sizes)
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional

import yaml

from skillctl.eval.schemas import Finding, Severity, Category


# Citations for STR-* findings. Format mirrors skill-reviewer's
# references/rules.md so users can cross-reference upstream.
_STR_CITATIONS = {
    "STR-001": "agentskills.io/specification §directory-structure",
    "STR-002": "agentskills.io/specification §directory-structure",
    "STR-003": "agentskills.io/specification §frontmatter",
    "STR-004": "agentskills.io/specification §frontmatter",
    "STR-005": "agentskills.io/specification §required-fields",
    "STR-006": "agentskills.io/specification §name; skills-ref MAX_SKILL_NAME_LENGTH=64",
    "STR-007": "agentskills.io/specification §name",
    "STR-008": "agentskills.io/specification §name",
    "STR-009": "agentskills.io/specification §required-fields",
    "STR-010": "agentskills.io/specification §description; skills-ref MAX_DESCRIPTION_LENGTH=1024",
    "STR-011": "platform.claude.com agent-skills/best-practices",
    "STR-012": "skills-ref MAX_COMPATIBILITY_LENGTH=500",
    "STR-013": "agentskills.io/specification §metadata",
    "STR-014": "platform.claude.com agent-skills/best-practices",
    "STR-015": "platform.claude.com agent-skills/overview",
    "STR-016": "platform.claude.com agent-skills/overview",
    "STR-017": "platform.claude.com agent-skills/best-practices",
    "STR-018": "agentskills.io/specification §name",
    "STR-019": "platform.claude.com agent-skills/best-practices",
    "STR-020": "platform.claude.com agent-skills/best-practices",
    "STR-021": "platform.claude.com agent-skills/best-practices",
}


# --- Name validation ---

_NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")
_CONSECUTIVE_HYPHENS = re.compile(r"--")
_MAX_NAME_LEN = 64
_MAX_DESC_LEN = 1024
_MAX_COMPAT_LEN = 500
_RECOMMENDED_MAX_LINES = 500
_RECOMMENDED_MAX_BODY_TOKENS_APPROX = 5000  # ~4 chars per token


def _parse_frontmatter(content: str) -> tuple[Optional[dict], Optional[str], int]:
    """Parse YAML frontmatter from SKILL.md content.

    Returns (frontmatter_dict, error_message, body_start_line).
    If parsing fails, returns (None, error_msg, 0).
    """
    lines = content.split("\n")

    # Find opening ---
    if not lines or lines[0].strip() != "---":
        return None, "SKILL.md does not start with YAML frontmatter (---)", 0

    # Find closing ---
    end_idx = None
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            end_idx = i
            break

    if end_idx is None:
        return None, "YAML frontmatter is not closed (missing second ---)", 0

    # Parse YAML — use PyYAML's safe_load (PyYAML is already a hard dep).
    yaml_text = "\n".join(lines[1:end_idx])
    try:
        fm = yaml.safe_load(yaml_text) or {}
    except yaml.YAMLError as e:
        return None, f"Failed to parse YAML frontmatter: {e}", 0

    if not isinstance(fm, dict):
        return None, "YAML frontmatter must be a mapping (key: value pairs)", 0

    # Coerce values to strings for keys the audit logic expects as strings.
    # PyYAML decodes numeric / boolean values to native types; downstream
    # checks expect strings.
    return fm, None, end_idx + 1


def check_structure(skill_path: str | Path) -> tuple[list[Finding], Optional[dict], int]:
    """Run all structure checks on a skill directory.

    Args:
        skill_path: Path to the skill directory

    Returns:
        Tuple of (findings, frontmatter_dict_or_None, body_start_line).
        On early failure (missing dir/file/frontmatter), frontmatter is None and body_start is 0.
    """
    skill_path = Path(skill_path)
    findings: list[Finding] = []

    # --- Check 1: Directory exists ---
    if not skill_path.is_dir():
        findings.append(
            Finding(
                code="STR-001",
                severity=Severity.CRITICAL,
                category=Category.STRUCTURE,
                title="Skill path is not a directory",
                detail=f"Expected a directory at '{skill_path}', but it doesn't exist or isn't a directory.",
                file_path=str(skill_path),
                citation=_STR_CITATIONS["STR-001"],
            )
        )
        return findings, None, 0  # Can't continue without the directory

    dir_name = skill_path.name

    # --- Check 2: SKILL.md exists ---
    skill_md = skill_path / "SKILL.md"
    if not skill_md.is_file():
        findings.append(
            Finding(
                code="STR-002",
                severity=Severity.CRITICAL,
                category=Category.STRUCTURE,
                title="Missing SKILL.md",
                detail="Every skill must have a SKILL.md file at its root. This is the only required file.",
                file_path=str(skill_md),
                fix="Create a SKILL.md with YAML frontmatter (name, description) and markdown instructions.",
                citation=_STR_CITATIONS["STR-002"],
            )
        )
        return findings, None, 0  # Can't continue without SKILL.md

    # --- Read and parse SKILL.md ---
    try:
        content = skill_md.read_text(encoding="utf-8")
    except Exception as e:
        findings.append(
            Finding(
                code="STR-003",
                severity=Severity.CRITICAL,
                category=Category.STRUCTURE,
                title="Cannot read SKILL.md",
                detail=f"Failed to read SKILL.md: {e}",
                file_path=str(skill_md),
                citation=_STR_CITATIONS["STR-003"],
            )
        )
        return findings, None, 0

    frontmatter, error, body_start = _parse_frontmatter(content)

    if error:
        findings.append(
            Finding(
                code="STR-004",
                severity=Severity.CRITICAL,
                category=Category.STRUCTURE,
                title="Invalid frontmatter",
                detail=error,
                file_path=str(skill_md),
                line_number=1,
                fix="SKILL.md must start with --- followed by YAML key-value pairs and a closing ---.",
                citation=_STR_CITATIONS["STR-004"],
            )
        )
        return findings, None, 0

    # --- Check 3: name field ---
    assert frontmatter is not None  # guaranteed: we returned above if None
    name = frontmatter.get("name")
    if not name:
        findings.append(
            Finding(
                code="STR-005",
                severity=Severity.CRITICAL,
                category=Category.STRUCTURE,
                title="Missing required 'name' field",
                detail="The 'name' field is required in SKILL.md frontmatter.",
                file_path=str(skill_md),
                line_number=1,
                fix="Add 'name: your-skill-name' to the frontmatter.",
                citation=_STR_CITATIONS["STR-005"],
            )
        )
    elif isinstance(name, str):
        # Validate name format
        if len(name) > _MAX_NAME_LEN:
            findings.append(
                Finding(
                    code="STR-006",
                    severity=Severity.WARNING,
                    category=Category.STRUCTURE,
                    title=f"Name too long ({len(name)} chars, max {_MAX_NAME_LEN})",
                    detail=f"The name '{name}' exceeds the {_MAX_NAME_LEN}-character limit.",
                    file_path=str(skill_md),
                    fix=f"Shorten the name to {_MAX_NAME_LEN} characters or fewer.",
                    citation=_STR_CITATIONS["STR-006"],
                )
            )

        if not _NAME_RE.match(name):
            issues = []
            if name != name.lower():
                issues.append("contains uppercase characters")
            if name.startswith("-") or name.endswith("-"):
                issues.append("starts or ends with a hyphen")
            if not re.match(r"^[a-z0-9-]+$", name):
                issues.append("contains characters other than lowercase letters, numbers, and hyphens")
            if _CONSECUTIVE_HYPHENS.search(name):
                issues.append("contains consecutive hyphens (--)")

            detail = (
                f"The name '{name}' is invalid: {'; '.join(issues)}."
                if issues
                else f"The name '{name}' doesn't match the required pattern."
            )
            findings.append(
                Finding(
                    code="STR-007",
                    severity=Severity.WARNING,
                    category=Category.STRUCTURE,
                    title="Invalid name format",
                    detail=detail,
                    file_path=str(skill_md),
                    fix="Name must be 1-64 lowercase alphanumeric characters and hyphens, not starting/ending with hyphen.",
                    citation=_STR_CITATIONS["STR-007"],
                )
            )

        # Check name matches directory name
        if name != dir_name:
            findings.append(
                Finding(
                    code="STR-008",
                    severity=Severity.INFO,
                    category=Category.STRUCTURE,
                    title="Name doesn't match directory",
                    detail=f"Frontmatter name '{name}' doesn't match directory name '{dir_name}'.",
                    file_path=str(skill_md),
                    fix=f"Either rename the directory to '{name}/' or change the name field to '{dir_name}'.",
                    citation=_STR_CITATIONS["STR-008"],
                )
            )

        # Check name does not contain reserved words (agentskills.io spec)
        _RESERVED_WORDS = ["anthropic", "claude"]
        for reserved in _RESERVED_WORDS:
            if reserved in name:
                findings.append(
                    Finding(
                        code="STR-018",
                        severity=Severity.WARNING,
                        category=Category.STRUCTURE,
                        title=f"Name contains reserved word '{reserved}'",
                        detail=f"The name '{name}' contains '{reserved}', which is reserved per the agentskills.io specification. "
                        f"Names must not contain 'anthropic' or 'claude'.",
                        file_path=str(skill_md),
                        fix=f"Remove '{reserved}' from the skill name. Use a descriptive name for what the skill does instead.",
                        citation=_STR_CITATIONS["STR-018"],
                    )
                )
                break  # One finding is enough
    else:
        # PyYAML decoded the value as a non-string (list, int, bool, ...).
        # Previously the custom parser silently coerced everything to a
        # string; safe_load is stricter, so flag the error explicitly.
        findings.append(
            Finding(
                code="STR-005",
                severity=Severity.CRITICAL,
                category=Category.STRUCTURE,
                title="'name' field must be a string",
                detail=f"The 'name' field must be a string, got {type(name).__name__}.",
                file_path=str(skill_md),
                line_number=1,
                fix='Quote the name value in YAML: name: "my-skill".',
                citation=_STR_CITATIONS["STR-005"],
            )
        )

    # --- Check 4: description field ---
    desc = frontmatter.get("description")
    if not desc:
        findings.append(
            Finding(
                code="STR-009",
                severity=Severity.CRITICAL,
                category=Category.STRUCTURE,
                title="Missing required 'description' field",
                detail="The 'description' field is required in SKILL.md frontmatter. It's the primary trigger signal.",
                file_path=str(skill_md),
                line_number=1,
                fix="Add 'description: What it does and when to use it' to the frontmatter.",
                citation=_STR_CITATIONS["STR-009"],
            )
        )
    elif isinstance(desc, str):
        if len(desc) > _MAX_DESC_LEN:
            findings.append(
                Finding(
                    code="STR-010",
                    severity=Severity.WARNING,
                    category=Category.STRUCTURE,
                    title=f"Description too long ({len(desc)} chars, max {_MAX_DESC_LEN})",
                    detail=f"The description exceeds the {_MAX_DESC_LEN}-character limit.",
                    file_path=str(skill_md),
                    fix=f"Shorten the description to {_MAX_DESC_LEN} characters. Move details to the body.",
                    citation=_STR_CITATIONS["STR-010"],
                )
            )

        if len(desc) < 20:
            findings.append(
                Finding(
                    code="STR-011",
                    severity=Severity.WARNING,
                    category=Category.STRUCTURE,
                    title="Description too short",
                    detail=f"The description '{desc}' is very short ({len(desc)} chars). It should describe what the skill does AND when to use it.",
                    file_path=str(skill_md),
                    fix="Include both what the skill does and specific trigger contexts/phrases.",
                    citation=_STR_CITATIONS["STR-011"],
                )
            )

        # Check description does not contain XML tags (agentskills.io spec)
        if re.search(r"<[a-zA-Z][^>]*>", desc):
            findings.append(
                Finding(
                    code="STR-019",
                    severity=Severity.WARNING,
                    category=Category.STRUCTURE,
                    title="Description contains XML tags",
                    detail="The description field must not contain XML tags per the agentskills.io specification. "
                    "XML tags in the description can interfere with system prompt injection.",
                    file_path=str(skill_md),
                    fix="Remove all XML/HTML tags from the description. Use plain text only.",
                    citation=_STR_CITATIONS["STR-019"],
                )
            )

        # Check description uses third person (Anthropic best practice)
        # Flag first-person ("I can", "I will", "I help") and second-person ("You can", "You will")
        _FIRST_PERSON_RE = re.compile(
            r"\b(I can|I will|I help|I am|I\'m|I process|I analyze|I generate|I create|I extract|I manage)\b",
            re.IGNORECASE,
        )
        _SECOND_PERSON_RE = re.compile(
            r"\b(You can|You will|You should|You may)\b",
            re.IGNORECASE,
        )
        fp_match = _FIRST_PERSON_RE.search(desc)
        sp_match = _SECOND_PERSON_RE.search(desc)
        if fp_match or sp_match:
            matched = fp_match.group(0) if fp_match else sp_match.group(0) if sp_match else ""
            findings.append(
                Finding(
                    code="STR-020",
                    severity=Severity.INFO,
                    category=Category.STRUCTURE,
                    title="Description should use third person",
                    detail=f"Found '{matched}' in description. Per Anthropic best practices, descriptions should use "
                    f"third person (e.g., 'Processes Excel files') instead of first person ('I can help') "
                    f"or second person ('You can use this'). Inconsistent point-of-view can cause discovery problems.",
                    file_path=str(skill_md),
                    fix="Rewrite the description in third person: 'Analyzes data...' instead of 'I analyze data...'.",
                    citation=_STR_CITATIONS["STR-020"],
                )
            )
    else:
        findings.append(
            Finding(
                code="STR-009",
                severity=Severity.CRITICAL,
                category=Category.STRUCTURE,
                title="'description' field must be a string",
                detail=f"The 'description' field must be a string, got {type(desc).__name__}.",
                file_path=str(skill_md),
                line_number=1,
                fix='Quote the description value in YAML: description: "..."',
                citation=_STR_CITATIONS["STR-009"],
            )
        )

    # --- Check 5: compatibility field ---
    compat = frontmatter.get("compatibility")
    if compat and isinstance(compat, str) and len(compat) > _MAX_COMPAT_LEN:
        findings.append(
            Finding(
                code="STR-012",
                severity=Severity.WARNING,
                category=Category.STRUCTURE,
                title=f"Compatibility field too long ({len(compat)} chars, max {_MAX_COMPAT_LEN})",
                detail=f"The compatibility field exceeds {_MAX_COMPAT_LEN} characters.",
                file_path=str(skill_md),
                citation=_STR_CITATIONS["STR-012"],
            )
        )

    # --- Check 6: metadata field type ---
    metadata = frontmatter.get("metadata")
    if metadata is not None and not isinstance(metadata, dict):
        # Try to parse as inline JSON (common in OpenClaw skills)
        if isinstance(metadata, str):
            try:
                parsed = json.loads(metadata)
                if isinstance(parsed, dict):
                    metadata = parsed  # Valid inline JSON map, accept it
                else:
                    findings.append(
                        Finding(
                            code="STR-013",
                            severity=Severity.WARNING,
                            category=Category.STRUCTURE,
                            title="metadata field should be a mapping",
                            detail=f"The metadata field should be a YAML mapping (key: value pairs). Parsed JSON is {type(parsed).__name__}.",
                            file_path=str(skill_md),
                            citation=_STR_CITATIONS["STR-013"],
                        )
                    )
            except (json.JSONDecodeError, Exception):
                findings.append(
                    Finding(
                        code="STR-013",
                        severity=Severity.WARNING,
                        category=Category.STRUCTURE,
                        title="metadata field should be a mapping",
                        detail="The metadata field should be a YAML mapping (key: value pairs), got string that isn't valid JSON.",
                        file_path=str(skill_md),
                        citation=_STR_CITATIONS["STR-013"],
                    )
                )
        else:
            findings.append(
                Finding(
                    code="STR-013",
                    severity=Severity.WARNING,
                    category=Category.STRUCTURE,
                    title="metadata field should be a mapping",
                    detail=f"The metadata field should be a YAML mapping (key: value pairs), got {type(metadata).__name__}.",
                    file_path=str(skill_md),
                    citation=_STR_CITATIONS["STR-013"],
                )
            )

    # --- Check 7: Progressive disclosure - SKILL.md size ---
    lines = content.split("\n")
    body_lines = lines[body_start:] if body_start > 0 else lines
    body_text = "\n".join(body_lines)
    total_lines = len(lines)

    if total_lines > _RECOMMENDED_MAX_LINES:
        findings.append(
            Finding(
                code="STR-014",
                severity=Severity.INFO,
                category=Category.STRUCTURE,
                title=f"SKILL.md exceeds recommended {_RECOMMENDED_MAX_LINES} lines ({total_lines} lines)",
                detail=f"The spec recommends keeping SKILL.md under {_RECOMMENDED_MAX_LINES} lines for efficient context usage.",
                file_path=str(skill_md),
                fix="Move detailed reference material to separate files in references/ or scripts/.",
                citation=_STR_CITATIONS["STR-014"],
            )
        )

    # Approximate token count (rough: ~4 chars per token for English)
    approx_tokens = len(body_text) // 4
    if approx_tokens > _RECOMMENDED_MAX_BODY_TOKENS_APPROX:
        findings.append(
            Finding(
                code="STR-015",
                severity=Severity.INFO,
                category=Category.STRUCTURE,
                title=f"SKILL.md body is large (~{approx_tokens} tokens, recommended <{_RECOMMENDED_MAX_BODY_TOKENS_APPROX})",
                detail="Large SKILL.md files consume significant context when activated. The spec recommends <5000 tokens for the instructions body.",
                file_path=str(skill_md),
                fix="Use progressive disclosure: move detailed content to references/ files loaded on demand.",
                citation=_STR_CITATIONS["STR-015"],
            )
        )

    # --- Check 8: README.md conflict ---
    readme = skill_path / "README.md"
    if readme.is_file():
        findings.append(
            Finding(
                code="STR-016",
                severity=Severity.INFO,
                category=Category.STRUCTURE,
                title="README.md present alongside SKILL.md",
                detail="Some agents may confuse README.md with SKILL.md. The skill entry point should be SKILL.md only.",
                file_path=str(readme),
                fix="Consider removing README.md or clearly differentiating it from SKILL.md.",
                citation=_STR_CITATIONS["STR-016"],
            )
        )

    # --- Check 9: Standard directories ---
    # Not a finding, just metadata — unusual dirs aren't necessarily wrong

    # --- Check 10: Token budget check — skills over ~4,000 tokens may degrade agent performance ---
    if body_text:
        word_count = len(body_text.split())
        estimated_tokens = int(word_count * 1.3)
        if estimated_tokens > 4000:
            findings.append(
                Finding(
                    code="STR-021",
                    severity=Severity.INFO,
                    category=Category.STRUCTURE,
                    title=f"Skill body is ~{estimated_tokens} tokens (recommended: <4,000)",
                    detail=(
                        f"The SKILL.md body has ~{word_count} words (~{estimated_tokens} tokens). "
                        "Long skills consume more context and may confuse the agent. "
                        "Consider splitting into a shorter SKILL.md with references/ for detailed content."
                    ),
                    file_path=str(skill_path / "SKILL.md"),
                    fix="Move detailed checklists or specifications to a references/ directory",
                    citation=_STR_CITATIONS["STR-021"],
                )
            )

    # --- Check 11: Scripts have no extension or are executable ---
    scripts_dir = skill_path / "scripts"
    if scripts_dir.is_dir():
        for script_file in scripts_dir.rglob("*"):
            if script_file.is_file() and script_file.suffix in (".py", ".sh", ".js", ".ts"):
                # Check for shebang
                try:
                    first_line = script_file.read_text(encoding="utf-8").split("\n")[0]
                    if script_file.suffix in (".py", ".sh") and not first_line.startswith("#!"):
                        findings.append(
                            Finding(
                                code="STR-017",
                                severity=Severity.INFO,
                                category=Category.QUALITY,
                                title="Script missing shebang line",
                                detail=f"'{script_file.name}' lacks a shebang (e.g., #!/usr/bin/env python3). Agents may not know how to execute it.",
                                file_path=str(script_file),
                                line_number=1,
                                fix="Add '#!/usr/bin/env python3' (or appropriate) as the first line.",
                                citation=_STR_CITATIONS["STR-017"],
                            )
                        )
                except Exception:
                    pass

    return findings, frontmatter, body_start
