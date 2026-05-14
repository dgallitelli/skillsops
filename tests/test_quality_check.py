"""Tests for the QLT-* authoring-quality checks."""
from pathlib import Path

import pytest

from skillctl.eval.audit.quality_check import check_quality
from skillctl.eval.schemas import Finding


def _write_skill(skill_dir: Path, name: str, description: str, body: str = "") -> None:
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: {description}\n---\n\n{body}\n"
    )


@pytest.fixture
def good_skill(tmp_path: Path) -> Path:
    """A skill that should produce zero QLT findings."""
    d = tmp_path / "good-skill"
    _write_skill(
        d,
        name="good-skill",
        description=(
            "Use when reviewing pull requests for security issues; checks for hardcoded "
            "credentials, unsafe deserialization, and prompt-injection patterns."
        ),
        body="## Example\n\n```bash\nskillctl eval audit ./my-skill\n```\n",
    )
    return d


def test_check_quality_returns_a_list_of_findings(good_skill: Path):
    findings = check_quality(good_skill)
    assert isinstance(findings, list)
    assert all(isinstance(f, Finding) for f in findings)


def test_check_quality_clean_skill_has_no_warnings(good_skill: Path):
    findings = check_quality(good_skill)
    warning_codes = [f.code for f in findings if f.severity.value == "WARNING"]
    assert not warning_codes, f"expected no QLT warnings, got {warning_codes}"


def test_check_quality_returns_empty_for_missing_skill_md(tmp_path: Path):
    # No SKILL.md — quality_check should bail gracefully (structure_check handles the error)
    d = tmp_path / "empty"
    d.mkdir()
    findings = check_quality(d)
    assert findings == []


# --- QLT-001: description starts with "Use when ..." ----------------------

def test_qlt_001_emitted_when_description_lacks_use_when_prefix(tmp_path):
    d = tmp_path / "skill-no-prefix"
    _write_skill(d, name="skill-no-prefix",
                 description="Reviews pull requests for security issues "
                             "across multiple languages and frameworks")
    codes = [f.code for f in check_quality(d)]
    assert "QLT-001" in codes


def test_qlt_001_not_emitted_when_description_starts_with_use_when(tmp_path):
    d = tmp_path / "skill-with-prefix"
    _write_skill(d, name="skill-with-prefix",
                 description="Use when reviewing pull requests for security issues "
                             "across multiple languages and frameworks")
    codes = [f.code for f in check_quality(d)]
    assert "QLT-001" not in codes


# --- QLT-002: description >=60 chars --------------------------------------

def test_qlt_002_emitted_for_short_description(tmp_path):
    d = tmp_path / "short-desc"
    _write_skill(d, name="short-desc", description="Use when something happens")
    codes = [f.code for f in check_quality(d)]
    assert "QLT-002" in codes


def test_qlt_002_not_emitted_for_60_plus_char_description(tmp_path):
    d = tmp_path / "long-desc"
    _write_skill(d, name="long-desc",
                 description="Use when reviewing PRs across multiple languages "
                             "and frameworks for security issues")
    codes = [f.code for f in check_quality(d)]
    assert "QLT-002" not in codes


# --- QLT-003: description doesn't summarise workflow ----------------------

def test_qlt_003_emitted_when_description_summarises_workflow(tmp_path):
    d = tmp_path / "workflow-desc"
    _write_skill(d, name="workflow-desc",
                 description="First runs the linter, then formats the output, "
                             "and finally writes a report to disk")
    codes = [f.code for f in check_quality(d)]
    assert "QLT-003" in codes


def test_qlt_003_not_emitted_for_when_focused_description(tmp_path):
    d = tmp_path / "when-desc"
    _write_skill(d, name="when-desc",
                 description="Use when reviewing pull requests for security issues "
                             "across multiple languages and frameworks")
    codes = [f.code for f in check_quality(d)]
    assert "QLT-003" not in codes


# --- QLT-004: name avoids generic words -----------------------------------

def test_qlt_004_emitted_for_generic_name(tmp_path):
    d = tmp_path / "data-helpers"
    _write_skill(d, name="data-helpers",
                 description="Use when munging data files for downstream tools and pipelines")
    codes = [f.code for f in check_quality(d)]
    assert "QLT-004" in codes


def test_qlt_004_not_emitted_for_specific_name(tmp_path):
    d = tmp_path / "csv-deduplicator"
    _write_skill(d, name="csv-deduplicator",
                 description="Use when removing duplicate rows from CSV files based on primary key")
    codes = [f.code for f in check_quality(d)]
    assert "QLT-004" not in codes


# --- QLT-005: directory uses hyphens, not underscores ---------------------

def test_qlt_005_emitted_for_underscore_directory(tmp_path):
    d = tmp_path / "my_skill"
    # Write SKILL.md by hand so the name field doesn't conflict with directory
    d.mkdir()
    (d / "SKILL.md").write_text(
        "---\nname: my-skill\ndescription: Use when handling test cases for the skill workflow checker\n---\n\nbody\n"
    )
    codes = [f.code for f in check_quality(d)]
    assert "QLT-005" in codes


def test_qlt_005_not_emitted_for_hyphen_directory(tmp_path):
    d = tmp_path / "my-skill"
    _write_skill(d, name="my-skill",
                 description="Use when handling test cases for the skill workflow checker")
    codes = [f.code for f in check_quality(d)]
    assert "QLT-005" not in codes


# --- QLT-018: SKILL.md has body content -----------------------------------

def test_qlt_018_emitted_for_frontmatter_only_skill(tmp_path):
    d = tmp_path / "empty-body"
    d.mkdir()
    (d / "SKILL.md").write_text(
        "---\nname: empty-body\ndescription: Use when needing to check edge cases for empty bodies\n---\n"
    )
    codes = [f.code for f in check_quality(d)]
    assert "QLT-018" in codes


def test_qlt_018_not_emitted_when_body_present(tmp_path):
    d = tmp_path / "with-body"
    _write_skill(d, name="with-body",
                 description="Use when handling test cases for the skill workflow checker",
                 body="Real instructions go here.")
    codes = [f.code for f in check_quality(d)]
    assert "QLT-018" not in codes


GOOD_DESC = "Use when handling test cases for the skill workflow checker"


# --- QLT-007: no Windows-style backslash paths ----------------------------

def test_qlt_007_emitted_for_backslash_paths(tmp_path):
    d = tmp_path / "win-paths"
    _write_skill(d, "win-paths", GOOD_DESC,
                 body="Run scripts\\helper.py to start.")
    codes = [f.code for f in check_quality(d)]
    assert "QLT-007" in codes


def test_qlt_007_not_emitted_for_forward_slashes(tmp_path):
    d = tmp_path / "unix-paths"
    _write_skill(d, "unix-paths", GOOD_DESC,
                 body="Run scripts/helper.py to start.")
    codes = [f.code for f in check_quality(d)]
    assert "QLT-007" not in codes


# --- QLT-011: time-sensitive language outside Old Patterns ---------------

def test_qlt_011_emitted_for_dated_language_in_main_section(tmp_path):
    d = tmp_path / "dated"
    _write_skill(d, "dated", GOOD_DESC,
                 body="## How it works\n\nAs of 2024 the API returns JSON.\n")
    codes = [f.code for f in check_quality(d)]
    assert "QLT-011" in codes


def test_qlt_011_not_emitted_in_old_patterns_section(tmp_path):
    d = tmp_path / "ok-dated"
    _write_skill(d, "ok-dated", GOOD_DESC,
                 body="## Old patterns\n\nAs of 2024 the API returned JSON.\n")
    codes = [f.code for f in check_quality(d)]
    assert "QLT-011" not in codes


# --- QLT-013: MCP tool refs fully qualified ------------------------------

def test_qlt_013_emitted_for_unqualified_mcp(tmp_path):
    d = tmp_path / "bad-mcp"
    _write_skill(d, "bad-mcp", GOOD_DESC,
                 body="Use the `mcp__search` tool to look up records.")
    codes = [f.code for f in check_quality(d)]
    assert "QLT-013" in codes


def test_qlt_013_not_emitted_for_qualified_mcp(tmp_path):
    d = tmp_path / "good-mcp"
    _write_skill(d, "good-mcp", GOOD_DESC,
                 body="Use the `mcp__brave__search` tool to look up records.")
    codes = [f.code for f in check_quality(d)]
    assert "QLT-013" not in codes


# --- QLT-016: template residue -------------------------------------------

def test_qlt_016_emitted_for_template_residue(tmp_path):
    d = tmp_path / "residue"
    _write_skill(d, "residue", GOOD_DESC,
                 body="# residue\n\nInsert instructions below.\n")
    codes = [f.code for f in check_quality(d)]
    assert "QLT-016" in codes


def test_qlt_016_not_emitted_for_real_body(tmp_path):
    d = tmp_path / "no-residue"
    _write_skill(d, "no-residue", GOOD_DESC,
                 body="# Real skill\n\nThis skill does X by running Y.\n")
    codes = [f.code for f in check_quality(d)]
    assert "QLT-016" not in codes


# --- QLT-017: at least one fenced block or ## Example section -----------

def test_qlt_017_emitted_when_no_examples(tmp_path):
    d = tmp_path / "no-examples"
    _write_skill(d, "no-examples", GOOD_DESC,
                 body="Just narrative prose with no code or examples.\n")
    codes = [f.code for f in check_quality(d)]
    assert "QLT-017" in codes


def test_qlt_017_not_emitted_when_fenced_block_present(tmp_path):
    d = tmp_path / "with-fence"
    _write_skill(d, "with-fence", GOOD_DESC,
                 body="Run this:\n\n```bash\nls\n```\n")
    codes = [f.code for f in check_quality(d)]
    assert "QLT-017" not in codes


# --- QLT-019: consistent terminology -------------------------------------

def test_qlt_019_emitted_for_three_synonyms(tmp_path):
    d = tmp_path / "synonyms"
    _write_skill(d, "synonyms", GOOD_DESC,
                 body="Fill the field, then the box, then the input control.\n")
    codes = [f.code for f in check_quality(d)]
    assert "QLT-019" in codes


def test_qlt_019_not_emitted_for_one_term(tmp_path):
    d = tmp_path / "consistent"
    _write_skill(d, "consistent", GOOD_DESC,
                 body="Fill the field. Then fill the next field. Done.\n")
    codes = [f.code for f in check_quality(d)]
    assert "QLT-019" not in codes
