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
