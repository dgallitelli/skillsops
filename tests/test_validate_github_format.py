"""Regression tests for ``skillctl validate --format=github``.

The format mirrors ``eval audit --format=github``: one workflow command
per validation issue, wrapped in a ``::group::Validation: <skill>``
collapse with a ``VALID|INVALID — N errors, M warnings`` summary line.

Tests cover:

- The shared ``_gh_workflow_line`` primitive behaves identically
  whether called from the audit or validate format.
- Per-issue file routing (load_warnings → SKILL.md, schema/cap
  warnings → skill.yaml).
- The summary line.
- Backward compatibility: ``--json`` still works exactly as before;
  ``--format=github`` supersedes ``--json`` when both are passed.
- Catastrophic load failure (unparseable YAML) emits a single
  ``::error file=skill.yaml::`` instead of a Python traceback —
  the most CI-relevant scenario.
- Skill-name escaping in the group title.
- CLI smoke against the real binary.
"""

from __future__ import annotations

import io
import shutil
import subprocess
import sys
from pathlib import Path

from skillctl.eval.report import (
    _gh_workflow_line,
    format_github_validation,
)


def _find_skillctl() -> str:
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
# _gh_workflow_line — shared primitive
# ---------------------------------------------------------------------------


class TestWorkflowLine:
    def test_basic_error(self):
        line = _gh_workflow_line(
            "error",
            file="skill.yaml",
            line=None,
            title="VAL-X some title",
            body="some body",
        )
        assert line == "::error file=skill.yaml,title=VAL-X some title::some body"

    def test_omits_file_when_none(self):
        line = _gh_workflow_line("error", file=None, line=None, title="t", body="b")
        assert "file=" not in line
        assert "line=" not in line
        assert line.endswith("title=t::b")

    def test_omits_line_when_file_missing(self):
        # Even if line is set, drop it when file is None — GitHub
        # silently drops it anyway.
        line = _gh_workflow_line("warning", file=None, line=42, title="t", body="b")
        assert "line=" not in line

    def test_emits_line_when_file_present(self):
        line = _gh_workflow_line("error", file="skill.yaml", line=42, title="t", body="b")
        assert "file=skill.yaml" in line
        assert "line=42" in line

    def test_escapes_title_param(self):
        line = _gh_workflow_line("error", file=None, line=None, title="a:b,c", body="d")
        assert "title=a%3Ab%2Cc" in line

    def test_preserves_body_punctuation(self):
        line = _gh_workflow_line("error", file=None, line=None, title="t", body="a:b, c")
        # Body keeps colons and commas literal.
        assert line.endswith("::a:b, c")


# ---------------------------------------------------------------------------
# format_github_validation — direct calls
# ---------------------------------------------------------------------------


class TestFormatGithubValidation:
    def test_clean_skill_emits_just_group(self):
        buf = io.StringIO()
        format_github_validation(skill_name="my-skill", issues=[], file=buf)
        out = buf.getvalue()
        lines = [line for line in out.splitlines() if line]
        assert lines[0] == "::group::Validation: my-skill"
        assert lines[1] == "VALID — 0 errors, 0 warnings"
        assert lines[-1] == "::endgroup::"
        assert not any(line.startswith(("::error", "::warning")) for line in lines)

    def test_error_emits_error_annotation(self):
        issues = [
            {
                "severity": "error",
                "code": "VAL-NAME-REQUIRED",
                "message": "metadata.name is required",
                "path": "metadata.name",
                "hint": "Add a name like 'my-org/my-skill'",
                "file": "skill.yaml",
            }
        ]
        buf = io.StringIO()
        format_github_validation(skill_name="my-skill", issues=issues, file=buf)
        out = buf.getvalue()
        assert "INVALID — 1 error, 0 warnings" in out
        # Annotation line is bound to skill.yaml and carries the path
        # and hint in the body.
        annotation = next(line for line in out.splitlines() if line.startswith("::error"))
        assert "file=skill.yaml" in annotation
        assert "title=VAL-NAME-REQUIRED metadata.name is required" in annotation
        assert "Path: metadata.name" in annotation
        assert "Fix: Add a name" in annotation

    def test_warning_emits_warning_annotation(self):
        issues = [
            {
                "severity": "warning",
                "code": "VAL-NAME-NO-NAMESPACE",
                "message": "Name has no namespace prefix",
                "path": "metadata.name",
                "hint": "Use 'my-org/my-skill'",
                "file": "skill.yaml",
            }
        ]
        buf = io.StringIO()
        format_github_validation(skill_name="my-skill", issues=issues, file=buf)
        out = buf.getvalue()
        assert "VALID — 0 errors, 1 warning" in out
        annotation = next(line for line in out.splitlines() if line.startswith("::warning"))
        assert "file=skill.yaml" in annotation
        assert "VAL-NAME-NO-NAMESPACE" in annotation

    def test_summary_pluralizes_correctly(self):
        # Two errors → "2 errors"; one warning → "1 warning".
        issues = [
            {
                "severity": "error",
                "code": "X",
                "message": "a",
                "path": "",
                "hint": "",
                "file": "skill.yaml",
            },
            {
                "severity": "error",
                "code": "Y",
                "message": "b",
                "path": "",
                "hint": "",
                "file": "skill.yaml",
            },
            {
                "severity": "warning",
                "code": "W",
                "message": "c",
                "path": "",
                "hint": "",
                "file": "skill.yaml",
            },
        ]
        buf = io.StringIO()
        format_github_validation(skill_name="x", issues=issues, file=buf)
        assert "INVALID — 2 errors, 1 warning" in buf.getvalue()

    def test_skill_name_uses_message_escapes(self):
        # Group title is in the message body, so colons stay literal
        # but newlines escape.
        buf = io.StringIO()
        format_github_validation(skill_name="my:org/skill\nname", issues=[], file=buf)
        first = buf.getvalue().splitlines()[0]
        assert first == "::group::Validation: my:org/skill%0Aname"


# ---------------------------------------------------------------------------
# CLI smoke
# ---------------------------------------------------------------------------


VALID_SKILL_YAML = """\
apiVersion: skillctl.io/v1
kind: Skill

metadata:
  name: test-org/test-skill
  version: 0.1.0
  description: A skill for testing the validate-format-github path

spec:
  content:
    path: ./SKILL.md
  capabilities:
    - read_file
"""

VALID_SKILL_MD = """\
---
name: test-org/test-skill
description: A skill for testing the validate-format-github path
---

Body.
"""

INVALID_SKILL_YAML = """\
apiVersion: skillctl.io/v1
kind: Skill

metadata:
  name: ""
  version: not-a-version
  description: ""

spec:
  content:
    path: ./SKILL.md
"""

UNPARSEABLE_SKILL_YAML = """\
this is not :: valid YAML
%%%
"""


def _make_skill(tmp_path: Path, *, yaml: str = VALID_SKILL_YAML, md: str = VALID_SKILL_MD) -> Path:
    skill = tmp_path / "skill"
    skill.mkdir()
    (skill / "skill.yaml").write_text(yaml)
    (skill / "SKILL.md").write_text(md)
    return skill


class TestValidateGithubCLI:
    def test_clean_skill_emits_VALID_summary(self, tmp_path):
        skill = _make_skill(tmp_path)
        r = subprocess.run(
            [SKILLCTL, "validate", str(skill), "--format=github"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0, r.stderr
        assert "::group::Validation: test-org/test-skill" in r.stdout
        assert "VALID — 0 errors" in r.stdout
        assert "::endgroup::" in r.stdout
        # No annotations for a clean skill.
        assert "::error" not in r.stdout
        assert "::warning" not in r.stdout

    def test_invalid_skill_emits_error_annotations(self, tmp_path):
        skill = _make_skill(tmp_path, yaml=INVALID_SKILL_YAML)
        r = subprocess.run(
            [SKILLCTL, "validate", str(skill), "--format=github"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 1
        assert "INVALID" in r.stdout
        # At least one ::error line bound to skill.yaml.
        error_lines = [line for line in r.stdout.splitlines() if line.startswith("::error")]
        assert error_lines
        assert all("file=" in line and "skill.yaml" in line for line in error_lines)

    def test_unparseable_yaml_emits_VAL_LOAD_annotation_not_traceback(self, tmp_path):
        # The most CI-relevant scenario: a malformed YAML PR diff.
        skill = _make_skill(tmp_path, yaml=UNPARSEABLE_SKILL_YAML)
        r = subprocess.run(
            [SKILLCTL, "validate", str(skill), "--format=github"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 1
        # No Python traceback.
        assert "Traceback" not in r.stderr
        assert "Traceback" not in r.stdout
        # Single ::error annotation bound to skill.yaml.
        assert "::error" in r.stdout
        assert "VAL-LOAD" in r.stdout
        assert "skill.yaml" in r.stdout

    def test_json_flag_still_works(self, tmp_path):
        skill = _make_skill(tmp_path)
        r = subprocess.run(
            [SKILLCTL, "validate", str(skill), "--json"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        # Backward-compat: --json produces a JSON object.
        import json as _json

        data = _json.loads(r.stdout)
        assert data["valid"] is True
        assert data["errors"] == []

    def test_format_github_supersedes_json_flag(self, tmp_path):
        # When both --json and --format=github are passed, --format wins.
        skill = _make_skill(tmp_path)
        r = subprocess.run(
            [SKILLCTL, "validate", str(skill), "--json", "--format=github"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        # Github output, not JSON.
        assert r.stdout.startswith("::group::")
        # Sanity: NOT a JSON object.
        import json as _json

        try:
            _json.loads(r.stdout)
            assert False, "stdout was parseable as JSON; expected workflow commands"
        except _json.JSONDecodeError:
            pass

    def test_format_text_default_unchanged(self, tmp_path):
        # Regression guard: the default text format keeps emitting its
        # human-readable output and the "Next:" breadcrumb suppression
        # rules.
        skill = _make_skill(tmp_path)
        r = subprocess.run(
            [SKILLCTL, "validate", str(skill)],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert "✓ Valid" in r.stdout
        assert "::group::" not in r.stdout

    def test_load_warnings_route_to_SKILL_md(self, tmp_path):
        # Deterministic exercise of the load_warnings branch: a bare
        # SKILL.md with no description triggers ``W_NO_DESCRIPTION``
        # from `ManifestLoader.load` (manifest.py:255-262).  That
        # warning must bind to SKILL.md, not skill.yaml — load
        # warnings come from frontmatter parsing.
        skill = tmp_path / "bare-skill"
        skill.mkdir()
        (skill / "SKILL.md").write_text("---\nname: bare-skill\n---\n\nBody.\n")
        # No skill.yaml on purpose.

        r = subprocess.run(
            [SKILLCTL, "validate", str(skill), "--format=github"],
            capture_output=True,
            text=True,
        )
        # Validation completes (the loader auto-wraps a bare SKILL.md);
        # exit code depends on the warnings collected, but the
        # important invariant is the routing.
        warning_lines = [line for line in r.stdout.splitlines() if line.startswith("::warning ")]
        load_warnings = [line for line in warning_lines if "W_NO_DESCRIPTION" in line]
        assert load_warnings, "expected W_NO_DESCRIPTION load warning to fire"
        # The W_NO_DESCRIPTION load warning must annotate SKILL.md.
        assert "file=" in load_warnings[0]
        assert "SKILL.md" in load_warnings[0]
        assert "skill.yaml" not in load_warnings[0]
