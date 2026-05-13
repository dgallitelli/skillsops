"""Regression tests for ``skillctl eval audit --strict``.

The strict mode adds three things on top of the default audit:

1. NFKC normalisation of text before regex matching (catches fullwidth
   and mathematical-alphanumeric homoglyphs; does NOT catch Cyrillic).
2. A Python AST pass over ``*.py`` files that catches multi-line
   eval/exec, unsafe pickle/yaml.load, subprocess.shell=True, and
   base64 literal-concatenation bypasses that the line-oriented regex
   pass misses.
3. A larger default file-size cap (10 MB instead of 1 MB), with files
   at the cap surfaced via a STR-022 INFO finding.

Tests cover each on its own + interactions with ``.skilleval.yaml``
and the existing CLI flags.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

from skillctl.eval.audit.security_scan import (
    DEFAULT_MAX_FILE_BYTES,
    STRICT_MAX_FILE_BYTES,
    _ast_scan_python,
    _nfkc_normalize,
    scan_security,
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
# NFKC normalisation
# ---------------------------------------------------------------------------


class TestNFKCNormalize:
    def test_fullwidth_eval_collapses_to_ascii(self):
        # Fullwidth Latin small letters in U+FF00 block — NFKC folds.
        assert _nfkc_normalize("ｅｖａｌ") == "eval"

    def test_mathematical_bold_eval_collapses_to_ascii(self):
        # Mathematical bold (U+1D400 block) — NFKC folds.
        assert _nfkc_normalize("𝐞𝐯𝐚𝐥") == "eval"

    def test_cyrillic_homoglyphs_NOT_collapsed(self):
        # Cyrillic small letter ie (U+0435) is a different script, not a
        # compatibility variant — NFKC leaves it alone.  Documented in
        # docs/3-security-audit.md as a known gap.
        assert _nfkc_normalize("еval") != "eval"
        assert "е" in _nfkc_normalize("еval")  # cyrillic stays cyrillic

    def test_ascii_passthrough(self):
        assert _nfkc_normalize("eval(x)") == "eval(x)"


# ---------------------------------------------------------------------------
# AST scanner — Python source patterns
# ---------------------------------------------------------------------------


def _ast_codes(source: str) -> list[str]:
    """Run the AST scanner on a string and return the finding codes."""
    findings = _ast_scan_python(Path("/tmp/test.py"), source)
    return [f.code for f in findings]


class TestASTScanner:
    def test_multi_line_eval_detected(self):
        # The existing line-oriented regex sees `eval(` on the first line
        # and flags it via SEC-003; the AST flags it specifically as
        # SEC-007-AST so reviewers can distinguish.
        codes = _ast_codes("eval(\n  'print(1)'\n)\n")
        assert "SEC-007-AST" in codes

    def test_exec_detected(self):
        assert "SEC-007-AST" in _ast_codes("exec('x = 1')\n")

    def test_compile_detected(self):
        assert "SEC-007-AST" in _ast_codes("compile('x', 'f', 'exec')\n")

    def test_dunder_import_detected(self):
        assert "SEC-007-AST" in _ast_codes("m = __import__('os')\n")

    def test_pickle_loads_detected(self):
        codes = _ast_codes("import pickle\npickle.loads(data)\n")
        assert "SEC-006-AST" in codes

    def test_pickle_load_detected(self):
        codes = _ast_codes("import pickle\nwith open('f', 'rb') as fh:\n    pickle.load(fh)\n")
        assert "SEC-006-AST" in codes

    def test_marshal_loads_detected(self):
        assert "SEC-006-AST" in _ast_codes("import marshal\nmarshal.loads(b)\n")

    def test_shelve_open_detected(self):
        assert "SEC-006-AST" in _ast_codes("import shelve\nshelve.open('db')\n")

    def test_yaml_load_without_loader_detected(self):
        assert "SEC-006-AST" in _ast_codes("import yaml\nyaml.load(s)\n")

    def test_yaml_load_with_safeloader_NOT_detected(self):
        codes = _ast_codes("import yaml\nyaml.load(s, Loader=yaml.SafeLoader)\n")
        assert "SEC-006-AST" not in codes

    def test_yaml_safe_load_NOT_detected(self):
        codes = _ast_codes("import yaml\nyaml.safe_load(s)\n")
        assert "SEC-006-AST" not in codes

    def test_subprocess_shell_true_detected(self):
        codes = _ast_codes("import subprocess\nsubprocess.run('ls', shell=True)\n")
        assert "SEC-003-AST" in codes

    def test_subprocess_without_shell_NOT_detected(self):
        codes = _ast_codes("import subprocess\nsubprocess.run(['ls'])\n")
        assert "SEC-003-AST" not in codes

    def test_subprocess_shell_false_NOT_detected(self):
        codes = _ast_codes("import subprocess\nsubprocess.run('ls', shell=False)\n")
        assert "SEC-003-AST" not in codes

    def test_os_system_detected(self):
        codes = _ast_codes("import os\nos.system('echo hi')\n")
        assert "SEC-003-AST" in codes

    def test_os_popen_detected(self):
        codes = _ast_codes("import os\nos.popen('ls')\n")
        assert "SEC-003-AST" in codes

    def test_b64decode_literal_concat_detected(self):
        codes = _ast_codes('import base64\nbase64.b64decode("AA" + "BB" + "CC")\n')
        assert "SEC-008-AST" in codes

    def test_b64decode_single_literal_NOT_detected_by_AST(self):
        # Single-literal b64decode is caught by the existing
        # LONG_BASE64_STRING regex when the data is long enough — the
        # AST's job is the multi-literal-concat bypass.
        codes = _ast_codes('import base64\nbase64.b64decode("AAAA")\n')
        assert "SEC-008-AST" not in codes

    def test_b64decode_variable_concat_NOT_detected(self):
        # `b64decode(s + t)` where s and t are names would require taint
        # analysis — out of scope.  AST only flags Constant+Constant.
        codes = _ast_codes("import base64\nbase64.b64decode(s + t)\n")
        assert "SEC-008-AST" not in codes

    def test_non_python_syntax_skipped_silently(self):
        # A file with .py extension that's not actually Python should
        # not bubble up a SyntaxError.
        codes = _ast_codes("this is not :: valid python\n%%%\n")
        assert codes == []

    def test_clean_python_no_findings(self):
        source = textwrap.dedent("""
            def add(a, b):
                return a + b

            class Foo:
                def __init__(self, x):
                    self.x = x
        """)
        assert _ast_codes(source) == []


# ---------------------------------------------------------------------------
# from-import aliasing — closes the docs-listed gap from PR #8
# ---------------------------------------------------------------------------


class TestFromImportAliasing:
    """`from MOD import NAME [as ALIAS]; NAME(args)` should resolve
    through the alias map to ``MOD.NAME`` so the same dispatch rules
    fire as for the plain ``MOD.NAME(args)`` shape.  Unaliased
    bare-name calls (e.g. a hand-rolled ``def loads(x)``) must NOT
    be flagged — that's the false-positive boundary."""

    # ---- Positive cases (aliased dangerous calls are flagged) ----

    def test_from_pickle_import_loads_detected(self):
        codes = _ast_codes("from pickle import loads\nloads(data)\n")
        assert "SEC-006-AST" in codes

    def test_from_pickle_import_loads_with_asname_detected(self):
        codes = _ast_codes("from pickle import loads as P\nP(data)\n")
        assert "SEC-006-AST" in codes

    def test_from_marshal_import_loads_detected(self):
        codes = _ast_codes("from marshal import loads\nloads(b)\n")
        assert "SEC-006-AST" in codes

    def test_from_yaml_import_load_detected(self):
        codes = _ast_codes("from yaml import load\nload(s)\n")
        assert "SEC-006-AST" in codes

    def test_from_yaml_import_load_with_safeloader_NOT_detected(self):
        codes = _ast_codes("from yaml import load, SafeLoader\nload(s, Loader=SafeLoader)\n")
        assert "SEC-006-AST" not in codes

    def test_from_subprocess_import_run_shell_true_detected(self):
        codes = _ast_codes("from subprocess import run\nrun('ls', shell=True)\n")
        assert "SEC-003-AST" in codes

    def test_from_subprocess_import_run_no_shell_NOT_detected(self):
        codes = _ast_codes("from subprocess import run\nrun(['ls'])\n")
        assert "SEC-003-AST" not in codes

    def test_from_os_import_system_detected(self):
        codes = _ast_codes("from os import system\nsystem('echo hi')\n")
        assert "SEC-003-AST" in codes

    def test_from_base64_import_b64decode_concat_detected(self):
        codes = _ast_codes('from base64 import b64decode\nb64decode("AA" + "BB" + "CC")\n')
        assert "SEC-008-AST" in codes

    # ---- Negative cases (false-positive boundary) ----

    def test_unaliased_loads_NOT_detected(self):
        # `loads(data)` with no matching from-import should not fire.
        # Otherwise the scanner false-positives on every module that
        # has its own `loads` symbol.
        codes = _ast_codes("loads(data)\n")
        assert "SEC-006-AST" not in codes

    def test_function_named_loads_NOT_detected(self):
        # Local function definition called `loads` is unrelated to
        # pickle.loads.  No `from pickle import loads` happens.
        codes = _ast_codes(
            textwrap.dedent("""
                def loads(x):
                    return x

                loads(data)
            """)
        )
        assert "SEC-006-AST" not in codes

    def test_function_named_b64decode_NOT_detected(self):
        # Regression guard: before the alias-map refactor, a bare-name
        # `b64decode(...)` call would fire SEC-008-AST regardless of
        # any imports.  With aliases, only `from base64 import
        # b64decode` (or attribute access) fires; a hand-rolled
        # local `def b64decode` is left alone.  This locks in the new
        # boundary.
        codes = _ast_codes(
            textwrap.dedent("""
                def b64decode(x):
                    return x

                b64decode("AA" + "BB" + "CC")
            """)
        )
        assert "SEC-008-AST" not in codes

    # ---- File-wide alias-map semantics ----

    def test_module_scope_alias_is_detected(self):
        # The simple, intended case: a module-scope `from X import Y`
        # followed by a call to Y at module scope fires.
        codes = _ast_codes("from pickle import loads\n\nloads(blob)\n")
        assert "SEC-006-AST" in codes

    def test_alias_map_is_file_wide_by_design(self):
        # Document the deliberate trade-off: a `from`-import inside a
        # function still pollutes the module-wide alias map.  The
        # `def loads(x): ...` shadow case is unrealistic in the same
        # file as a `from pickle import loads`, and over-flagging is
        # the right side of the false-positive/false-negative ledger
        # when the dangerous call is `pickle.loads`.  See
        # `_collect_from_import_aliases` docstring.
        codes = _ast_codes(
            textwrap.dedent("""
                def helper():
                    from pickle import loads
                    return loads(trusted_blob)

                # File-wide alias map means the call below ALSO
                # resolves through the alias.  Over-flagging is
                # deliberate; see docstring on _collect_from_import_aliases.
                loads(maybe_untrusted)
            """)
        )
        # Two findings: the call inside ``helper()`` AND the
        # module-scope call resolve through the file-wide alias map.
        # The module-scope call is the load-bearing assertion — under
        # hypothetical module-scope-only collection, only the in-function
        # call would fire, and the count would be 1.  Asserting == 2
        # locks in the deliberate file-wide semantic.
        assert codes.count("SEC-006-AST") == 2

    def test_star_import_does_not_register_aliases(self):
        # `from X import *` doesn't tell us what was bound; the alias
        # collector skips it.  An unaliased `loads(x)` after a star
        # import is still NOT flagged.
        codes = _ast_codes("from pickle import *\nloads(data)\n")
        assert "SEC-006-AST" not in codes

    def test_relative_import_does_not_register_aliases(self):
        # `from .pickle import loads` refers to a LOCAL submodule named
        # `pickle`, not stdlib pickle.  The collector skips relative
        # imports so we don't false-positive on
        # ``from .stdlib_alias import loads`` shapes.
        codes = _ast_codes("from .pickle import loads\nloads(data)\n")
        assert "SEC-006-AST" not in codes

    def test_dotted_relative_import_does_not_register_aliases(self):
        # Same logic for multi-dot relative imports.
        codes = _ast_codes("from ..foo.pickle import loads\nloads(data)\n")
        assert "SEC-006-AST" not in codes


# ---------------------------------------------------------------------------
# Integration: scan_security with strict=True
# ---------------------------------------------------------------------------


def _make_skill(tmp_path: Path, *, py_content: str = "", md_extra: str = "") -> Path:
    """Build a minimal valid skill at tmp_path / 'skill'."""
    skill = tmp_path / "skill"
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        f"---\nname: test-skill\ndescription: A test skill that exists for unit-test purposes only\n---\n\n# Body\n{md_extra}\n"
    )
    if py_content:
        scripts = skill / "scripts"
        scripts.mkdir()
        (scripts / "main.py").write_text(py_content)
    return skill


class TestScanSecurityStrict:
    def test_strict_off_misses_multiline_eval_AST_finding(self, tmp_path):
        skill = _make_skill(tmp_path, py_content="eval(\n  'x'\n)\n")
        findings = scan_security(skill, include_all=True)
        codes = [f.code for f in findings]
        # AST findings should NOT appear without --strict.
        assert not any(c.endswith("-AST") for c in codes)

    def test_strict_on_adds_AST_findings(self, tmp_path):
        skill = _make_skill(tmp_path, py_content="eval(\n  'x'\n)\n")
        findings = scan_security(skill, include_all=True, strict=True)
        codes = [f.code for f in findings]
        assert "SEC-007-AST" in codes

    def test_strict_does_not_change_clean_skill_grade(self, tmp_path):
        # Clean Python — no AST findings, no homoglyphs, no oversized
        # files.  Strict shouldn't penalise.
        skill = _make_skill(tmp_path, py_content="def add(a, b):\n    return a + b\n")
        clean_findings = scan_security(skill, include_all=True)
        strict_findings = scan_security(skill, include_all=True, strict=True)
        # Same set of findings either way.
        assert {f.code for f in clean_findings} == {f.code for f in strict_findings}

    def test_strict_default_cap_is_10mb(self, tmp_path):
        # Drop a 5 MB file in scripts/.  Default cap (1 MB) skips it
        # with STR-022; strict cap (10 MB) scans it.
        skill = _make_skill(tmp_path, py_content="x = 1\n")
        big_path = skill / "scripts" / "big.py"
        big_path.write_text("# pad\n" * 1_000_000)  # ~7 MB of comments

        default = scan_security(skill, include_all=True)
        default_codes = [f.code for f in default]
        assert "STR-022" in default_codes  # skipped under default cap

        strict = scan_security(skill, include_all=True, strict=True)
        strict_codes = [f.code for f in strict]
        # In strict mode the file is under the 10 MB cap so it's
        # scanned, no STR-022.
        assert "STR-022" not in strict_codes

    def test_explicit_max_file_bytes_overrides_default(self, tmp_path):
        # max_file_bytes=100 overrides both the default and strict's
        # raised cap, forcing skip with STR-022.
        skill = _make_skill(tmp_path, py_content="x = 1\n" * 100)  # > 100 bytes
        findings = scan_security(skill, include_all=True, max_file_bytes=100)
        codes = [f.code for f in findings]
        assert "STR-022" in codes

    def test_strict_constants_for_caps_are_sane(self):
        assert DEFAULT_MAX_FILE_BYTES == 1_000_000
        assert STRICT_MAX_FILE_BYTES == 10_000_000


# ---------------------------------------------------------------------------
# .skilleval.yaml integration
# ---------------------------------------------------------------------------


class TestSkillevalYAMLStrict:
    def test_strict_true_in_yaml_enables_strict_mode(self, tmp_path):
        skill = _make_skill(tmp_path, py_content="eval(\n  'x'\n)\n")
        (skill / ".skilleval.yaml").write_text("audit:\n  strict: true\n")

        # Run via run_audit (which reads .skilleval.yaml) so the test
        # exercises the config-merge path, not just scan_security().
        from skillctl.eval.cli import run_audit

        report = run_audit(str(skill), include_all=True)
        codes = [f.code for f in report.findings]
        assert "SEC-007-AST" in codes

    def test_max_file_bytes_in_yaml_respected(self, tmp_path):
        skill = _make_skill(tmp_path, py_content="x = 1\n" * 100)
        (skill / ".skilleval.yaml").write_text("audit:\n  max_file_bytes: 100\n")

        from skillctl.eval.cli import run_audit

        report = run_audit(str(skill), include_all=True)
        codes = [f.code for f in report.findings]
        assert "STR-022" in codes

    def test_cli_strict_overrides_yaml_off(self, tmp_path):
        # YAML doesn't enable strict; CLI flag does — strict should run.
        skill = _make_skill(tmp_path, py_content="eval(\n  'x'\n)\n")
        (skill / ".skilleval.yaml").write_text("audit:\n  strict: false\n")

        from skillctl.eval.cli import run_audit

        report = run_audit(str(skill), include_all=True, strict=True)
        codes = [f.code for f in report.findings]
        assert "SEC-007-AST" in codes


# ---------------------------------------------------------------------------
# CLI smoke
# ---------------------------------------------------------------------------


class TestStrictCLISmoke:
    def test_strict_flag_emits_AST_findings_in_text_output(self, tmp_path):
        skill = _make_skill(tmp_path, py_content="eval(\n  'x'\n)\n")
        r = subprocess.run(
            [SKILLCTL, "eval", "audit", str(skill), "--strict", "--include-all", "--verbose"],
            capture_output=True,
            text=True,
        )
        # Warnings only, no critical — exit 0.
        assert r.returncode == 0
        assert "SEC-007-AST" in r.stdout

    def test_strict_with_fail_on_warning_exits_1(self, tmp_path):
        skill = _make_skill(tmp_path, py_content="eval(\n  'x'\n)\n")
        r = subprocess.run(
            [
                SKILLCTL,
                "eval",
                "audit",
                str(skill),
                "--strict",
                "--include-all",
                "--fail-on-warning",
            ],
            capture_output=True,
            text=True,
        )
        # AST eval warning + --fail-on-warning → exit 1.
        assert r.returncode == 1

    def test_max_file_bytes_flag(self, tmp_path):
        skill = _make_skill(tmp_path, py_content="x = 1\n" * 100)
        r = subprocess.run(
            [
                SKILLCTL,
                "eval",
                "audit",
                str(skill),
                "--include-all",
                "--max-file-bytes",
                "100",
                "--verbose",
            ],
            capture_output=True,
            text=True,
        )
        assert "STR-022" in r.stdout

    def test_default_audit_unchanged(self, tmp_path):
        # The example skills must still grade A under the default
        # audit — strict mode is opt-in.
        examples = Path(__file__).parent.parent / "examples"
        for name in ("api-design-reviewer", "dependency-scanner", "tdd-workflow"):
            path = examples / name
            if not path.is_dir():
                continue  # Don't fail in environments without examples
            r = subprocess.run(
                [SKILLCTL, "eval", "audit", str(path), "--quiet"],
                capture_output=True,
                text=True,
            )
            assert r.returncode == 0, f"{name}: {r.stderr}"
            assert "PASSED" in r.stdout
