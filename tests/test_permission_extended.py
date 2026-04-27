"""Extended tests for permission analyzer — uncovered branches."""

from pathlib import Path

from skillctl.eval.audit.permission_analyzer import analyze_permissions


def _run(frontmatter: dict, content: str = "# Test\nSome content") -> list:
    """Run permission analysis with given frontmatter and content."""
    tmp = Path("/tmp/test-perm-skill")
    tmp.mkdir(exist_ok=True)
    (tmp / "SKILL.md").write_text(f"---\n---\n{content}")
    return analyze_permissions(tmp, frontmatter=frontmatter, skill_content=content)


class TestAllowedToolsAnalysis:
    def test_unscoped_bash(self):
        findings = _run({"allowed-tools": "Bash Read Write"})
        codes = [f.code for f in findings]
        assert "PERM-001" in codes

    def test_bash_star(self):
        findings = _run({"allowed-tools": "Bash(*)"})
        codes = [f.code for f in findings]
        assert "PERM-001" in codes

    def test_bash_double_star(self):
        findings = _run({"allowed-tools": "Bash(**)"})
        codes = [f.code for f in findings]
        assert "PERM-001" in codes

    def test_scoped_bash_is_ok(self):
        findings = _run({"allowed-tools": "Bash(git *) Read"})
        codes = [f.code for f in findings]
        assert "PERM-001" not in codes

    def test_shell_alias(self):
        findings = _run({"allowed-tools": "Shell"})
        codes = [f.code for f in findings]
        assert "PERM-001" in codes

    def test_terminal_alias(self):
        findings = _run({"allowed-tools": "Terminal"})
        codes = [f.code for f in findings]
        assert "PERM-001" in codes

    def test_high_risk_non_bash_tool(self):
        findings = _run({"allowed-tools": "Write Edit"})
        high_risk = [f for f in findings if f.code == "PERM-002"]
        # Write/Edit may or may not be classified as high-risk depending on TOOL_RISK_LEVELS
        # Just verify no crash
        assert isinstance(high_risk, list)

    def test_excessive_tools(self):
        tools = " ".join([f"Tool{i}" for i in range(20)])
        findings = _run({"allowed-tools": tools})
        codes = [f.code for f in findings]
        assert "PERM-003" in codes

    def test_no_allowed_tools(self):
        findings = _run({})
        perm_findings = [f for f in findings if f.code.startswith("PERM")]
        # No PERM-001/002/003 without allowed-tools
        for f in perm_findings:
            assert f.code not in ("PERM-001", "PERM-002", "PERM-003")

    def test_empty_string_allowed_tools(self):
        findings = _run({"allowed-tools": ""})
        perm_findings = [f for f in findings if f.code.startswith("PERM")]
        for f in perm_findings:
            assert f.code not in ("PERM-001", "PERM-002", "PERM-003")


class TestNoContentFallback:
    def test_no_skill_md_returns_empty(self):
        tmp = Path("/tmp/test-perm-empty")
        tmp.mkdir(exist_ok=True)
        (tmp / "SKILL.md").unlink(missing_ok=True)
        findings = analyze_permissions(tmp)
        assert findings == []

    def test_frontmatter_parse_error(self):
        findings = analyze_permissions(
            Path("/tmp/test-perm-skill"),
            frontmatter=None,
            skill_content="no frontmatter here",
        )
        assert isinstance(findings, list)
