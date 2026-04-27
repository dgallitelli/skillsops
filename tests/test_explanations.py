"""Tests for educational explanations for audit finding codes."""

from skillctl.eval.explanations import get_explanation


class TestGetExplanation:
    def test_exact_code(self):
        result = get_explanation("SEC-001")
        assert result is not None
        assert "secret" in result.lower() or "key" in result.lower()

    def test_all_sec_codes(self):
        for code in ("SEC-001", "SEC-002", "SEC-003", "SEC-004", "SEC-005", "SEC-006", "SEC-007", "SEC-008", "SEC-009"):
            assert get_explanation(code) is not None

    def test_prefix_fallback_str(self):
        result = get_explanation("STR-999")
        assert result is not None
        assert "structure" in result.lower() or "frontmatter" in result.lower()

    def test_prefix_fallback_perm(self):
        result = get_explanation("PERM-999")
        assert result is not None
        assert "permission" in result.lower() or "privilege" in result.lower()

    def test_unknown_code(self):
        result = get_explanation("UNKNOWN-001")
        assert result is None

    def test_no_dash_in_code(self):
        result = get_explanation("NOPE")
        assert result is None
