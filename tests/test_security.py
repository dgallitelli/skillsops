"""Regression tests for the security fixes in v0.1.0b4.

Each test is named after the finding it exercises (C1, C2, ... H6, M3, ...)
so future drift is easy to track against SECURITY.md.
"""

from __future__ import annotations

import os
import stat

import pytest

from skillctl._secure import (
    DEFAULT_MAX_DOWNLOAD_BYTES,
    _resolve_and_validate_host,
    atomic_write_secret,
    safe_urlopen,
)
from skillctl.errors import SkillctlError
from skillctl.registry.audit import AuditLogger
from skillctl.registry.auth import AuthManager, PERMISSION_PATTERN, _anonymous_token
from skillctl.registry.config import RegistryConfig
from skillctl.registry.db import MetadataDB
from skillctl.registry.github_backend import _validate_name_version
from skillctl.registry.server import _validate_security_invariants


# ---------------------------------------------------------------------------
# C1 — SSRF protection in install --from-url
# ---------------------------------------------------------------------------


class TestC1_SSRF:
    @pytest.mark.parametrize(
        "host",
        [
            "127.0.0.1",
            "localhost",
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
            "169.254.169.254",  # AWS IMDS
            "::1",
            "fe80::1",
            "fd00:ec2::254",
            "::ffff:127.0.0.1",  # IPv4-mapped IPv6 (loopback)
            "::ffff:169.254.169.254",  # IPv4-mapped IPv6 (IMDS)
            "::ffff:10.0.0.1",  # IPv4-mapped IPv6 (private)
        ],
    )
    def test_blocked_hosts_refused(self, host):
        with pytest.raises(SkillctlError) as exc_info:
            _resolve_and_validate_host(host)
        assert exc_info.value.code == "E_BLOCKED_HOST"

    def test_public_host_passes(self):
        # Just a public DNS name; we don't actually fetch.
        _resolve_and_validate_host("example.com")

    def test_safe_urlopen_rejects_private_literal(self):
        with pytest.raises(SkillctlError) as exc_info:
            safe_urlopen("http://10.0.0.1/x")
        assert exc_info.value.code == "E_BLOCKED_HOST"

    def test_safe_urlopen_rejects_imds(self):
        with pytest.raises(SkillctlError) as exc_info:
            safe_urlopen("http://169.254.169.254/latest/meta-data/")
        assert exc_info.value.code == "E_BLOCKED_HOST"

    def test_safe_urlopen_rejects_file_scheme(self):
        with pytest.raises(SkillctlError) as exc_info:
            safe_urlopen("file:///etc/passwd")
        assert exc_info.value.code == "E_INVALID_URL"

    def test_safe_urlopen_default_max_bytes_is_modest(self):
        # Should be small enough that an attacker can't OOM the CLI.
        assert DEFAULT_MAX_DOWNLOAD_BYTES <= 16 * 1024 * 1024


# ---------------------------------------------------------------------------
# C2 — Audit log hash chain
# ---------------------------------------------------------------------------


class TestC2_AuditChain:
    def test_chain_links_entries(self, tmp_path):
        logger = AuditLogger(tmp_path / "audit.jsonl", b"key")
        logger.log("a", "x", "r1")
        logger.log("b", "x", "r2")
        logger.log("c", "x", "r3")

        events = logger.read()
        assert events[0].prev_signature == "GENESIS"
        assert events[1].prev_signature == events[0].hmac_signature
        assert events[2].prev_signature == events[1].hmac_signature

    def test_deletion_detected(self, tmp_path):
        logger = AuditLogger(tmp_path / "audit.jsonl", b"key")
        logger.log("a", "x", "r1")
        logger.log("b", "x", "r2")
        logger.log("c", "x", "r3")

        # Delete the middle entry — chain should break for entry 3.
        lines = logger.log_path.read_text().splitlines()
        del lines[1]
        logger.log_path.write_text("\n".join(lines) + "\n")

        valid, invalid, _ = logger.verify_integrity()
        assert invalid >= 1

    def test_audit_log_file_is_0600(self, tmp_path):
        logger = AuditLogger(tmp_path / "audit.jsonl", b"key")
        logger.log("a", "x", "r1")
        mode = stat.S_IMODE(os.stat(logger.log_path).st_mode)
        assert mode == 0o600


# ---------------------------------------------------------------------------
# C4 — auth_disabled refuses non-loopback bind
# ---------------------------------------------------------------------------


class TestC4_AuthDisabledLocalhost:
    def test_auth_disabled_on_public_host_refused(self):
        cfg = RegistryConfig(host="0.0.0.0", auth_disabled=True)
        with pytest.raises(RuntimeError, match="auth_disabled"):
            _validate_security_invariants(cfg)

    @pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1"])
    def test_auth_disabled_on_localhost_ok(self, host):
        cfg = RegistryConfig(host=host, auth_disabled=True)
        _validate_security_invariants(cfg)  # does not raise

    def test_auth_enabled_any_host_ok(self):
        cfg = RegistryConfig(host="0.0.0.0", auth_disabled=False)
        _validate_security_invariants(cfg)


# ---------------------------------------------------------------------------
# H3 — atomic credential file writes
# ---------------------------------------------------------------------------


class TestH3_AtomicSecret:
    def test_new_file_is_0600(self, tmp_path):
        target = tmp_path / "secret.key"
        atomic_write_secret(target, b"secret-data")
        mode = stat.S_IMODE(os.stat(target).st_mode)
        assert mode == 0o600
        assert target.read_bytes() == b"secret-data"

    def test_overwrite_preserves_0600(self, tmp_path):
        target = tmp_path / "secret.key"
        target.write_bytes(b"old")
        target.chmod(0o644)
        atomic_write_secret(target, b"new")
        mode = stat.S_IMODE(os.stat(target).st_mode)
        assert mode == 0o600
        assert target.read_bytes() == b"new"


# ---------------------------------------------------------------------------
# H4 — read permission scoping
# ---------------------------------------------------------------------------


class TestH4_ReadScoping:
    def _mgr(self, tmp_path) -> AuthManager:
        db = MetadataDB(tmp_path / "test.db")
        db.initialize()
        return AuthManager(db)

    def test_write_scope_grants_read_in_namespace(self, tmp_path):
        mgr = self._mgr(tmp_path)
        from skillctl.registry.auth import TokenInfo

        token = TokenInfo("id", "n", ["write:foo"], "now", None)
        assert mgr.check_permission(token, "read", "foo")

    def test_write_scope_no_read_in_other_namespace(self, tmp_path):
        mgr = self._mgr(tmp_path)
        from skillctl.registry.auth import TokenInfo

        token = TokenInfo("id", "n", ["write:foo"], "now", None)
        # Previously this returned True (any perm = read access).
        assert not mgr.check_permission(token, "read", "bar")

    def test_unscoped_read_grants_all(self, tmp_path):
        mgr = self._mgr(tmp_path)
        from skillctl.registry.auth import TokenInfo

        token = TokenInfo("id", "n", ["read"], "now", None)
        assert mgr.check_permission(token, "read", "foo")
        assert mgr.check_permission(token, "read", "bar")

    def test_read_namespace_scope_works(self, tmp_path):
        mgr = self._mgr(tmp_path)
        from skillctl.registry.auth import TokenInfo

        token = TokenInfo("id", "n", ["read:foo"], "now", None)
        assert mgr.check_permission(token, "read", "foo")
        assert not mgr.check_permission(token, "read", "bar")


# ---------------------------------------------------------------------------
# H5 — permission string validation at create_token
# ---------------------------------------------------------------------------


class TestH5_PermissionValidation:
    @pytest.mark.parametrize(
        "perm",
        [
            "admin",
            "read",
            "read:org-name",
            "write:org-name",
            "write:abc-123",
        ],
    )
    def test_pattern_accepts_legal(self, perm):
        assert PERMISSION_PATTERN.match(perm)

    @pytest.mark.parametrize(
        "perm",
        [
            "Admin",
            "write:../etc",
            "write: foo",
            "write:org name",
            "delete:foo",
            "*",
            "",
            "read:",
            "write:UPPER",
        ],
    )
    def test_pattern_rejects_illegal(self, perm):
        assert not PERMISSION_PATTERN.match(perm)

    def test_create_token_rejects_invalid_permission(self, tmp_path):
        db = MetadataDB(tmp_path / "test.db")
        db.initialize()
        mgr = AuthManager(db)
        with pytest.raises(ValueError, match="Invalid permission"):
            mgr.create_token("ci", ["write:../etc"])


# ---------------------------------------------------------------------------
# H6 — name/version re-validation in github_backend
# ---------------------------------------------------------------------------


class TestH6_NameVersionValidation:
    def test_traversal_in_name_rejected(self):
        with pytest.raises(SkillctlError) as exc_info:
            _validate_name_version("../etc/passwd", "1.0.0")
        assert exc_info.value.code == "E_INVALID_NAME"

    def test_uppercase_in_name_rejected(self):
        with pytest.raises(SkillctlError):
            _validate_name_version("Org/Name", "1.0.0")

    def test_bare_name_rejected(self):
        with pytest.raises(SkillctlError):
            _validate_name_version("just-a-name", "1.0.0")

    def test_invalid_version_rejected(self):
        with pytest.raises(SkillctlError) as exc_info:
            _validate_name_version("org/name", "; rm -rf /")
        assert exc_info.value.code == "E_INVALID_VERSION"

    def test_legal_name_version_passes(self):
        _validate_name_version("my-org/my-skill", "1.2.3")
        _validate_name_version("my-org/my-skill", "1.2.3-rc.1")


# ---------------------------------------------------------------------------
# Anonymous token returned by auth_disabled
# ---------------------------------------------------------------------------


class TestAnonymousToken:
    def test_anonymous_token_has_admin(self):
        token = _anonymous_token()
        assert "admin" in token.permissions
        assert token.name == "anonymous"


# ---------------------------------------------------------------------------
# config.yaml is written 0600 atomically
# ---------------------------------------------------------------------------


class TestConfigFilePermissions:
    def test_save_config_is_0600(self, tmp_path, monkeypatch):
        # Redirect CONFIG_PATH to tmp_path.
        from skillctl import config as cfg_mod

        target = tmp_path / "config.yaml"
        monkeypatch.setattr(cfg_mod, "CONFIG_DIR", tmp_path)
        monkeypatch.setattr(cfg_mod, "CONFIG_PATH", target)

        cfg = cfg_mod.SkillctlConfig()
        cfg.registry.local.token = "secret"
        cfg_mod.save_config(cfg)

        assert target.exists()
        mode = stat.S_IMODE(os.stat(target).st_mode)
        assert mode == 0o600


# ---------------------------------------------------------------------------
# safe_urlopen used by download_skill
# ---------------------------------------------------------------------------


class TestDownloadSkillSSRF:
    def test_download_skill_blocks_imds(self, tmp_path):
        from skillctl.install import download_skill

        with pytest.raises(SkillctlError) as exc_info:
            download_skill("http://169.254.169.254/latest/meta-data/", tmp_path / "out")
        # Could be E_BLOCKED_HOST or E_INVALID_URL depending on path; both
        # block the fetch, which is what matters.
        assert exc_info.value.code in {"E_BLOCKED_HOST", "E_INVALID_URL"}

    def test_download_skill_rejects_non_utf8(self, tmp_path):
        from unittest.mock import patch

        from skillctl.install import download_skill

        # Latin-1 bytes that aren't valid UTF-8.
        bad_bytes = "café".encode("latin-1")
        with patch("skillctl._secure.safe_urlopen", return_value=bad_bytes):
            with pytest.raises(SkillctlError) as exc_info:
                download_skill("https://example.com/skill.md", tmp_path / "out")
        assert exc_info.value.code == "E_INVALID_ENCODING"


# ---------------------------------------------------------------------------
# safe_urlopen redirect handling — regression for #6 (NoRedirectHandler must
# raise so safe_urlopen can re-validate the next hop).
# ---------------------------------------------------------------------------


class TestRedirectHandler:
    def test_no_redirect_handler_raises_on_3xx(self):
        from unittest.mock import MagicMock

        from skillctl._secure import _NoRedirectHandler
        from urllib.error import HTTPError

        handler = _NoRedirectHandler()
        req = MagicMock()
        req.full_url = "https://example.com/old"
        with pytest.raises(HTTPError):
            handler.http_error_301(req, MagicMock(), 301, "Moved", {"Location": "x"})


# ---------------------------------------------------------------------------
# H4 follow-up: list_skills now requires explicit namespace for scoped
# tokens.
# ---------------------------------------------------------------------------


class TestH4_ListNamespaceFiltering:
    def _mgr(self, tmp_path):
        db = MetadataDB(tmp_path / "test.db")
        db.initialize()
        return AuthManager(db)

    def test_allowed_namespaces_admin(self, tmp_path):
        from skillctl.registry.auth import TokenInfo

        token = TokenInfo("id", "n", ["admin"], "now", None)
        assert AuthManager.allowed_namespaces(token) is None

    def test_allowed_namespaces_unscoped_read(self, tmp_path):
        from skillctl.registry.auth import TokenInfo

        token = TokenInfo("id", "n", ["read"], "now", None)
        assert AuthManager.allowed_namespaces(token) is None

    def test_allowed_namespaces_scoped(self, tmp_path):
        from skillctl.registry.auth import TokenInfo

        token = TokenInfo("id", "n", ["read:foo", "write:bar"], "now", None)
        assert AuthManager.allowed_namespaces(token) == {"foo", "bar"}

    def test_allowed_namespaces_empty(self, tmp_path):
        from skillctl.registry.auth import TokenInfo

        token = TokenInfo("id", "n", [], "now", None)
        assert AuthManager.allowed_namespaces(token) == set()

    def test_check_permission_read_namespace_none_with_scoped_token(self, tmp_path):
        # Previously: any read:* / write:* could pass.  Now scoped tokens
        # must pass an explicit namespace.
        mgr = self._mgr(tmp_path)
        from skillctl.registry.auth import TokenInfo

        token = TokenInfo("id", "n", ["read:foo"], "now", None)
        assert not mgr.check_permission(token, "read", None)
        assert mgr.check_permission(token, "read", "foo")
