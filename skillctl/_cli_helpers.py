"""Private helpers for ``skillctl.cli``.

This module exists to keep ``skillctl/cli.py`` focused on parser /
dispatch / handlers without also being the home of registry-HTTP
boilerplate, config IO, and breadcrumb logic.

The leading underscore signals "private — do not import from outside
the skillctl package."  Tests that need to monkeypatch helpers should
do so via ``skillctl.cli`` (the helpers are re-exported there for
test stability).

**Important caveat for monkeypatching**: helper-to-helper calls *inside
this module* (for example ``_require_registry_url`` calling
``_get_registry_url``) resolve against this module's own globals, NOT
against ``skillctl.cli``.  So a test that does
``monkeypatch.setattr("skillctl.cli._get_registry_url", ...)`` will only
intercept callers that go through ``skillctl.cli`` — not callers nested
inside ``_cli_helpers.py``.  Today only ``cmd_apply`` reads
``_get_registry_url`` directly, so this is fine; if that ever changes,
patch ``skillctl._cli_helpers._get_registry_url`` instead (or both).
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

import yaml

from skillctl.config import (
    CONFIG_PATH,
    load_config as _load_skillctl_config,
)
from skillctl.errors import SkillctlError


# ---------------------------------------------------------------------------
# Config helpers — thin wrappers over skillctl.config
# ---------------------------------------------------------------------------


def _load_config() -> dict:
    """Load raw CLI config as a dict (backward compat for config set/get)."""
    if CONFIG_PATH.exists():
        return yaml.safe_load(CONFIG_PATH.read_text()) or {}
    return {}


def _save_config(config: dict):
    """Save raw CLI config dict (backward compat for config set/get)."""
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(yaml.dump(config, default_flow_style=False))
    CONFIG_PATH.chmod(0o600)


# ---------------------------------------------------------------------------
# Registry URL / token resolution
# ---------------------------------------------------------------------------


def _get_registry_url(args) -> str | None:
    """Resolve registry URL from args > env > typed config."""
    url = getattr(args, "registry_url", None)
    if url:
        return url.rstrip("/")
    url = os.environ.get("SKILLCTL_REGISTRY_URL")
    if url:
        return url.rstrip("/")
    cfg = _load_skillctl_config()
    url = cfg.registry.local.url
    if url:
        return url.rstrip("/")
    return None


def _require_registry_url(args) -> str:
    """Resolve registry URL, raise SkillctlError if not configured."""
    url = _get_registry_url(args)
    if url:
        return url
    raise SkillctlError(
        code="E_NO_REGISTRY",
        what="No registry URL configured",
        why="This command requires a registry URL to communicate with the remote registry",
        fix="Run 'skillctl configure' or 'skillctl config set registry.url <url>'",
    )


def _get_registry_token(args) -> str | None:
    """Resolve registry token from args > env > typed config."""
    token = getattr(args, "token", None)
    if token:
        return token
    token = os.environ.get("SKILLCTL_REGISTRY_TOKEN")
    if token:
        return token
    cfg = _load_skillctl_config()
    return cfg.registry.local.token


def _load_github_token() -> str | None:
    """Load GitHub token from env > config."""
    from skillctl.github_auth import load_github_token

    return load_github_token()


# ---------------------------------------------------------------------------
# Output / TTY discipline
# ---------------------------------------------------------------------------


def _output_is_machine(args) -> bool:
    """True when output is being piped or the caller asked for machine output.

    Suppress human breadcrumbs in those cases so they don't pollute JSON
    pipelines or CI logs.
    """
    if getattr(args, "json", False):
        return True
    if getattr(args, "quiet", False):
        return True
    return not sys.stdout.isatty()


def _emit_plugin_hint():
    """Emit a Claude Code plugin hint on stderr when running inside Claude Code."""
    if os.environ.get("CLAUDECODE"):
        print(
            '<claude-code-hint v="1" type="plugin" value="skillctl@claude-plugins-official" />',
            file=sys.stderr,
        )


# ---------------------------------------------------------------------------
# Registry HTTP helper — collapses six near-duplicate try/except blocks
# ---------------------------------------------------------------------------


def _registry_request(
    method: str,
    url: str,
    *,
    token: str | None = None,
    body: bytes | None = None,
    content_type: str | None = None,
    timeout: int = 30,
) -> bytes:
    """Issue an HTTP request to the registry and return the response body.

    On non-2xx responses or transport failures, raises ``SkillctlError``
    with a code the dispatch layer's ``except SkillctlError`` handler
    formats and prints.  The bytes returned are the raw response body —
    the caller decodes / parses them as JSON if appropriate.

    Codes raised:

    - ``E_REGISTRY_HTTP``        — non-2xx response (response body included).
    - ``E_REGISTRY_UNREACHABLE`` — TCP/DNS/timeout failure.
    """
    req = urllib.request.Request(url, data=body, method=method)
    if content_type:
        req.add_header("Content-Type", content_type)
    if token:
        req.add_header("Authorization", f"Bearer {token}")

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except urllib.error.HTTPError as e:
        body_text = ""
        try:
            body_text = e.read().decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            pass
        # If the registry returned a structured error envelope, surface
        # its `what` field — the audit/api layer emits these with
        # SkillctlError-shaped JSON.
        what = f"Registry request failed (HTTP {e.code})"
        if body_text:
            try:
                envelope = json.loads(body_text)
            except (json.JSONDecodeError, ValueError):
                envelope = None
            if isinstance(envelope, dict):
                detail = envelope.get("detail")
                if isinstance(detail, dict) and detail.get("what"):
                    what = f"{what}: {detail['what']}"
                elif envelope.get("what"):
                    what = f"{what}: {envelope['what']}"
        raise SkillctlError(
            code="E_REGISTRY_HTTP",
            what=what,
            why=body_text or e.reason or f"HTTP {e.code}",
            fix="Check registry URL and auth with 'skillctl doctor'",
        ) from e
    except urllib.error.URLError as e:
        raise SkillctlError(
            code="E_REGISTRY_UNREACHABLE",
            what=f"Could not connect to {url}",
            why=str(e.reason),
            fix="Check registry URL with 'skillctl doctor'",
        ) from e
