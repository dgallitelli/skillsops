"""Registry configuration — RegistryConfig dataclass.

Centralises all server configuration with sensible defaults.  Values can be
overridden via CLI flags passed to ``skillctl serve``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class RegistryConfig:
    """Configuration for the skill registry server.

    Defaults are conservative for a self-hosted, single-node deployment.
    See :func:`skillctl.registry.server.create_app` for the security
    invariants enforced at startup.
    """

    host: str = "127.0.0.1"
    port: int = 8080
    data_dir: Path = field(default_factory=lambda: Path("~/.skillctl/registry").expanduser())
    storage_backend: str = "filesystem"  # "filesystem" or "github"
    github_repo: str | None = None  # e.g. "https://github.com/org/skill-registry.git"
    github_token: str | None = None  # PAT for push access
    github_branch: str = "main"
    auth_disabled: bool = False
    hmac_key: str | None = None  # Auto-generated if not set AND auto_generate_hmac_key=True
    auto_generate_hmac_key: bool = False
    log_level: str = "info"
    # Hosts to accept in the Host header in addition to host/localhost/127.0.0.1.
    allowed_hosts: tuple[str, ...] = ()
    # CORS allow_origins — empty means no browser cross-origin access.
    cors_allow_origins: tuple[str, ...] = ()
