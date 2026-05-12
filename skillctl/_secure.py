"""Shared security utilities used across the CLI and registry.

Two responsibilities:

1. ``atomic_write_secret`` — create a file with mode 0o600 atomically (no
   TOCTOU window) and write bytes to it.  Used for HMAC keys, the local
   ~/.skillctl/config.yaml, and other files that contain credentials.

2. ``safe_urlopen`` — fetch an http(s) URL while blocking SSRF to private
   networks (RFC1918, link-local, loopback, IMDSv1/IMDSv2 metadata) and
   capping the response size and redirect count.

Keeping these in one module makes the security-relevant code paths easy to
audit and reuse.
"""

from __future__ import annotations

import ipaddress
import os
import secrets
import socket
import threading
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urljoin, urlparse

from skillctl.errors import SkillctlError

DEFAULT_MAX_DOWNLOAD_BYTES = 5 * 1024 * 1024  # 5 MiB
DEFAULT_MAX_REDIRECTS = 3
DEFAULT_TIMEOUT = 30


def atomic_write_secret(path: Path, data: bytes, *, mode: int = 0o600) -> None:
    """Atomically create *path* with *mode* and write *data*.

    Unlike ``Path.write_bytes`` followed by ``chmod``, this never leaves a
    world-readable file on disk — the file is created with the target mode
    in a single ``open(..., O_CREAT|O_EXCL|O_WRONLY, mode)`` call.

    If *path* already exists it is replaced atomically via a sibling temp
    file.  Parent directories are created with mode ``0o700`` (the home
    convention) if they don't exist.
    """
    path = Path(path)
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(parent, 0o700)
    except OSError:
        # Parent may be a system directory we don't own — that's fine.
        pass

    # Suffix uses pid + thread id + 4 random bytes so two threads or two
    # processes targeting the same path don't collide on O_EXCL.  The
    # random component also defends against a stale tmp file from a
    # crashed prior run with the same pid.
    suffix = f"{os.getpid()}.{threading.get_ident()}.{secrets.token_hex(4)}"
    tmp_path = parent / f".{path.name}.tmp.{suffix}"

    fd = os.open(str(tmp_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
    except Exception:
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass
        raise

    os.replace(str(tmp_path), str(path))
    # os.replace preserves the source mode, but be defensive in case the
    # destination already existed with looser perms (the replace would have
    # overwritten that, but on some filesystems behavior varies).
    try:
        os.chmod(str(path), mode)
    except OSError:
        pass


def _is_blocked_address(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True if *ip* is in a network range we refuse to fetch from.

    Also unwraps IPv4-mapped IPv6 (``::ffff:1.2.3.4``) and IPv4-compatible
    IPv6 (``::1.2.3.4``) so an attacker can't bypass IPv4 checks by
    expressing the address in an IPv6 form.
    """
    if isinstance(ip, ipaddress.IPv6Address):
        mapped = ip.ipv4_mapped
        if mapped is not None:
            return _is_blocked_address(mapped)
        # ::1.2.3.4 (IPv4-compatible, deprecated but still parseable).
        if ip.sixtofour is not None:
            return _is_blocked_address(ip.sixtofour)

    if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast:
        return True
    if ip.is_reserved or ip.is_unspecified:
        return True
    # Block IPv4 IMDSv1/IMDSv2 (already covered by is_link_local for 169.254/16,
    # but keep the explicit check in case of future refactors).
    if isinstance(ip, ipaddress.IPv4Address) and str(ip) == "169.254.169.254":
        return True
    # Block well-known cloud metadata IPv6 (Azure, GCE).
    if isinstance(ip, ipaddress.IPv6Address) and str(ip) == "fd00:ec2::254":
        return True
    return False


def _resolve_and_validate_host(host: str) -> None:
    """Resolve *host* and raise SkillctlError if any address is blocked.

    All A/AAAA results must be public — if any is private/loopback/etc, the
    fetch is refused.  This blocks DNS-rebinding to internal endpoints.
    """
    if not host:
        raise SkillctlError(
            code="E_INVALID_URL",
            what="URL has no host",
            why="A hostname is required",
            fix="Use a fully-qualified URL like https://example.com/skill.md",
        )

    # Reject literal IPs that fall in blocked ranges directly, without DNS.
    try:
        literal_ip = ipaddress.ip_address(host)
    except ValueError:
        literal_ip = None
    if literal_ip is not None and _is_blocked_address(literal_ip):
        raise SkillctlError(
            code="E_BLOCKED_HOST",
            what=f"Refusing to fetch from blocked address: {host}",
            why="Loopback, private, link-local and metadata addresses are blocked to prevent SSRF",
            fix="Use a public https:// URL",
        )

    if literal_ip is None:
        try:
            infos = socket.getaddrinfo(host, None)
        except socket.gaierror as e:
            raise SkillctlError(
                code="E_DNS_FAILED",
                what=f"DNS lookup failed for {host}",
                why=str(e),
                fix="Check the URL host and your network connectivity",
            ) from e

        for info in infos:
            sockaddr = info[4]
            ip_str = sockaddr[0]
            try:
                ip = ipaddress.ip_address(ip_str)
            except ValueError:
                continue
            if _is_blocked_address(ip):
                raise SkillctlError(
                    code="E_BLOCKED_HOST",
                    what=f"Refusing to fetch from {host}: resolves to blocked address {ip}",
                    why="Loopback, private, link-local and metadata addresses are blocked to prevent SSRF",
                    fix="Use a public https:// URL",
                )


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Handler that disables HTTP redirect following.

    We re-validate every hop ourselves so an attacker can't redirect a
    public URL to ``http://169.254.169.254/...``.  Raising ``HTTPError``
    here (rather than returning ``None``) makes urllib propagate the 3XX
    response as an exception so :func:`safe_urlopen` can re-validate the
    target host before fetching it.
    """

    def http_error_301(self, req, fp, code, msg, headers):  # type: ignore[override]
        raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)

    http_error_302 = http_error_301
    http_error_303 = http_error_301
    http_error_307 = http_error_301
    http_error_308 = http_error_301


def safe_urlopen(
    url: str,
    *,
    max_bytes: int = DEFAULT_MAX_DOWNLOAD_BYTES,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    timeout: int = DEFAULT_TIMEOUT,
    allowed_schemes: tuple[str, ...] = ("https", "http"),
) -> bytes:
    """Fetch *url* with SSRF protection, size cap, and bounded redirects.

    - Scheme must be in *allowed_schemes* (default https/http).
    - Host is resolved and rejected if any A/AAAA address is in a blocked
      range (loopback, private, link-local, multicast, reserved, IMDS).
    - Redirects are followed manually up to *max_redirects* hops; each hop
      is re-validated.
    - Response is read with a hard cap of *max_bytes* + 1 to detect oversize.
    """
    visited: list[str] = []
    current = url

    for _hop in range(max_redirects + 1):
        parsed = urlparse(current)
        if parsed.scheme not in allowed_schemes:
            raise SkillctlError(
                code="E_INVALID_URL",
                what=f"Unsupported URL scheme: {parsed.scheme}",
                why=f"Only {', '.join(allowed_schemes)} URLs are supported for security",
                fix="Use an https:// URL",
            )
        host = parsed.hostname or ""
        _resolve_and_validate_host(host)
        visited.append(current)

        opener = urllib.request.build_opener(_NoRedirectHandler())
        req = urllib.request.Request(current, method="GET")
        try:
            resp = opener.open(req, timeout=timeout)
        except urllib.error.HTTPError as e:
            if e.code in (301, 302, 303, 307, 308):
                location = e.headers.get("Location")
                if not location:
                    raise SkillctlError(
                        code="E_REDIRECT_INVALID",
                        what="Redirect response missing Location header",
                        why=f"HTTP {e.code} from {current}",
                        fix="Check the URL or contact the server operator",
                    ) from e
                current = urljoin(current, location)
                continue
            raise SkillctlError(
                code="E_HTTP_ERROR",
                what=f"HTTP {e.code} fetching {current}",
                why=str(e),
                fix="Check the URL and try again",
            ) from e
        except urllib.error.URLError as e:
            raise SkillctlError(
                code="E_HTTP_ERROR",
                what=f"Failed to fetch {current}",
                why=str(e),
                fix="Check the URL and your network connectivity",
            ) from e

        with resp:
            data = resp.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise SkillctlError(
                    code="E_TOO_LARGE",
                    what=f"Response from {current} exceeds {max_bytes // 1024} KiB",
                    why="Oversized responses are rejected to prevent DoS",
                    fix="Host the file at a different URL or split it up",
                )
            return data

    raise SkillctlError(
        code="E_TOO_MANY_REDIRECTS",
        what=f"Exceeded {max_redirects} redirects",
        why=f"Redirect chain: {' -> '.join(visited)}",
        fix="Use a URL that resolves directly without bouncing through redirects",
    )
