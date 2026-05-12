"""Audit logger — append-only JSONL with HMAC-SHA256 signatures.

Records every mutating operation (publish, delete, token create/revoke) as a
signed JSONL entry.  Each entry's HMAC includes the previous entry's
signature, forming a hash chain — single-line tampering, deletion, and
reordering are all detectable.

Supports filtered reads and full-log integrity verification.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import hmac
import json
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

# Sentinel for the "previous signature" of the very first log entry.
_GENESIS_PREV = "GENESIS"


@contextlib.contextmanager
def _flock_excl(f):
    """Hold an exclusive ``fcntl.flock`` on *f* for the duration of the block."""
    fcntl.flock(f.fileno(), fcntl.LOCK_EX)
    try:
        yield
    finally:
        fcntl.flock(f.fileno(), fcntl.LOCK_UN)


@dataclass
class AuditEvent:
    """A single audit log entry."""

    timestamp: str  # ISO 8601
    action: str  # "skill.published", "skill.deleted", "token.created", etc.
    actor: str  # token name or "anonymous"
    resource: str  # "my-org/code-reviewer@1.0.0"
    details: dict  # action-specific metadata
    prev_signature: str  # HMAC of the previous entry (or "GENESIS")
    hmac_signature: str  # HMAC-SHA256 of the event payload incl. prev_signature


class AuditLogger:
    """Append-only JSONL audit log with HMAC-SHA256 hash-chained signatures.

    The hash chain prevents an attacker who has only write access to the log
    file (but not the HMAC key) from deleting or reordering entries —
    ``verify_integrity()`` will detect breaks in the chain.

    The logger is process-safe via an in-process lock; it is NOT cross-
    process safe.  Multi-worker deployments should send audit events through
    a single writer or use external append-only storage.
    """

    def __init__(self, log_path: Path, hmac_key: bytes) -> None:
        self.log_path = log_path
        self.hmac_key = hmac_key
        self._lock = threading.Lock()

    @staticmethod
    def _sign(key: bytes, payload: dict) -> str:
        payload_bytes = json.dumps(payload, sort_keys=True).encode()
        return hmac.new(key, payload_bytes, hashlib.sha256).hexdigest()

    def _last_signature(self) -> str:
        """Return the hmac_signature of the last entry, or GENESIS sentinel."""
        if not self.log_path.exists():
            return _GENESIS_PREV
        # Walk to the last non-empty line.  For typical audit log sizes this
        # is fast enough; for very large logs an index file would help.
        last_sig = _GENESIS_PREV
        with open(self.log_path) as f:
            for line in f:
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    entry = json.loads(stripped)
                except (json.JSONDecodeError, ValueError):
                    continue
                sig = entry.get("hmac_signature")
                if isinstance(sig, str) and sig:
                    last_sig = sig
        return last_sig

    def log(
        self,
        action: str,
        actor: str,
        resource: str,
        details: dict | None = None,
    ) -> None:
        """Append a signed event to the audit log.

        Cross-process safety: while the in-process ``threading.Lock``
        serialises threads, an ``fcntl.flock(LOCK_EX)`` on the open file
        also serialises across processes (e.g. multi-worker uvicorn).  The
        flock is acquired AFTER the file exists so worker startup can't
        race ahead of the lock.
        """
        with self._lock:
            # Ensure the log file exists with 0o600 perms before appending.
            if not self.log_path.exists():
                self.log_path.parent.mkdir(parents=True, exist_ok=True)
                fd = os.open(str(self.log_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                os.close(fd)

            with open(self.log_path, "a") as f:
                # Hold the flock for the read-prev + sign + write sequence
                # so two processes can't both observe the same prev_sig.
                with _flock_excl(f):
                    prev_sig = self._last_signature()
                    payload = {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "action": action,
                        "actor": actor,
                        "resource": resource,
                        "details": details or {},
                        "prev_signature": prev_sig,
                    }
                    signature = self._sign(self.hmac_key, payload)
                    event = {**payload, "hmac_signature": signature}
                    f.write(json.dumps(event) + "\n")
                    f.flush()
                    os.fsync(f.fileno())

    def read(
        self,
        since: str | None = None,
        until: str | None = None,
        action: str | None = None,
        limit: int = 100,
    ) -> list[AuditEvent]:
        """Read audit events, optionally filtered by time range and action."""
        if not self.log_path.exists():
            return []

        events: list[AuditEvent] = []
        with open(self.log_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue
                ts = entry.get("timestamp", "")

                if since is not None and ts < since:
                    continue
                if until is not None and ts > until:
                    continue
                if action is not None and entry.get("action") != action:
                    continue

                events.append(
                    AuditEvent(
                        timestamp=entry["timestamp"],
                        action=entry["action"],
                        actor=entry["actor"],
                        resource=entry["resource"],
                        details=entry.get("details", {}),
                        prev_signature=entry.get("prev_signature", _GENESIS_PREV),
                        hmac_signature=entry["hmac_signature"],
                    )
                )
                if len(events) >= limit:
                    break

        return events

    def verify_integrity(self) -> tuple[int, int, int]:
        """Verify HMAC signatures and the hash chain.

        Returns ``(valid_count, invalid_count, parse_error_count)``.  An
        entry counts as invalid if either its HMAC fails or its
        ``prev_signature`` does not match the previous entry's HMAC.
        """
        if not self.log_path.exists():
            return (0, 0, 0)

        valid = 0
        invalid = 0
        parse_errors = 0
        expected_prev = _GENESIS_PREV

        with open(self.log_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    parse_errors += 1
                    continue
                payload = {
                    "timestamp": entry.get("timestamp", ""),
                    "action": entry.get("action", ""),
                    "actor": entry.get("actor", ""),
                    "resource": entry.get("resource", ""),
                    "details": entry.get("details", {}),
                    "prev_signature": entry.get("prev_signature", _GENESIS_PREV),
                }
                expected = self._sign(self.hmac_key, payload)
                got = entry.get("hmac_signature", "")
                chain_ok = entry.get("prev_signature", _GENESIS_PREV) == expected_prev
                if hmac.compare_digest(expected, got) and chain_ok:
                    valid += 1
                    expected_prev = got
                else:
                    invalid += 1
                    # Don't advance expected_prev — a single corruption
                    # invalidates everything after it, which is the desired
                    # behaviour of a hash chain.

        return (valid, invalid, parse_errors)
