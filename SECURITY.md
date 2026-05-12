# Security policy

This document describes the threat model SkillsOps is designed against, the
security controls in place, and how to report vulnerabilities.

## Reporting a vulnerability

Please **do not file public GitHub issues for security problems**.

Instead, open a private security advisory:
<https://github.com/dgallitelli/skillsops/security/advisories/new>

We will acknowledge within 5 business days and target a fix or mitigation
in the next patch release.  Please include:

- a clear description of the vulnerability,
- the affected version (`skillctl version`),
- a minimal reproduction (PoC), and
- the impact you believe it has.

If you would prefer email, write to the maintainer's GitHub-listed contact
address.

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |
| < 0.1   | No        |

## Threat model

SkillsOps assumes the following deployment shape:

- The CLI runs on developer or CI workstations and reads/writes files in
  `~/.skillctl/` and IDE skill folders.  Trust boundary: **the local user**.
- The registry server is a self-hosted FastAPI service intended to run
  behind a TLS-terminating reverse proxy on a private network or
  authenticated VPC.  Trust boundary: **operators of the registry**.
- Skill content is **untrusted by default** — skills come from many
  authors and are subject to `eval audit` before publication.

The following are **out of scope**:

- Multi-tenant SaaS hosting of the registry.  The token model is namespace-
  scoped but does not provide hard isolation between tenants on the same
  process.
- Side-channel attacks against the audit log (timing, disk forensics).
- Adversaries with root on the registry host (they can replace HMAC keys).
- DNS rebinding *during a single HTTP request* (TOCTOU between
  `getaddrinfo` for validation and the kernel's resolution at TCP-connect
  time).  Deploy behind an egress proxy or pin resolved IPs at the socket
  layer if this matters.  All redirect *hops* are individually
  re-validated, so cross-hop rebinding is closed.

## Controls

### CLI

- `install --from-url` resolves and validates every host hop, blocking
  loopback, private (RFC1918), link-local (169.254/16, fe80::/10), reserved,
  and well-known cloud-metadata addresses.  Redirects are followed manually
  with a hard cap and re-validation each hop.
- Downloads are size-capped (5 MiB by default).
- Tar/zip archive extraction validates every member path; absolute and
  `..` paths are rejected.
- Credential files (`~/.skillctl/config.yaml`, GitHub PATs, registry HMAC
  keys) are written atomically with mode `0o600` — there is no window in
  which they are world-readable.
- The `configure` wizard reads the auth token via `getpass.getpass`; the
  value never echoes to the terminal or shell history.

### Registry

- Tokens are stored as SHA-256 hashes; raw tokens are returned only at
  creation time.
- Permission strings are validated against a strict regex
  (`admin | read | read:<ns> | write:<ns>`); arbitrary scopes cannot be
  stored.
- `read` is namespace-scoped: a `read:foo` or `write:foo` token cannot
  read other namespaces.
- `auth_disabled` mode is **only** allowed in combination with a loopback
  bind (`127.0.0.1`, `localhost`, `::1`) — the server refuses to start
  otherwise.
- The HMAC key for the audit log is read from `--hmac-key`,
  `SKILLCTL_HMAC_KEY`, or auto-generated only when
  `--auto-generate-hmac-key` is passed.  Otherwise the server refuses to
  start so operators wire up real key management.
- The audit log is hash-chained: each entry's HMAC includes the previous
  entry's signature, so deletion or reordering is detectable by
  `verify_integrity()`.  The log file is created with mode `0o600`.  The
  read-prev / sign / write-event sequence holds an `fcntl.flock` on the
  log file, so the chain stays consistent even with multi-worker uvicorn.
- `TrustedHostMiddleware` and `CORSMiddleware` are installed by default.
  CORS allow_origins is empty (no browser cross-origin access) unless
  explicitly configured.
- Rate limiting via `slowapi` is installed when available (default 60
  req/min/IP).
- The GitHub backend uses `GIT_ASKPASS` with a one-shot helper to supply
  the PAT; the token is never embedded in argv or error output.

### Audit scanner (`eval audit`)

The audit scanner is a **static-pattern audit**.  An A grade means "no
obvious issues against ~50 detectors", not "safe to run untrusted".

Operators publishing third-party skills should defense-in-depth with an
LLM-as-a-judge eval, AST-level review, and runtime sandboxing.

## Hardening checklist for production

1. Run the registry behind HTTPS termination (nginx, Caddy, ALB).
2. Set `SKILLCTL_HMAC_KEY` from a secrets manager — never auto-generate.
3. Use `--allowed-host` to explicitly list the public hostname.
4. Use `--cors-origin` only for the specific browser UI you trust.
5. Issue tokens with the narrowest possible scopes (`read:org-name`,
   `write:org-name` — never bare `admin` for day-to-day operations).
6. Rotate tokens regularly; revoke promptly.
7. Periodically run `audit.verify_integrity()` and alert on `invalid > 0`.
8. Back up `audit.jsonl` and the SQLite index to immutable storage.
