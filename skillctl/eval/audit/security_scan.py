"""Security scanning for Agent Skills.

Checks:
- Secret detection (API keys, tokens, passwords, connection strings)
- External URL/endpoint inventory (data exfiltration risk surface)
- Subprocess/shell command analysis in scripts
- Unsafe dependency installation patterns (supply chain risk)
- Prompt injection surface analysis
- Unsafe deserialization (pickle, yaml.load, marshal, shelve)
- Dynamic import/code generation (importlib, __import__, compile, types)
- Base64 encoded payload detection
- MCP server reference detection
"""

from __future__ import annotations

import ast
import re
import unicodedata
from pathlib import Path

from skillctl.eval.schemas import Category, Finding, Severity

# Default file-size cap for scanning.  Files larger than this are
# skipped with a STR-022 INFO finding so operators can see the audit
# is incomplete rather than silently truncating coverage.
DEFAULT_MAX_FILE_BYTES = 1_000_000  # 1 MB

# Strict mode raises the cap so larger scripts/data files can be
# audited at the cost of slower scans.  Still finite — we don't want
# to OOM on a hostile skill that ships a multi-gigabyte file.
STRICT_MAX_FILE_BYTES = 10_000_000  # 10 MB


# --- Secret detection patterns ---
# Based on common patterns from detect-secrets, truffleHog, gitleaks
# We focus on patterns likely to appear in skill files

SECRET_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    # API Keys (generic)
    (
        "Generic API Key assignment",
        re.compile(r"""(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['"]([a-zA-Z0-9_\-]{20,})['"]""", re.IGNORECASE),
        "Potential API key found in assignment",
    ),
    # AWS
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}"), "AWS Access Key ID detected"),
    (
        "AWS Secret Key",
        re.compile(
            r"""(?:aws[_-]?secret[_-]?(?:access[_-]?)?key|secret[_-]?key)\s*[:=]\s*['"]([a-zA-Z0-9/+]{40})['"]""",
            re.IGNORECASE,
        ),
        "Potential AWS Secret Access Key",
    ),
    # GitHub
    ("GitHub Token (classic)", re.compile(r"ghp_[a-zA-Z0-9]{36}"), "GitHub Personal Access Token detected"),
    ("GitHub Token (fine-grained)", re.compile(r"github_pat_[a-zA-Z0-9_]{82}"), "GitHub Fine-Grained Token detected"),
    ("GitHub OAuth", re.compile(r"gho_[a-zA-Z0-9]{36}"), "GitHub OAuth Token detected"),
    # OpenAI
    ("OpenAI API Key", re.compile(r"sk-[a-zA-Z0-9]{20,}T3BlbkFJ[a-zA-Z0-9]{20,}"), "OpenAI API key detected"),
    ("OpenAI API Key (proj)", re.compile(r"sk-proj-[a-zA-Z0-9_\-]{40,}"), "OpenAI project API key detected"),
    # Anthropic
    ("Anthropic API Key", re.compile(r"sk-ant-[a-zA-Z0-9_\-]{40,}"), "Anthropic API key detected"),
    # Slack
    ("Slack Token", re.compile(r"xox[bpors]-[0-9a-zA-Z\-]{10,}"), "Slack token detected"),
    (
        "Slack Webhook",
        re.compile(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+"),
        "Slack webhook URL detected",
    ),
    # Generic secrets
    (
        "Generic Password",
        re.compile(r"""(?:password|passwd|pwd)\s*[:=]\s*['"]([^'"]{8,})['"]""", re.IGNORECASE),
        "Potential password in assignment",
    ),
    (
        "Generic Token",
        re.compile(r"""(?:token|bearer|auth[_-]?token)\s*[:=]\s*['"]([a-zA-Z0-9_\-\.]{20,})['"]""", re.IGNORECASE),
        "Potential token in assignment",
    ),
    (
        "Generic Secret",
        re.compile(r"""(?:secret|client[_-]?secret)\s*[:=]\s*['"]([a-zA-Z0-9_\-]{16,})['"]""", re.IGNORECASE),
        "Potential secret in assignment",
    ),
    # Connection strings
    (
        "Database Connection String",
        re.compile(r"(?:mongodb|postgres|mysql|redis)://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+", re.IGNORECASE),
        "Database connection string with credentials detected",
    ),
    # Private keys
    ("Private Key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "Private key detected"),
    # High entropy strings (simplified - long hex or base64 strings that look like secrets)
    (
        "Potential Base64 Secret",
        re.compile(
            r"""(?:key|secret|token|password|credential)\s*[:=]\s*['"]([A-Za-z0-9+/=]{40,})['"]""", re.IGNORECASE
        ),
        "Long encoded string in secret-like variable",
    ),
]

# --- Patterns that look like secrets but are usually safe ---
SECRET_ALLOWLIST = [
    re.compile(r"your[-_]?(?:api)?[-_]?key[-_]?here", re.IGNORECASE),
    re.compile(r"<your[-_]", re.IGNORECASE),
    re.compile(r"\$\{?\w+\}?"),  # Environment variable references
    re.compile(r"process\.env\.\w+"),  # Node.js env vars
    re.compile(r"os\.environ"),  # Python env vars
    re.compile(r"PLACEHOLDER", re.IGNORECASE),
    re.compile(r"xxx+", re.IGNORECASE),
    re.compile(r"CHANGEME", re.IGNORECASE),
]

# --- External URL patterns ---
URL_PATTERN = re.compile(r"https?://[^\s'\"\)>\]]+", re.IGNORECASE)

# Well-known safe domains (documentation, specs, standards)
SAFE_DOMAINS = {
    "github.com",
    "raw.githubusercontent.com",
    "docs.anthropic.com",
    "docs.claude.com",
    "anthropic.com",
    "agentskills.io",
    "docs.python.org",
    "pypi.org",
    "developer.mozilla.org",
    "mdn.io",
    "owasp.org",
    "stackoverflow.com",
    "wikipedia.org",
    "example.com",
    "example.org",
    "localhost",
    "127.0.0.1",
}

# --- Subprocess / shell patterns ---
SUBPROCESS_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    (
        "subprocess.run/call/Popen",
        re.compile(r"subprocess\.(run|call|Popen|check_output|check_call)\s*\("),
        "Subprocess execution detected",
    ),
    ("os.system", re.compile(r"os\.system\s*\("), "os.system execution detected"),
    ("os.popen", re.compile(r"os\.popen\s*\("), "os.popen execution detected"),
    ("shell=True", re.compile(r"shell\s*=\s*True"), "shell=True is dangerous — allows shell injection"),
    ("eval/exec", re.compile(r"(?:^|\s)(?:eval|exec)\s*\("), "eval/exec detected — can execute arbitrary code"),
    # Note: backtick pattern removed — causes massive false positives in Python
    # f-strings and markdown. Shell backtick execution is rare in skill scripts.
]

# --- Unsafe install patterns ---
INSTALL_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    (
        "pip install",
        re.compile(r"pip3?\s+install\s+(?!-r\s)", re.IGNORECASE),
        "Direct pip install — dependency not pinned in requirements",
    ),
    ("npm install", re.compile(r"npm\s+install\s+", re.IGNORECASE), "npm install detected"),
    (
        "curl | sh",
        re.compile(r"curl\s+.*\|\s*(?:bash|sh|zsh)", re.IGNORECASE),
        "curl-pipe-shell pattern — extremely dangerous supply chain risk",
    ),
    (
        "wget | sh",
        re.compile(r"wget\s+.*\|\s*(?:bash|sh|zsh)", re.IGNORECASE),
        "wget-pipe-shell pattern — extremely dangerous supply chain risk",
    ),
]

# --- Injection surface patterns ---
# Patterns in SKILL.md instructions that might make the skill vulnerable to prompt injection
INJECTION_SURFACE_PATTERNS: list[tuple[str, re.Pattern, str, str]] = [
    (
        "Unbounded user input handling",
        re.compile(
            r"(?:read|accept|take|use|process)\s+(?:any|all|whatever|user)\s+(?:input|content|data|text)", re.IGNORECASE
        ),
        "Skill instructs agent to process arbitrary user input without validation",
        "Add input validation or scope restrictions",
    ),
    (
        "Execute user-provided code/commands",
        re.compile(
            r"(?:run|execute|eval)\s+(?:the\s+)?(?:user|their|provided|given)\s+(?:code|command|script|query)",
            re.IGNORECASE,
        ),
        "Skill instructs agent to execute user-provided code",
        "Never execute user input directly; validate and sandbox",
    ),
    (
        "Write to arbitrary paths",
        re.compile(
            r"(?:write|save|create)\s+(?:to|at|in)\s+(?:any|the\s+specified|user|given)\s+(?:path|location|directory|file)",
            re.IGNORECASE,
        ),
        "Skill allows writing to user-specified paths without restrictions",
        "Restrict write paths to a workspace directory",
    ),
]

# --- Unsafe deserialization patterns (SEC-006) ---
DESERIALIZATION_PATTERNS: list[tuple[str, re.Pattern, str, str]] = [
    (
        "pickle.load/loads",
        re.compile(r"(?:c?[Pp]ickle)\.(?:load|loads)\s*\("),
        "pickle deserialization detected — can execute arbitrary code",
        "CRITICAL",
    ),
    (
        "marshal.loads",
        re.compile(r"marshal\.loads?\s*\("),
        "marshal deserialization detected — can execute arbitrary code",
        "CRITICAL",
    ),
    (
        "shelve.open",
        re.compile(r"shelve\.open\s*\("),
        "shelve.open uses pickle internally — can execute arbitrary code",
        "CRITICAL",
    ),
    (
        "yaml.load without SafeLoader",
        re.compile(r"yaml\.load\s*\("),
        "yaml.load without SafeLoader can execute arbitrary code",
        "WARNING",
    ),
]

# yaml.safe_load is the safe alternative — no flag needed
YAML_SAFE_PATTERN = re.compile(r"yaml\.safe_load\s*\(")
YAML_SAFE_LOADER_PATTERN = re.compile(r"Loader\s*=\s*(?:yaml\.)?SafeLoader")

# --- Dynamic import / code generation patterns (SEC-007) ---
DYNAMIC_IMPORT_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("importlib.import_module", re.compile(r"importlib\.import_module\s*\("), "Dynamic module import detected"),
    ("__import__", re.compile(r"__import__\s*\("), "Dynamic import via __import__ detected"),
    ("compile()", re.compile(r"(?<!\w)compile\s*\(\s*['\"]"), "Code compilation via compile() detected"),
    ("types.FunctionType", re.compile(r"types\.FunctionType\s*\("), "Dynamic function creation via types.FunctionType"),
    ("types.CodeType", re.compile(r"types\.CodeType\s*\("), "Dynamic code object creation via types.CodeType"),
]

# --- Base64 encoded payload patterns (SEC-008) ---
BASE64_DECODE_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("base64.b64decode", re.compile(r"base64\.b64decode\s*\("), "Base64 decoding detected"),
    ("base64.decodebytes", re.compile(r"base64\.decodebytes\s*\("), "Base64 decodebytes detected"),
    ("atob()", re.compile(r"(?<!\w)atob\s*\("), "JavaScript atob() base64 decoding detected"),
]

# Pattern for long base64 strings (>100 chars of base64 alphabet)
LONG_BASE64_STRING = re.compile(r"""['"]([A-Za-z0-9+/=]{100,})['"]""")

# Pattern for eval/exec near base64 (on same line or adjacent)
EVAL_EXEC_PATTERN = re.compile(r"(?:eval|exec)\s*\(", re.IGNORECASE)

# --- MCP server reference patterns (SEC-009) ---
MCP_CONFIG_PATTERNS: list[tuple[str, re.Pattern, str, str]] = [
    (
        "mcpServers config block",
        re.compile(r"""(?:["']?mcpServers["']?|["']?mcp_servers["']?)\s*[:=]""", re.IGNORECASE),
        "MCP server configuration block detected — could connect to external servers",
        "WARNING",
    ),
    (
        "npx -y external package",
        re.compile(r"npx\s+-y\s+@?[a-zA-Z0-9_\-]+(?:/[a-zA-Z0-9_\-]+)?"),
        "npx -y auto-installs and runs a package — supply chain risk for MCP servers",
        "CRITICAL",
    ),
    (
        "MCP/SSE endpoint URL",
        re.compile(r"https?://[^\s'\"]+/(?:mcp|sse)(?:[/\s'\"]|$)", re.IGNORECASE),
        "Reference to external MCP/SSE endpoint detected",
        "WARNING",
    ),
]


def _scan_file_for_secrets(file_path: Path, content: str) -> list[Finding]:
    """Scan a single file for secret patterns."""
    findings = []

    for line_num, line in enumerate(content.split("\n"), 1):
        for pattern_name, pattern, description in SECRET_PATTERNS:
            match = pattern.search(line)
            if match:
                # Check against allowlist
                matched_text = match.group(0)
                if any(allow.search(matched_text) for allow in SECRET_ALLOWLIST):
                    continue
                # Also check the full line for allowlist patterns
                if any(allow.search(line) for allow in SECRET_ALLOWLIST):
                    continue

                findings.append(
                    Finding(
                        code="SEC-001",
                        severity=Severity.CRITICAL,
                        category=Category.SECURITY,
                        title=f"Secret detected: {pattern_name}",
                        detail=f"{description}. Line: {line.strip()[:100]}{'...' if len(line.strip()) > 100 else ''}",
                        file_path=str(file_path),
                        line_number=line_num,
                        fix="Remove the secret. Use environment variables or a secrets manager instead.",
                    )
                )

    return findings


def _scan_file_for_urls(file_path: Path, content: str, extra_safe_domains: set[str] | None = None) -> list[Finding]:
    """Scan a file for external URLs."""
    findings = []
    seen_urls = set()
    all_safe = SAFE_DOMAINS | (extra_safe_domains or set())

    for line_num, line in enumerate(content.split("\n"), 1):
        for match in URL_PATTERN.finditer(line):
            url = match.group(0).rstrip(".,;:)]}'\"")
            if url in seen_urls:
                continue
            seen_urls.add(url)

            # Extract domain
            domain_match = re.match(r"https?://([^/:]+)", url)
            if not domain_match:
                continue
            domain = domain_match.group(1).lower()

            # Skip safe domains (exact match or proper subdomain)
            if any(domain == safe or domain.endswith("." + safe) for safe in all_safe):
                continue

            # Check if it's in a script (higher risk) vs documentation/comments (lower risk)
            is_script = file_path.suffix in (".py", ".sh", ".js", ".ts")

            # In scripts, check if the URL is in a comment line
            line_stripped = line.strip()
            is_comment = (
                line_stripped.startswith("#")
                or line_stripped.startswith("//")
                or line_stripped.startswith("*")
                or line_stripped.startswith('"""')
            )

            if is_script and not is_comment:
                severity = Severity.WARNING
            else:
                severity = Severity.INFO

            findings.append(
                Finding(
                    code="SEC-002",
                    severity=severity,
                    category=Category.SECURITY,
                    title=f"External URL: {domain}",
                    detail=f"URL: {url[:120]}{'...' if len(url) > 120 else ''}",
                    file_path=str(file_path),
                    line_number=line_num,
                    fix="Document why this external endpoint is necessary. External calls are a data exfiltration risk.",
                )
            )

    return findings


def _scan_file_for_subprocess(file_path: Path, content: str) -> list[Finding]:
    """Scan script files for subprocess execution patterns."""
    findings = []

    if file_path.suffix not in (".py", ".sh", ".js", ".ts", ".bash"):
        return findings

    for line_num, line in enumerate(content.split("\n"), 1):
        for pattern_name, pattern, description in SUBPROCESS_PATTERNS:
            if pattern.search(line):
                # shell=True is always a warning; others are INFO
                severity = (
                    Severity.WARNING
                    if "shell" in pattern_name.lower() or "eval" in pattern_name.lower()
                    else Severity.INFO
                )

                findings.append(
                    Finding(
                        code="SEC-003",
                        severity=severity,
                        category=Category.SECURITY,
                        title=f"Subprocess pattern: {pattern_name}",
                        detail=f"{description}. Line: {line.strip()[:100]}",
                        file_path=str(file_path),
                        line_number=line_num,
                        fix="Ensure inputs are validated before passing to subprocess. Avoid shell=True.",
                    )
                )

    return findings


def _scan_file_for_installs(file_path: Path, content: str) -> list[Finding]:
    """Scan for unsafe dependency installation patterns.

    Only scans script files and shell files — skips documentation (.md) files
    where install commands are instructions for the user, not executable code.
    curl|bash and wget|bash are still flagged in all files due to extreme risk.
    """
    findings = []

    # Skip documentation files for non-critical patterns (pip/npm in docs are user instructions)
    is_doc = file_path.suffix in (".md", ".txt", ".rst")

    for line_num, line in enumerate(content.split("\n"), 1):
        for pattern_name, pattern, description in INSTALL_PATTERNS:
            if pattern.search(line):
                is_pipe_shell = "curl" in pattern_name.lower() or "wget" in pattern_name.lower()
                # Skip pip/npm in documentation files (user instructions, not executable code)
                if is_doc and not is_pipe_shell:
                    continue
                severity = Severity.CRITICAL if is_pipe_shell else Severity.WARNING

                findings.append(
                    Finding(
                        code="SEC-004",
                        severity=severity,
                        category=Category.SECURITY,
                        title=f"Unsafe install: {pattern_name}",
                        detail=f"{description}. Line: {line.strip()[:100]}",
                        file_path=str(file_path),
                        line_number=line_num,
                        fix="Pin dependencies in a requirements file. Never pipe curl output to shell.",
                    )
                )

    return findings


def _scan_file_for_deserialization(file_path: Path, content: str) -> list[Finding]:
    """Scan script files for unsafe deserialization patterns (SEC-006)."""
    findings = []

    if file_path.suffix not in (".py", ".sh", ".js", ".ts", ".bash"):
        return findings

    for line_num, line in enumerate(content.split("\n"), 1):
        for pattern_name, pattern, description, sev_str in DESERIALIZATION_PATTERNS:
            if pattern.search(line):
                # Special case: yaml.load is OK if SafeLoader is on the same line
                if "yaml.load" in pattern_name:
                    if YAML_SAFE_LOADER_PATTERN.search(line):
                        continue
                    # Also skip if it's actually yaml.safe_load
                    if YAML_SAFE_PATTERN.search(line):
                        continue

                severity = Severity.CRITICAL if sev_str == "CRITICAL" else Severity.WARNING

                findings.append(
                    Finding(
                        code="SEC-006",
                        severity=severity,
                        category=Category.SECURITY,
                        title=f"Unsafe deserialization: {pattern_name}",
                        detail=f"{description}. Line: {line.strip()[:100]}",
                        file_path=str(file_path),
                        line_number=line_num,
                        fix="Use safe alternatives: yaml.safe_load(), json.loads(), or validate input before deserialization.",
                    )
                )

    return findings


def _scan_file_for_dynamic_imports(file_path: Path, content: str) -> list[Finding]:
    """Scan script files for dynamic import/code generation patterns (SEC-007)."""
    findings = []

    if file_path.suffix not in (".py", ".sh", ".js", ".ts", ".bash"):
        return findings

    for line_num, line in enumerate(content.split("\n"), 1):
        for pattern_name, pattern, description in DYNAMIC_IMPORT_PATTERNS:
            if pattern.search(line):
                findings.append(
                    Finding(
                        code="SEC-007",
                        severity=Severity.WARNING,
                        category=Category.SECURITY,
                        title=f"Dynamic import/codegen: {pattern_name}",
                        detail=f"{description}. Line: {line.strip()[:100]}",
                        file_path=str(file_path),
                        line_number=line_num,
                        fix="Avoid dynamic imports; use explicit imports. Dynamic code generation is a code injection risk.",
                    )
                )

    return findings


def _scan_file_for_base64_payloads(file_path: Path, content: str) -> list[Finding]:
    """Scan files for base64 encoded payload patterns (SEC-008)."""
    findings = []

    if file_path.suffix not in (".py", ".sh", ".js", ".ts", ".bash"):
        return findings

    lines = content.split("\n")
    for line_num, line in enumerate(lines, 1):
        # Check for base64 decode function calls
        for pattern_name, pattern, description in BASE64_DECODE_PATTERNS:
            if pattern.search(line):
                # Check if eval/exec is on the same line — CRITICAL
                if EVAL_EXEC_PATTERN.search(line):
                    severity = Severity.CRITICAL
                    detail = (
                        f"{description} Combined with eval/exec — likely malicious payload. Line: {line.strip()[:100]}"
                    )
                else:
                    severity = Severity.WARNING
                    detail = f"{description}. Line: {line.strip()[:100]}"

                findings.append(
                    Finding(
                        code="SEC-008",
                        severity=severity,
                        category=Category.SECURITY,
                        title=f"Base64 payload: {pattern_name}",
                        detail=detail,
                        file_path=str(file_path),
                        line_number=line_num,
                        fix="Avoid decoding and executing base64 payloads. Use plain-text code for transparency.",
                    )
                )

        # Check for long base64 strings combined with eval/exec
        if LONG_BASE64_STRING.search(line):
            # Look for eval/exec on the same line or within 3 lines
            context_start = max(0, line_num - 2)
            context_end = min(len(lines), line_num + 2)
            context = "\n".join(lines[context_start:context_end])
            if EVAL_EXEC_PATTERN.search(context):
                findings.append(
                    Finding(
                        code="SEC-008",
                        severity=Severity.CRITICAL,
                        category=Category.SECURITY,
                        title="Base64 payload: long encoded string with eval/exec",
                        detail=f"Long base64 string near eval/exec — likely obfuscated malicious payload. Line: {line.strip()[:100]}",
                        file_path=str(file_path),
                        line_number=line_num,
                        fix="Remove obfuscated payloads. All code should be human-readable.",
                    )
                )

    return findings


def _scan_file_for_mcp_references(file_path: Path, content: str) -> list[Finding]:
    """Scan files for MCP server references (SEC-009)."""
    findings = []

    for line_num, line in enumerate(content.split("\n"), 1):
        for pattern_name, pattern, description, sev_str in MCP_CONFIG_PATTERNS:
            if pattern.search(line):
                severity = Severity.CRITICAL if sev_str == "CRITICAL" else Severity.WARNING

                findings.append(
                    Finding(
                        code="SEC-009",
                        severity=severity,
                        category=Category.SECURITY,
                        title=f"MCP server reference: {pattern_name}",
                        detail=f"{description}. Line: {line.strip()[:100]}",
                        file_path=str(file_path),
                        line_number=line_num,
                        fix="Verify MCP server references are trusted. External MCP servers can be an attack vector.",
                    )
                )

    return findings


def _scan_skill_md_for_eval_exec(skill_md: Path, content: str) -> list[Finding]:
    """Scan SKILL.md code blocks for eval()/exec() instructions (SEC-005 enhancement)."""
    findings = []
    in_code_block = False

    for line_num, line in enumerate(content.split("\n"), 1):
        stripped = line.strip()

        # Track code block boundaries
        if stripped.startswith("```"):
            if in_code_block:
                in_code_block = False
            else:
                in_code_block = True
                stripped[3:].strip().lower()
            continue

        if in_code_block and EVAL_EXEC_PATTERN.search(line):
            findings.append(
                Finding(
                    code="SEC-005",
                    severity=Severity.WARNING,
                    category=Category.SECURITY,
                    title="Injection surface: eval/exec in SKILL.md code block",
                    detail=f"SKILL.md code block contains eval/exec — instructs agent to run dangerous code. Line: {stripped[:100]}",
                    file_path=str(skill_md),
                    line_number=line_num,
                    fix="Remove eval/exec from SKILL.md code examples. Use safe alternatives.",
                )
            )

    return findings


def _scan_skill_md_for_injection(skill_md: Path, content: str) -> list[Finding]:
    """Scan SKILL.md body for injection surface patterns."""
    findings = []

    for line_num, line in enumerate(content.split("\n"), 1):
        for pattern_name, pattern, description, fix in INJECTION_SURFACE_PATTERNS:
            if pattern.search(line):
                findings.append(
                    Finding(
                        code="SEC-005",
                        severity=Severity.WARNING,
                        category=Category.SECURITY,
                        title=f"Injection surface: {pattern_name}",
                        detail=f"{description}. Line: {line.strip()[:100]}",
                        file_path=str(skill_md),
                        line_number=line_num,
                        fix=fix,
                    )
                )

    return findings


# ---------------------------------------------------------------------------
# Strict-mode helpers: NFKC normalisation + Python AST pass
# ---------------------------------------------------------------------------


def _nfkc_normalize(content: str) -> str:
    """NFKC-normalise *content* so fullwidth and mathematical-alphanumeric
    homoglyphs collapse to ASCII before regex matching.

    NFKC handles compatibility decomposition — ``ｅｖａｌ`` (fullwidth) and
    ``𝐞𝐯𝐚𝐥`` (mathematical bold) both fold to ``eval``.  It does NOT fold
    Cyrillic letters that visually resemble Latin (``е`` U+0435 stays
    U+0435), because those are different scripts entirely; that gap is
    documented in ``docs/3-security-audit.md``.
    """
    return unicodedata.normalize("NFKC", content)


# AST node names that are considered arbitrary-code-execution surfaces
# when called as a bare name (e.g. ``eval(...)``).  The mapping value is
# the suffix appended to the SEC-* code so reviewers can distinguish AST
# findings from regex findings (``SEC-007-AST`` vs ``SEC-007``).
_AST_DANGEROUS_BUILTINS = {
    "eval": ("SEC-007-AST", "Dangerous builtin: eval()"),
    "exec": ("SEC-007-AST", "Dangerous builtin: exec()"),
    "compile": ("SEC-007-AST", "Dangerous builtin: compile()"),
    "__import__": ("SEC-007-AST", "Dynamic import: __import__()"),
}

# Attribute-call patterns: maps ``module.attr`` → (code, title).  The
# attribute resolution walks Attribute chains (``a.b.c``) so both
# ``pickle.loads(...)`` and ``module.pickle.loads(...)`` match.
_AST_DANGEROUS_CALLS = {
    "pickle.loads": ("SEC-006-AST", "Unsafe deserialization: pickle.loads"),
    "pickle.load": ("SEC-006-AST", "Unsafe deserialization: pickle.load"),
    "marshal.loads": ("SEC-006-AST", "Unsafe deserialization: marshal.loads"),
    "marshal.load": ("SEC-006-AST", "Unsafe deserialization: marshal.load"),
    "shelve.open": ("SEC-006-AST", "Unsafe deserialization: shelve.open"),
    "os.system": ("SEC-003-AST", "Subprocess: os.system"),
    "os.popen": ("SEC-003-AST", "Subprocess: os.popen"),
}


def _attr_chain(node: ast.AST) -> str | None:
    """Return ``"a.b.c"`` for an ``Attribute(Attribute(Name("a"), "b"), "c")``
    node, or ``None`` if the chain isn't pure name/attribute access."""
    parts: list[str] = []
    current: ast.AST = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if not isinstance(current, ast.Name):
        return None
    parts.append(current.id)
    return ".".join(reversed(parts))


def _is_yaml_load_unsafe(call: ast.Call) -> bool:
    """``yaml.load(s)`` without ``Loader=`` keyword is the unsafe form;
    ``yaml.load(s, Loader=SafeLoader)`` and ``yaml.safe_load(s)`` are
    safe.  This helper identifies only the unsafe shape."""
    chain = _attr_chain(call.func)
    if chain not in {"yaml.load"}:
        return False
    for kw in call.keywords:
        if kw.arg == "Loader":
            return False
    return True


def _is_subprocess_shell_true(call: ast.Call) -> bool:
    """``subprocess.run(..., shell=True)`` etc. — flags any
    subprocess-module call that explicitly passes ``shell=True``."""
    chain = _attr_chain(call.func)
    if not chain or not chain.startswith("subprocess."):
        return False
    for kw in call.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


def _is_b64decode_of_concat(call: ast.Call) -> bool:
    """``b64decode("AA" + "BB")`` — flags only the
    ``Constant + Constant`` shape (and chains of the same).  Source-level
    string concatenation (``"AA" "BB"``) is folded to a single
    ``Constant`` by the parser, so it's already caught by the existing
    long-string regex.  Variable-fed concat (``b64decode(s + t)``) is
    NOT flagged here — taint analysis is out of scope."""
    chain = _attr_chain(call.func) if isinstance(call.func, ast.Attribute) else None
    is_b64 = chain in {"base64.b64decode", "b64decode"} or (
        isinstance(call.func, ast.Name) and call.func.id == "b64decode"
    )
    if not is_b64 or not call.args:
        return False
    arg = call.args[0]

    def is_constant_concat(n: ast.AST) -> bool:
        if isinstance(n, ast.Constant) and isinstance(n.value, (str, bytes)):
            return True
        if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add):
            return is_constant_concat(n.left) and is_constant_concat(n.right)
        return False

    return isinstance(arg, ast.BinOp) and is_constant_concat(arg)


def _ast_scan_python(file_path: Path, content: str) -> list[Finding]:
    """Walk the Python AST of *content* and emit findings for known
    arbitrary-code-execution and unsafe-deserialization shapes.

    Catches multi-line / commented / line-continuation bypasses that
    the line-oriented regex pass misses.  Returns an empty list if
    *content* doesn't parse as Python (a ``.py`` extension on a non-
    Python file is not itself a security finding)."""
    findings: list[Finding] = []
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return findings

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        # Bare-name dangerous builtins: eval, exec, compile, __import__.
        if isinstance(node.func, ast.Name) and node.func.id in _AST_DANGEROUS_BUILTINS:
            code, title = _AST_DANGEROUS_BUILTINS[node.func.id]
            findings.append(
                Finding(
                    code=code,
                    severity=Severity.WARNING,
                    category=Category.SECURITY,
                    title=title,
                    detail=f"AST detected a call to {node.func.id}() at this location.",
                    file_path=str(file_path),
                    line_number=getattr(node, "lineno", None),
                    fix="Avoid arbitrary-code-execution builtins; use a safer parser or explicit dispatch.",
                )
            )
            continue

        # Attribute-call dangerous patterns: pickle.loads, os.system, etc.
        chain = _attr_chain(node.func) if isinstance(node.func, ast.Attribute) else None
        if chain in _AST_DANGEROUS_CALLS:
            code, title = _AST_DANGEROUS_CALLS[chain]
            # Tailor the fix-text by category — "use json.loads" is the
            # right hint for pickle/marshal/shelve, but useless for
            # os.system / os.popen.
            if code.startswith("SEC-006-AST"):
                fix = "Use a safer alternative: json.loads or yaml.safe_load."
            elif code.startswith("SEC-003-AST"):
                fix = "Use subprocess.run with a list argv (and shell=False)."
            else:
                fix = "Use a safer alternative."
            findings.append(
                Finding(
                    code=code,
                    severity=Severity.WARNING,
                    category=Category.SECURITY,
                    title=title,
                    detail=f"AST detected a call to {chain}() at this location.",
                    file_path=str(file_path),
                    line_number=getattr(node, "lineno", None),
                    fix=fix,
                )
            )
            continue

        # yaml.load without Loader=
        if _is_yaml_load_unsafe(node):
            findings.append(
                Finding(
                    code="SEC-006-AST",
                    severity=Severity.WARNING,
                    category=Category.SECURITY,
                    title="Unsafe deserialization: yaml.load without Loader=",
                    detail="yaml.load() without an explicit Loader= argument deserialises arbitrary Python objects.",
                    file_path=str(file_path),
                    line_number=getattr(node, "lineno", None),
                    fix="Use yaml.safe_load() or pass Loader=yaml.SafeLoader.",
                )
            )
            continue

        # subprocess.run(..., shell=True)
        if _is_subprocess_shell_true(node):
            findings.append(
                Finding(
                    code="SEC-003-AST",
                    severity=Severity.WARNING,
                    category=Category.SECURITY,
                    title="Subprocess with shell=True",
                    detail="shell=True interprets the command string with the shell, enabling injection if any argument is user-controlled.",
                    file_path=str(file_path),
                    line_number=getattr(node, "lineno", None),
                    fix="Pass argv as a list and omit shell=True.",
                )
            )
            continue

        # b64decode("AA" + "BB" + ...) — base64 string-concat bypass.
        if _is_b64decode_of_concat(node):
            findings.append(
                Finding(
                    code="SEC-008-AST",
                    severity=Severity.WARNING,
                    category=Category.SECURITY,
                    title="Base64 decode of literal-concatenation",
                    detail="b64decode() called with a chain of string-literal concatenation — pattern often used to evade single-string base64 detectors.",
                    file_path=str(file_path),
                    line_number=getattr(node, "lineno", None),
                    fix="If the data is constant, store it as a single literal so static analysis can see it; better, don't ship encoded payloads.",
                )
            )

    return findings


# Directories that are part of an Agent Skill per the agentskills.io standard.
# Used when include_all=False to scope scanning to skill content only.
# We scan scripts/ and agents/ (executable code) but not references/ or assets/
# (documentation/static content that may describe security patterns without
# actually being vulnerable).
SKILL_SCAN_DIRS = {"scripts", "agents"}


def _iter_scan_files(
    skill_path: Path,
    include_all: bool = False,
    max_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> tuple[list[Path], list[Path]]:
    """Collect files to scan based on scope.

    When include_all is False (default), only scans:
    - SKILL.md (the skill manifest — the only root file agents read)
    - Executable skill directories: scripts/, agents/

    This excludes README.md, demo scripts, pyproject.toml, references/,
    assets/, evals/, tests/, examples/, docs/, and other files that are
    not part of the skill's executable content. Documentation and
    development files may describe security anti-patterns without
    actually being vulnerable.

    When include_all is True, scans the entire directory tree
    (excluding build artifacts).

    Args:
        skill_path: Path to the skill directory
        include_all: If True, scan entire directory tree
        max_bytes: Skip files larger than this size

    Returns:
        Two lists: (files_to_scan, files_skipped_for_size).  The second
        list lets callers emit STR-022 INFO findings so operators can
        see when the audit was incomplete instead of silently truncated.
    """
    # Directories to skip (build artifacts, environments, caches)
    skip_dirs = {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        "egg-info",
        ".egg-info",
        "dist",
        "build",
        ".tox",
    }

    text_extensions = {
        ".md",
        ".py",
        ".sh",
        ".js",
        ".ts",
        ".json",
        ".yaml",
        ".yml",
        ".toml",
        ".txt",
        ".bash",
        ".zsh",
        ".env",
        ".cfg",
        ".ini",
        ".conf",
    }

    files: list[Path] = []
    skipped: list[Path] = []

    if include_all:
        candidates = skill_path.rglob("*")
    else:
        # SKILL.md only at root + executable skill directories
        candidates_list: list[Path] = []
        skill_md = skill_path / "SKILL.md"
        if skill_md.is_file():
            candidates_list.append(skill_md)
        for item in skill_path.iterdir():
            if item.is_dir() and item.name in SKILL_SCAN_DIRS:
                candidates_list.extend(item.rglob("*"))
        candidates = iter(candidates_list)

    for file_path in candidates:
        if not file_path.is_file():
            continue
        if any(skip in file_path.parts for skip in skip_dirs):
            continue
        if any(p.endswith(".egg-info") for p in file_path.parts):
            continue
        if file_path.name.startswith(".") and file_path.suffix != ".env":
            continue
        if file_path.suffix.lower() not in text_extensions and file_path.suffix != "":
            continue
        if file_path.stat().st_size > max_bytes:
            skipped.append(file_path)
            continue
        files.append(file_path)

    return files, skipped


def scan_security(
    skill_path: str | Path,
    include_all: bool = False,
    extra_safe_domains: set[str] | None = None,
    *,
    strict: bool = False,
    max_file_bytes: int | None = None,
) -> list[Finding]:
    """Run all security scans on a skill directory.

    By default, scans only skill-standard directories (SKILL.md, scripts/,
    references/, assets/, evals/, agents/ and root-level files). This matches
    the agentskills.io definition of skill content and avoids false positives
    from test fixtures or development files.

    Use include_all=True to scan the entire directory tree.

    Args:
        skill_path: Path to the skill directory
        include_all: If True, scan entire directory tree instead of
            just skill-standard directories
        extra_safe_domains: Domains the URL scanner should treat as safe.
        strict: When True, enable bypass-resistant checks: NFKC normalise
            text before regex matching (catches fullwidth /
            mathematical-alphanumeric homoglyphs — but not Cyrillic, see
            ``docs/3-security-audit.md``), and run a Python-AST pass over
            ``*.py`` files (catches multi-line / commented eval/exec/
            pickle/yaml.load/subprocess.shell=True/literal-base64-concat
            patterns).
        max_file_bytes: Per-file size cap.  Defaults to
            ``DEFAULT_MAX_FILE_BYTES`` (1 MB) or, when ``strict=True``,
            ``STRICT_MAX_FILE_BYTES`` (10 MB).  Files exceeding the cap
            are skipped with a STR-022 INFO finding.

    Returns:
        List of security findings
    """
    skill_path = Path(skill_path)
    findings: list[Finding] = []

    if not skill_path.is_dir():
        return findings

    if max_file_bytes is None:
        max_file_bytes = STRICT_MAX_FILE_BYTES if strict else DEFAULT_MAX_FILE_BYTES

    files, skipped_for_size = _iter_scan_files(skill_path, include_all=include_all, max_bytes=max_file_bytes)

    # STR-022: surface files we skipped because of the size cap.  INFO
    # severity — operators can decide to raise the cap, but the audit
    # didn't actually fail anything.
    for skipped in skipped_for_size:
        findings.append(
            Finding(
                code="STR-022",
                severity=Severity.INFO,
                category=Category.STRUCTURE,
                title="File exceeds audit size cap — skipped",
                detail=(
                    f"Skipped {skipped.name} ({skipped.stat().st_size} bytes) — "
                    f"exceeds the audit's {max_file_bytes}-byte cap."
                ),
                file_path=str(skipped),
                fix=(
                    "Either trim the file, split content into smaller files, "
                    "or pass `--max-file-bytes <larger>` to raise the cap."
                ),
            )
        )

    for file_path in files:
        try:
            raw_content = file_path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, PermissionError):
            continue

        # In strict mode, NFKC-normalise the text before pattern
        # matching so fullwidth and mathematical-alphanumeric
        # homoglyphs collapse to ASCII.  Cyrillic homoglyphs are NOT
        # caught by NFKC; that gap is documented.
        content = _nfkc_normalize(raw_content) if strict else raw_content

        # Run all scanners
        findings.extend(_scan_file_for_secrets(file_path, content))
        findings.extend(_scan_file_for_urls(file_path, content, extra_safe_domains=extra_safe_domains))
        findings.extend(_scan_file_for_subprocess(file_path, content))
        findings.extend(_scan_file_for_installs(file_path, content))
        findings.extend(_scan_file_for_deserialization(file_path, content))
        findings.extend(_scan_file_for_dynamic_imports(file_path, content))
        findings.extend(_scan_file_for_base64_payloads(file_path, content))
        findings.extend(_scan_file_for_mcp_references(file_path, content))

        # Strict-mode AST pass for Python files (uses raw_content so
        # the parser sees the original source, including any
        # non-ASCII identifiers — though Python only legalises a
        # narrow set of Unicode in identifiers, so this is moot for
        # most cases).
        if strict and file_path.suffix == ".py":
            findings.extend(_ast_scan_python(file_path, raw_content))

    # Scan SKILL.md specifically for injection surfaces and eval/exec in code blocks
    skill_md = skill_path / "SKILL.md"
    if skill_md.is_file():
        try:
            raw_content = skill_md.read_text(encoding="utf-8")
            content = _nfkc_normalize(raw_content) if strict else raw_content
            findings.extend(_scan_skill_md_for_injection(skill_md, content))
            findings.extend(_scan_skill_md_for_eval_exec(skill_md, content))
        except Exception:
            pass

    return findings
