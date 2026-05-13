# Security Audit Patterns

The security scanner (`skillctl eval audit`) checks skill content against 9 threat categories. This document details every pattern, what triggers it, how to fix findings, and how to suppress false positives.

## Scan Scope

By default, the scanner only examines **skill-standard files**:
- `SKILL.md` (always scanned)
- `scripts/` directory (executable code)
- `agents/` directory (agent configurations)

Documentation files (README.md, examples/, docs/), test fixtures, and build artifacts are excluded to avoid false positives. Use `--include-all` to scan the entire directory tree.

## Threat Categories

### SEC-001: Hardcoded Secrets

**Severity:** CRITICAL

Detects API keys, tokens, passwords, connection strings, and private keys embedded in skill content.

| Pattern | What It Matches |
|---------|-----------------|
| Generic API key | `api_key = "ABCDEF..."` (20+ char alphanumeric) |
| AWS Access Key | `AKIA` followed by 16 uppercase alphanumeric chars |
| AWS Secret Key | `aws_secret_key = "..."` (40-char base64) |
| GitHub Token (classic) | `ghp_` followed by 36 alphanumeric chars |
| GitHub Token (fine-grained) | `github_pat_` followed by 82 chars |
| GitHub OAuth | `gho_` followed by 36 chars |
| OpenAI API Key | `sk-...T3BlbkFJ...` or `sk-proj-...` |
| Anthropic API Key | `sk-ant-...` (40+ chars) |
| Slack Token | `xox[bpors]-...` |
| Slack Webhook | `https://hooks.slack.com/services/T.../B.../...` |
| Generic password | `password = "..."` (8+ chars) |
| Generic token | `token = "..."` (20+ chars) |
| Generic secret | `secret = "..."` (16+ chars) |
| Database connection | `mongodb://user:pass@host`, `postgres://...` |
| Private key | `-----BEGIN RSA PRIVATE KEY-----` |
| Base64 secret | `key = "..."` (40+ char base64 in secret-like variable) |

**Allowlist** (these patterns are NOT flagged):
- Placeholder values: `your-api-key-here`, `<your-key>`, `PLACEHOLDER`, `CHANGEME`, `xxx`
- Environment variable references: `$VAR`, `${VAR}`, `process.env.VAR`, `os.environ`

**Fix:** Remove secrets. Use environment variables or a secrets manager.

---

### SEC-002: External URLs

**Severity:** WARNING (in scripts) / INFO (in documentation)

Flags URLs pointing to domains not on the safe allowlist. External URLs are a data exfiltration risk surface.

**Default safe domains:**
github.com, raw.githubusercontent.com, docs.anthropic.com, docs.claude.com, anthropic.com, agentskills.io, docs.python.org, pypi.org, developer.mozilla.org, mdn.io, owasp.org, stackoverflow.com, wikipedia.org, example.com, example.org, localhost, 127.0.0.1

**Adding safe domains:** Use `.skilleval.yaml`:
```yaml
safe_domains:
  - internal.company.com
  - registry.npmjs.org
```

**Fix:** Document why the external endpoint is necessary.

---

### SEC-003: Subprocess Execution

**Severity:** WARNING (shell=True, eval/exec) / INFO (others)

Detects subprocess execution in script files (.py, .sh, .js, .ts, .bash).

| Pattern | Risk |
|---------|------|
| `subprocess.run/call/Popen/check_output/check_call` | Can execute arbitrary commands |
| `os.system()` | Shell execution |
| `os.popen()` | Shell execution |
| `shell=True` | Enables shell injection |
| `eval()` / `exec()` | Arbitrary code execution |

**Fix:** Validate inputs before passing to subprocess. Avoid `shell=True`.

---

### SEC-004: Unsafe Dependency Installation

**Severity:** CRITICAL (curl\|sh, wget\|sh) / WARNING (pip/npm)

| Pattern | Risk |
|---------|------|
| `pip install <package>` | Unpinned dependency (supply chain risk) |
| `npm install <package>` | Unpinned dependency |
| `curl ... \| bash` | Downloads and executes arbitrary code |
| `wget ... \| sh` | Downloads and executes arbitrary code |

**Note:** `pip install` and `npm install` in documentation files (.md) are **not flagged** — they are user instructions, not executable code. `curl\|bash` and `wget\|sh` are **always flagged** regardless of file type due to extreme risk.

**Fix:** Pin dependencies in a requirements file. Never pipe downloads to a shell.

---

### SEC-005: Prompt Injection Surface

**Severity:** WARNING

Detects SKILL.md instructions that create injection vulnerabilities.

| Pattern | Example |
|---------|---------|
| Unbounded input handling | "read any user input", "process whatever data" |
| User-provided code execution | "run the user's code", "execute their script" |
| Arbitrary path writes | "write to the specified location", "save at given path" |
| eval/exec in code blocks | `eval(user_input)` inside SKILL.md fenced code blocks |

**Fix:** Add input validation. Scope writes to a workspace directory. Never execute user input directly.

---

### SEC-006: Unsafe Deserialization

**Severity:** CRITICAL (pickle, marshal, shelve) / WARNING (yaml.load)

| Pattern | Risk |
|---------|------|
| `pickle.load()` / `pickle.loads()` | Arbitrary code execution via crafted payloads |
| `marshal.loads()` | Arbitrary code execution |
| `shelve.open()` | Uses pickle internally |
| `yaml.load()` without SafeLoader | Can execute arbitrary Python objects |

**Not flagged:** `yaml.safe_load()` and `yaml.load(Loader=SafeLoader)` are safe alternatives.

**Fix:** Use `json.loads()`, `yaml.safe_load()`, or validate input before deserialization.

---

### SEC-007: Dynamic Imports and Code Generation

**Severity:** WARNING

| Pattern | Risk |
|---------|------|
| `importlib.import_module()` | Loads arbitrary modules at runtime |
| `__import__()` | Dynamic import |
| `compile("...")` | Compiles code strings into executable code |
| `types.FunctionType()` | Creates functions dynamically |
| `types.CodeType()` | Creates code objects dynamically |

**Fix:** Use explicit imports. Dynamic code generation is a code injection risk.

---

### SEC-008: Base64 Encoded Payloads

**Severity:** CRITICAL (with eval/exec) / WARNING (standalone)

| Pattern | Risk |
|---------|------|
| `base64.b64decode()` | Decodes potentially obfuscated payloads |
| `base64.decodebytes()` | Same |
| `atob()` (JavaScript) | Base64 decode |
| Long base64 string (100+ chars) near eval/exec | Obfuscated malicious payload |

The scanner checks a 3-line window around base64 operations for eval/exec calls. When found together, the finding is escalated to CRITICAL.

**Fix:** Remove obfuscated payloads. All code should be human-readable.

---

### SEC-009: MCP Server References

**Severity:** CRITICAL (npx -y) / WARNING (config blocks, endpoint URLs)

| Pattern | Risk |
|---------|------|
| `mcpServers` / `mcp_servers` config block | Connects to potentially untrusted MCP servers |
| `npx -y @package/name` | Auto-installs and runs an npm package (supply chain) |
| `https://host/mcp` or `https://host/sse` | External MCP/SSE endpoint reference |

**Fix:** Verify MCP server references are trusted. External MCP servers can be an attack vector.

---

## Suppressing Findings

### Per-Skill Configuration (`.skilleval.yaml`)

```yaml
audit:
  # Ignore specific finding codes entirely
  ignore:
    - SEC-002
    - STR-016

  # Override severity (downgrade or upgrade)
  severity_overrides:
    SEC-003: info        # Subprocess is expected in this skill
    PERM-005: warning    # Treat absolute paths as warnings

  # Add domains to the safe list
  safe_domains:
    - trusted-api.company.com
```

### Understanding Severity Levels

| Severity | Score Impact | Meaning |
|----------|-------------|---------|
| CRITICAL | -25 points | Blocks registry publishing. Must fix. |
| WARNING | -10 points | Should fix. May indicate a real risk. |
| INFO | -2 points | Informational. Review but may be acceptable. |

## Output Formats

| `--format` | Use case |
|------------|---------|
| `text` (default) | Human-readable, with grade banner and grouped findings. |
| `json` | Machine-readable; full report including `findings[]`, `metadata`, scores. |
| `html` | Standalone HTML page; pair with `--output` to save. |
| `github` | One workflow command per finding (`::error::` / `::warning::` / `::notice::`).  When run inside a GitHub Actions workflow, each finding appears as an inline annotation on the offending file/line in the PR diff.  `skillctl validate --format=github` mirrors the same shape for schema/semver/capability errors and warnings — together the two cover the full pre-publish gate as inline PR annotations. |

`--format=github` skips INFO findings unless `--verbose` is also passed
— GitHub caps inline annotations at 10 per level per workflow run, and
INFO findings would exhaust the cap fast.  Severity → level mapping:
CRITICAL → `error`, WARNING → `warning`, INFO → `notice`.

## Strict Mode (`--strict`)

`skillctl eval audit --strict` enables bypass-resistant checks on top
of the default audit.  It is **opt-in** — the default audit is
unchanged.

### What strict mode adds

| Bypass | Coverage |
|--------|----------|
| **Multi-line `eval`/`exec`** (`eval(\n  payload\n)`) | Closed.  An AST pass over `*.py` files emits `SEC-007-AST` for any literal `eval`/`exec`/`compile`/`__import__` call regardless of line wrapping. |
| **Unsafe deserialization with multi-line args** (`pickle.loads(\n  …\n)`) | Closed.  AST emits `SEC-006-AST` for `pickle.{load,loads}`, `marshal.{load,loads}`, `shelve.open`, and `yaml.load(...)` without `Loader=`. |
| **`subprocess.run(..., shell=True)`** with multi-line args | Closed.  AST emits `SEC-003-AST`. |
| **`os.system` / `os.popen`** | Closed.  AST emits `SEC-003-AST`. |
| **Base64 string-literal concatenation bypass** (`b64decode("AA" + "BB" + …)`) | Closed for the literal-only shape.  AST emits `SEC-008-AST`.  `b64decode(s + t)` where `s` and `t` are names is **not** flagged — that requires taint analysis, out of scope. |
| **`from`-import aliasing** (`from pickle import loads; loads(data)`, including `as`-rename) | Closed.  A pre-pass over `ImportFrom` nodes builds a file-wide alias map; bare-name calls are resolved through it before the dispatch.  The same finding fires whether the user wrote `pickle.loads(x)` or `from pickle import loads; loads(x)` (or `from pickle import loads as P; P(x)`).  See note below on the file-wide trade-off. |
| **Fullwidth / mathematical-alphanumeric homoglyphs** (`ｅｖａｌ`, `𝐞𝐯𝐚𝐥`) | Closed.  Strict mode NFKC-normalises text before regex matching. |
| **Cyrillic homoglyphs** (`еval` with Cyrillic `е`) | **NOT closed.**  Cyrillic letters are a different Unicode script, not a compatibility variant — NFKC leaves them alone.  Detecting visual confusables requires a different mechanism (e.g. the Unicode `confusables.txt` mapping); this is an honest gap. |
| **Files exceeding the size cap** | Strict raises the per-file cap from 1 MB to 10 MB.  Files that still exceed it are surfaced via a STR-022 INFO finding so operators can see the audit was incomplete instead of silently truncating coverage. |

### What strict mode does NOT add

- JavaScript / TypeScript / shell AST analysis — Python only.
- Deobfuscation of runtime-decoded payloads (e.g. base64 piped into
  `eval`).
- Detection of `getattr(__builtins__, "eval")(...)` style indirection
  — name-based AST matching is the limit.
- **`import X as Y` aliasing of dangerous *modules***: `import pickle
  as p; p.loads(x)` produces an attribute chain `"p.loads"` that
  doesn't match `"pickle.loads"` in the dispatch table.  Closing this
  would require module-level alias tracking on top of the existing
  `from`-import alias map.
- Deeply-namespaced calls (`some_pkg.pickle.loads(...)`) — the chain
  match is exact-string, so `some_pkg.pickle.loads` won't match
  `pickle.loads` in the dispatch table.
- Relative imports (`from .pickle import loads`) are skipped by the
  alias collector so the scanner doesn't false-positive on local
  submodules that happen to share a stdlib name.  Code that
  legitimately re-exports stdlib names through a relative import is
  exotic; the absolute form `from pickle import loads` is still
  caught.

### File-wide alias map (deliberate trade-off)

The `from`-import alias map is collected via `ast.walk`, so imports
inside function bodies, conditionals, and `try/except` blocks
contribute to the same file-wide map alongside module-scope imports.
That's deliberate:

- **Real-world frequency** of nested `from X import Y` defensive
  imports (e.g. `try: from foo import bar; except ImportError: bar
  = None`) is high; restricting to module scope would miss them.
- **The pathological false-positive** — a file that has both
  `from pickle import loads` (in any scope) AND `def loads(x): ...`
  (in any scope) and then calls `loads(...)` — is itself a footgun
  the author should fix; over-flagging is the right side of the
  false-positive/false-negative ledger when the dangerous call is
  `pickle.loads`.  Suppress per-file with the `audit.ignore` list in
  `.skilleval.yaml` if you hit a real false positive.

### Per-skill opt-in via `.skilleval.yaml`

```yaml
audit:
  strict: true
  max_file_bytes: 5242880  # optional override of the size cap
```

The CLI flag (`--strict`) wins over the config; the config wins over
the default-off.

### Performance

The AST pass parses each `*.py` file once with `ast.parse`.  For a
~50-file skill the added cost is sub-second; well within typical CI
budget.

## Key Source Files

| File | Role |
|------|------|
| `skillctl/eval/audit/security_scan.py` | All SEC-001 through SEC-009 pattern definitions and scanners |
| `skillctl/eval/audit/structure_check.py` | All STR-001 through STR-021 checks |
| `skillctl/eval/audit/permission_analyzer.py` | All PERM-001 through PERM-005 checks |
| `skillctl/eval/schemas.py` | `Finding`, `Severity`, `Category` types |
| `skillctl/eval/cli.py` | Audit orchestration, `.skilleval.yaml` config application, scoring |
