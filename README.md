<p align="center">
  <img src="skillsops.svg" alt="skillsops logo" width="450" />
</p>

<p align="center">
  <strong>Check, version, and share the skills your AI agents use.</strong>
</p>

<p align="center">
  SkillsOps is an open-source CLI and optional self-hosted registry for agent skills.<br>
  Catch risky instructions, review changes, and install the same skill across your team's coding tools.
</p>

<p align="center">
  <a href="https://github.com/dgallitelli/skillsops/actions/workflows/ci.yml"><img src="https://github.com/dgallitelli/skillsops/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/python-3.10%20|%203.11%20|%203.12%20|%203.13-blue" alt="Python">
  <img src="https://img.shields.io/badge/pyright-checked-green" alt="Type Checked">
  <img src="https://img.shields.io/badge/license-MPL--2.0-blue" alt="License">
  <img src="https://img.shields.io/badge/pip--audit-clean-green" alt="Security">
</p>

---

**SkillsOps is for developers and teams sharing agent skills across projects and
editors.** A skill is a reusable set of instructions in a `SKILL.md` file:
a code-review checklist, an incident playbook, or a release process.

Use the `skillctl` CLI to check those instructions, save a version, and install
it where your team works. Add a self-hosted registry when you need shared access.

## What it helps you do

| Your goal | Start here |
|---|---|
| Catch exposed secrets, injection patterns, and risky code before sharing | `skillctl eval audit ./my-skill` |
| Review instruction and manifest changes between versions | `skillctl diff my-org/skill@0.1.0 my-org/skill@0.1.1` |
| Install one skill across Claude Code, Cursor, Windsurf, Copilot, and Kiro | `skillctl install ./my-skill --target all` |
| Share private skills with scoped access and a registry audit log | `skillctl serve` (optional server package) |

**Local checks and installs need no account, server, or model API key.**
Static audits flag known patterns; they do not guarantee safe execution.

[Get started](#quickstart) · [Capabilities and maturity](#whats-in-the-box) · [Documentation](#documentation)

---

## Quickstart

Python 3.10+. If you already have a skill, install the CLI and audit its folder:

```bash
pip install skillsops
skillctl eval audit ./my-skill
```

To try the full workflow, [download the example skill](https://dgallitelli.github.io/skillsops/assets/code-reviewer.zip)
and unzip it. It includes the instructions and manifest, ready to validate.
Run these commands inside the `code-reviewer` folder:

```bash
pip install skillsops

# Check the skill
skillctl validate
skillctl eval audit .

# Save this version locally
skillctl apply --local

# Install for Claude Code and Cursor
skillctl install my-org/code-reviewer@0.1.0 --target claude,cursor
```

This writes `.claude/skills/code-reviewer/SKILL.md` and
`.cursor/rules/code-reviewer.mdc`. Choose other editors by name, or use
`--target all` to detect editors already present in your workspace.

See the [example source](examples/code-reviewer/SKILL.md) and
[manifest](examples/code-reviewer/skill.yaml). To author your own skill, run
`skillctl create skill my-org/my-skill` in an empty directory, then add your
instructions, required frontmatter, and manifest description.

`apply --local` stores a version on your machine. A shared remote registry
requires a namespaced name such as `my-org/code-reviewer`.

---

## What's in the box

The core workflow covers validation, static audits, version storage, editor
installation, and a self-hosted registry. Advanced features have separate
maturity labels below. The LLM-driven optimizer lives in `skillsops-optimize`.

<details>
<summary>Full capability list and maturity</summary>

| Capability | Status | Why it's here |
|---|---|---|
| `validate` — schema, semver, capability checks | stable | Bad manifests should never reach the store. |
| `eval audit` — static security audit (9 categories, ~35 finding codes, ~70 regex patterns; `--strict` adds an AST pass for Python) | stable | Block leaked secrets, prompt injection, exfil URLs, unsafe deserialization, encoded payloads in CI. |
| `apply` / `get` / `describe` / `delete` — content-addressed local store | stable | Deterministic complete-skill bundles with per-file SHA-256 integrity. |
| `diff` — structural diff between two stored versions | stable | Compare manifests for breaking changes and review content changes between versions. |
| `bump` — semver version edits in `skill.yaml` | stable | Update the version with `--major` / `--minor` / `--patch`. Pair with `skillctl diff` to review breaking changes. |
| `install` / `uninstall` — multi-IDE deploy (Claude Code, Cursor, Windsurf, Copilot, Kiro) | stable | One source SKILL.md, native frontmatter on every IDE. |
| `serve` — self-hosted FastAPI registry with token auth, hash-chained audit log | stable | Run governance on infra you control.  See [SECURITY.md](SECURITY.md) for the threat model. |
| `auth` / `rbac` / `namespace` — role-based access control | stable | Users, 4 roles, hierarchical namespaces, scoped tokens; every decision audited.  See [docs/rbac.md](docs/rbac.md). |
| `policy` / `observe` — opt-in policy and telemetry libraries | experimental | Useful hooks, but the registry and installed agent runtimes do not invoke them automatically. See [docs/runtime-policy.md](docs/runtime-policy.md). |
| `compliance` — framework control-mapping previews | experimental | Deterministic, non-certifying gap analysis; not a trusted compliance or promotion gate. See [docs/compliance.md](docs/compliance.md). |
| `deploy` — local rollout state-machine model | experimental | Models routing and rollback in SQLite; it does not control live registry or runtime traffic. See [docs/deployment.md](docs/deployment.md). |
| `identity` / `forensics` / federation | experimental | Local HS256 inspection, caller-recorded lineage queries, and a programmatic registry-copy helper; trust boundaries are not integrated. See [docs/enterprise.md](docs/enterprise.md). |
| `ci` — CI/CD starter templates | preview | Review, pin, and adapt generated pipelines before production use. |
| `eval report` — deterministic governance score (80% security audit + 20% schema contract) | stable | Reproducible: same inputs always yield the same score. |
| Claude Code MCP plugin (5 core tools: validate, audit, bump, diff, publish) | stable | Use SkillsOps from inside an agentic IDE. |
| `export` / `import` — portable archives | stable | Backup, share, migrate between hosts. |

</details>

---

## Share private skills on your infrastructure

Skills can contain internal processes and review rules. Install the optional
server package to share them through a registry you control:

```bash
# Run the registry on your own host (or a private VPC).
pip install "skillsops[server]"
skillctl serve --hmac-key "$SKILLCTL_HMAC_KEY"

# Issue narrowly-scoped tokens to CI / authors.
skillctl token create --name ci-bot --scope read --scope write:my-org

# Push and pull through your own URL.
skillctl config set registry.url https://skills.internal.example.com
skillctl apply ./my-skill
```

The registry is FastAPI + SQLite + FTS5, stores blobs content-addressed
on the filesystem (or in a git repository), and signs every mutation
into a hash-chained audit log.  Tokens are SHA-256-hashed at rest;
namespace-scoped permissions enforce tenant isolation; rate limiting,
CORS, and TrustedHost middleware are on by default.  See
[SECURITY.md](SECURITY.md) for the full threat model and hardening
checklist. The current persistence design is single-process: a second
registry process or worker using the same data directory is refused at
startup.

For a local container deployment:

```bash
docker compose up --build
```

The Compose file uses a named volume for `/data`. It generates and persists an
audit HMAC key when `SKILLCTL_HMAC_KEY` is absent; production deployments
should inject that variable from a secrets manager.

---

## Audit in CI

```yaml
# .github/workflows/skill-audit.yml
name: Skill audit
on:
  pull_request:
    paths: ['**/SKILL.md', '**/skill.yaml']

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: actions/setup-python@v6
        with: { python-version: '3.13' }
      - run: pip install skillsops
      - run: skillctl eval audit ./skills/ --fail-on-warning --format=github
```

A copy-paste-ready template lives at
[examples/workflows/skill-audit.yml](examples/workflows/skill-audit.yml).
CRITICAL findings fail the build unconditionally.

`--format=github` emits Actions workflow commands so each finding shows
up as an inline annotation on the offending line of the SKILL.md in the
PR diff.  GitHub caps inline annotations at 10 per level per run, so
quiet noisy categories with `.skilleval.yaml` if you hit it.  Tune per-skill
suppressions with a `.skilleval.yaml` ([docs](docs/3-security-audit.md)).
The audit is *static* — an A grade means "no obvious issues against
~35 finding codes / ~70 regex patterns", not "safe to run untrusted".
`skillctl eval report` combines it with deterministic schema-contract
validation (80% audit + 20% contract) for a reproducible governance score.

---

## Use one skill across your editors

Each IDE has its own conventions:

| IDE          | Project path                         | Frontmatter |
|--------------|--------------------------------------|-------------|
| Claude Code  | `.claude/skills/<name>/SKILL.md`     | passthrough |
| Cursor       | `.cursor/rules/<name>.mdc`           | `description`, `globs`, `alwaysApply` |
| Windsurf     | `.windsurf/rules/<name>.md`          | `trigger: always_on \| glob \| manual \| model_decision` |
| GitHub Copilot | `.github/instructions/<name>.instructions.md` | `applyTo: "<glob>"` |
| Kiro         | `.kiro/steering/<name>.md`           | `inclusion`, `fileMatchPattern` |

`skillctl install` writes the right primary file and frontmatter for every
target. Complete artifact support files are installed beside `SKILL.md` for
Claude Code. Single-file IDE formats retain them in a versioned
`.skillctl-artifacts/` sidecar and report that location explicitly.

`--target all` detects editors already present in the workspace. Name targets
explicitly to create their files in a new project.

```bash
skillctl install ./my-skill --target all                    # auto-detect
skillctl install ./my-skill --target cursor,windsurf,kiro   # specific
skillctl install ./my-skill --target claude --global        # user-level
skillctl uninstall ./my-skill --target all
```

---

## Install

```bash
pip install skillsops                  # core CLI
pip install "skillsops[server]"        # + the registry server
pip install "skillsops[plugin]"        # + MCP runtime for the separately installed Claude Code plugin
pip install "skillsops[observability]" # + OpenTelemetry tracing
pip install "skillsops[policy-opa]"    # + OPA policy integration
pip install "skillsops[all]"           # everything

# The LLM-driven optimizer is now a separate, optional package:
pip install skillsops-optimize         # authoring-time optimizer (pulls in litellm)
```

Python 3.10+.  The core CLI has only one dependency (`pyyaml`); the
server and plugin are optional extras.  The optimizer ships separately
(`skillsops-optimize`) because authoring assistance is a different
concern from governance gatekeeping.

---

## Where it fits

SkillsOps connects checks, versions, and distribution around the same skill.
Use it to reduce the scripts you maintain between those steps:

| Without SkillsOps | With SkillsOps |
|---|---|
| Bash script that copies SKILL.md to `.claude/skills/`, `.cursor/rules/`, `.windsurf/rules/`, `.github/instructions/`, `.kiro/steering/`, each with different frontmatter | `skillctl install ./my-skill --target all` |
| `gitleaks` + a list of "things people said agents shouldn't do" + a CI script | `skillctl eval audit --fail-on-warning` |
| `bumpversion` config + a `git tag` script + ad-hoc changelog | `skillctl bump`, `skillctl diff`, `skillctl logs` |
| Skills shipped to a vendor, or no central store at all | `skillctl serve` on your own host |
| Ad-hoc "does the schema look right?" review before merging | `skillctl eval report` (deterministic 80% audit + 20% contract) |

The benefit is having a shared workflow: review a skill, save a version,
and install it through the same CLI. Dedicated security scanners and eval
frameworks can complement it; the static audit detects known patterns and
does not guarantee that a skill is safe to execute.

---

## Documentation

| Document | Purpose |
|----------|---------|
| [docs/0-architecture.md](docs/0-architecture.md) | System overview, module map, data flow diagrams |
| [docs/1-skill-format.md](docs/1-skill-format.md) | Full CLI reference, skill format, registry server, eval suite, API endpoints |
| [docs/3-security-audit.md](docs/3-security-audit.md) | Audit categories, severities, suppression workflow |
| [docs/rbac.md](docs/rbac.md) | RBAC: roles, permissions, namespaces, CLI, bootstrap, audit |
| [docs/runtime-policy.md](docs/runtime-policy.md) | Experimental opt-in policy hooks and OpenTelemetry |
| [docs/compliance.md](docs/compliance.md) | Experimental non-certifying control mappings |
| [docs/deployment.md](docs/deployment.md) | Experimental local rollout state model |
| [docs/enterprise.md](docs/enterprise.md) | Experimental identity, ABAC, lineage, forensics, and federation utilities |
| [SECURITY.md](SECURITY.md) | Threat model, controls, and how to report vulnerabilities |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to set up a dev environment and send a PR |
| [CHANGELOG.md](CHANGELOG.md) | Version history and release notes |

---

## Verify your setup

```bash
skillctl doctor    # Python, deps, store, registry, IDE targets
skillctl version   # current version
```

---

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,server,plugin,observability]"
pytest tests/ -m "not integration"  # unit and local integration tests
pytest tests/e2e                   # real local filesystem/server/crypto E2E
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for project conventions.

---

## Status

Beta (`0.1.0b9`).  The core CLI surface (`apply`, `install`, `validate`,
`eval audit`, `eval report`, `bump`, `diff`, `get`, `describe`, `delete`,
`serve`, `logs`) is covered by 796 non-E2E tests and 43 real local
end-to-end tests.  The registry's REST API
shape and the `skillctl:` frontmatter block may change before `1.0.0`
based on user feedback.  The optimizer now lives in the separate
`skillsops-optimize` package with its own test and dependency lifecycle.

## License

[MPL-2.0](LICENSE) — see the [LICENSE](LICENSE) file for the full text.
