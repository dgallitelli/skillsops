# Release Readiness — Production-Proof Candidate

Date: 2026-09-09
Version: `0.1.0b9`
Branch: `codex/b9-production-proof`
Base: `origin/main@32a30f2`

## Decision

**Pass for local beta qualification.** The stable CLI, registry, artifact,
recovery, and RBAC paths passed. Merge or publication should still wait for a
live GitHub-backend exercise and hosted CI to confirm its Python
3.10/3.11/3.12/3.13 matrix and Docker Compose job.

The policy, observability, compliance, deployment, identity/ABAC,
lineage/forensics, federation, and generated CI surfaces remain experimental
or preview. They are not release-blocking enforcement claims.

## Qualification results

| Gate | Result |
|---|---|
| Non-E2E suite, including Git backend | 795 passed |
| Git storage backend | 13 passed, including retry, conflict, rejection, and rollback |
| Local end-to-end suite with server/plugin/OTel extras | 43 passed with deprecations treated as errors |
| Extracted optimizer unit suite | 111 passed, 3 external-provider tests deselected |
| Registry migration, restart, backup/restore, corruption repair, process ownership, and archive-adversarial coverage | Passed within the suites above |
| Ruff lint | Passed for the full checkout |
| Ruff format | 156 files clean |
| Production type check | `pyright skillctl/ plugin/scripts/mcp_server.py --pythonversion 3.10`: 0 errors |
| Dependency audit | `pip-audit`: no known vulnerabilities; local optimizer package was not on PyPI and was skipped |
| Dogfood security audit | Three shipped examples passed with grade A and zero warnings/critical findings |
| Package build | sdist and wheel built successfully |
| Package metadata | `twine check`: passed for both artifacts |
| Distribution contents | Wheel has 115 entries; sdist has 193 and includes the separate Claude plugin bundle; neither contains bytecode/cache files |
| Non-editable wheel install | CLI version/help and registry-server import passed in a fresh Python 3.13 venv |
| Container | Rebuilt on Python 3.12, booted as `appuser`, and reported API and storage health `ok` at version `0.1.0b9` |
| Compose | This host has no Compose plugin; `docker compose config` remains blocking in CI |

## Remaining risks and follow-ups

1. This host has Docker Engine but no Compose plugin. The file was
   structurally parsed here; the new hosted CI job is the authoritative Compose
   validation.
2. Local execution covered Python 3.13 and the Python 3.12 container. Python
   3.10, 3.11, and 3.12 package tests rely on the blocking hosted matrix.
3. Local Git repositories proved conflicts, retries, rejections, and rollback,
   but no disposable live GitHub repository has been authorized for the
   network-backed exercise.
4. External optimizer/provider tests were not run. The obsolete core Bedrock
   test was removed because that integration moved to the separate optimizer
   package.
5. TestClient/AnyIO compatibility is now enforced by running the E2E suite
   with deprecation warnings treated as errors.
6. A broad, non-blocking Pyright scan of tests and examples reports existing
   annotation debt. CI now type-checks both `skillctl/` and the shipped MCP
   server; test-only annotation debt remains non-blocking.
7. SQLite and filesystem persistence remain a single-node/single-process
   operational design. Startup now rejects a second process sharing the data
   directory; high availability still requires external transactional
   metadata, blob, and audit services.

## Release controls now in CI

- Core tests run on Python 3.10, 3.11, 3.12, and 3.13 without excluding Git
  backend coverage.
- The 43-test local E2E suite is blocking with all required optional
  dependencies installed.
- Publishing repeats tests, E2E, lint, format, type checking, package build,
  and metadata validation before PyPI trusted publishing.
- Build smoke validates wheel contents and installs the wheel in a fresh
  environment.
- Container smoke validates Compose, image build, registry boot, and health.
