# SkillsOps Stabilization Plan

1. ✅ **Secure registry boundaries** — Eliminate legacy-token privilege escalation, bind every artifact to one immutable authorization namespace, enforce lifecycle visibility, and add regression coverage.
2. ✅ **Make governance fail closed** — Ensure evaluation and promotion gates fail on missing or errored evidence, correct misleading compliance outcomes, and distinguish reports from enforceable controls.
3. ✅ **Preserve complete skill artifacts** — Replace the single-`SKILL.md` storage contract with immutable bundles containing the manifest, instructions, supporting files, hashes, and provenance.
4. ✅ **Repair release paths** — Make Docker and Compose boot successfully, run end-to-end tests in CI, remove stale integrations, and align versions, coverage claims, and documentation.
5. ✅ **Harden registry architecture** — Centralize authorization and lifecycle transitions, introduce explicit persistence migrations, and add concurrency and recovery coverage.
6. ✅ **Constrain enterprise modules** — Mark non-enforcing runtime, deployment, compliance, federation, identity, lineage, and forensics features experimental until their trust boundaries are integrated and tested.
7. ✅ **Qualify the stabilized release** — Run the complete test, type, lint, packaging, container, security, and upgrade matrices and document remaining release risks.
8. ✅ **Cut the beta candidate** — Bump core and plugin metadata to `0.1.0b8`, finalize the changelog, and update release documentation.
9. ✅ **Requalify release artifacts** — Re-run tests and static gates, then build and inspect the `0.1.0b8` wheel and source distribution.
10. ✅ **Prepare reviewable commits** — Commit implementation and release metadata in coherent units without pushing or tagging.
11. ✅ **Open the release PR** — Push `codex/p0-stabilization` and open a pull request against `main`.
12. ✅ **Clear hosted validation** — Monitor required GitHub checks and repair release-blocking failures if any occur.
13. ✅ **Land and tag the candidate** — Merge the green pull request, tag the resulting release commit as `v0.1.0b8`, and prepare an unpublished GitHub prerelease draft.
14. ✅ **Publish the beta** — Publish the GitHub prerelease, monitor trusted publishing, and verify `0.1.0b8` on PyPI.

## v0.1.0b9 Production-Proof Milestone

15. ✅ **Prove upgrades and recovery** — Exercise legacy database/store upgrades, persistent-volume restarts, backup/restore, and corruption repair.
16. ✅ **Enforce deployment boundaries** — Prevent unsupported multi-worker operation and document the path to coordinated scale-out.
17. ✅ **Close compatibility debt** — Add Python 3.11 CI, resolve upstream test-client warnings where possible, and expand type coverage.
18. 🔄 **Exercise live GitHub infrastructure** — Validate authenticated pushes, conflicts, retries, and rejected updates against a disposable repository.
19. 🔄 **Qualify the b9 milestone** — Run the complete release matrix and prepare evidence-driven follow-up priorities.
