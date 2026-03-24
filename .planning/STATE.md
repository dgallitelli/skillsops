# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-03-22)

**Core value:** No skill reaches production without passing through a governance gate
**Current focus:** Phase 1 complete, all v0.1.0 and v0.3.0 phases done

## Current Position

Phase: 5 of 7 complete (Phases 1, 2, 3, 6, 7 done; Phases 4, 5 not started)
Status: v0.1.0 and v0.3.0 shipped; v0.2.0 not started
Last activity: 2026-03-24 — Documentation update, cross-referencing README against implementation

Progress: [███████░░░] ~70% (5 of 7 phases complete)

## Performance Metrics

**Velocity:**
- Total plans completed: 12 (estimated across 5 phases)
- Average duration: ~2 hours per plan
- Total execution time: ~24 hours

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| 1. CLI and Local Governance | 3 | ~6h | ~2h |
| 2. Registry Server | 2 | ~5h | ~2.5h |
| 3. Eval Suite | 2 | ~5h | ~2.5h |
| 6. Skill Optimizer | 2 | ~4h | ~2h |
| 7. Optimization Governance | 1 | ~2h | ~2h |

**Recent Trend:**
- Last 5 plans: Phase 6 and 7 plans — optimizer loop, provenance, governance
- Trend: Stable velocity, ~2h per plan

*Updated: 2026-03-24*

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
Recent decisions affecting current work:

- [Scope]: Build on OSS eval patterns (MIT-0) instead of building eval from scratch
- [Scope]: Eval suite moves to v0.1.0, pub/sub moves to v0.2.0
- [Scope]: Skills gateway is part of skillctl (v0.2.0), not a separate product
- [Scope]: A-F eval grades map to certification tiers (verified/community/rejected)
- [Scope]: LLM-as-judge (Anthropic API) layered on top of deterministic eval
- [Roadmap]: 7 phases total — 3 for v0.1.0 (CLI + Registry + Eval), 2 for v0.2.0 (Gateway + PubSub/Governance), 2 for v0.3.0 (Optimizer + Opt Governance)
- [Scope]: Agent Identity + Observability moved to Out of Scope (cloud-layer candidate, crowded space)
- [Roadmap]: Coarse granularity, quality model profile (Opus for planning agents)
- [Scope]: v0.3.0 adds automated skill optimization (autoresearch pattern) — eval as reward signal, LLM-generated variants, failure-driven improvement
- [Tech]: Python/FastAPI instead of Go — faster iteration, same team expertise
- [Scope]: Web UI built despite being listed as "out of scope" — too useful to skip; HTMX-based, lightweight
- [Tech]: GitHub backend added as storage option — skills stored as directories in a git repo, full version history via commits
- [Auth]: Device flow auth (OAuth 2.0) instead of PAT-only — `skillctl login` opens browser, polls for token
- [Format]: Multi-file archive support for skills — .zip and .tar.gz uploads via Web UI and API

### Key References

- CLAUDE.md: Full technical spec (1051 lines)
- OSS eval patterns: MIT-0 licensed eval framework (fork target)
- Melanie Li research: Lightweight skills improve F1 by 34%; heavyweight degrade performance
- Platform engineering analysis: 7 pillars (registry, approval, gateway, identity, audit, shadow detection, composability)

### Pending Todos

- Phase 4 (Skills Gateway) and Phase 5 (Pub/Sub, SDK, Governance) are not started — these form the v0.2.0 milestone.

### Blockers/Concerns

None active.

## Session Continuity

Last session: 2026-03-24
Stopped at: Documentation update complete. Next work would be Phase 4 (Skills Gateway) or Phase 5 (Pub/Sub).
Resume file: None
