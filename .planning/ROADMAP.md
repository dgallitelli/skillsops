# Roadmap: skillctl

## Overview

skillctl delivers a governance-first CLI, registry, and evaluation platform for agent skills in three milestone releases. v0.1.0 covers the full "validate, evaluate, distribute" story: a CLI for local governance, a self-hosted registry for teams, and an eval suite with certification grading. v0.2.0 adds registry-side policy enforcement, approval workflows, webhook notifications, and deprecation management. v0.3.0 closes the loop with automated skill optimization — using eval as a reward signal to iteratively improve skills without human supervision.

## Phases

**Phase Numbering:**
- Phases 1-3: v0.1.0 milestone
- Phases 4-5: v0.2.0 milestone (merged into single Phase 4)
- Phase 6-7: v0.3.0 milestone
- Decimal phases (e.g. 2.1): Urgent insertions (marked with INSERTED)

- [x] **Phase 1: CLI and Local Governance** - Single-developer tool: init, validate, scan, push/pull, diff, dependencies, local registry
- [x] **Phase 2: Registry Server** - Self-hostable team registry with auth, publish/search, and audit logging
- [x] **Phase 3: Eval Suite** - Eval engine with LLM-as-judge, certification grades, registry integration
- [ ] **Phase 4: Registry Governance** - Publish policies, approval workflows, webhook notifications, deprecation, namespace rules
- [x] **Phase 5: Skill Optimizer** - Automated improvement loop: eval → failure analysis → variant generation → promotion
- [x] **Phase 6: Optimization Governance** - Audit, provenance, cost controls, and registry integration for optimization runs

## Phase Details

### Phase 1: CLI and Local Governance
**Goal**: A single developer can create, validate, security-scan, version-diff, and locally store skills with full governance enforcement -- no network required
**Depends on**: Nothing (first phase)
**Requirements**: CLI-01 to CLI-07, FMT-01 to FMT-06, VAL-01 to VAL-06, SEC-01 to SEC-10, REG-01 to REG-05, DIF-01 to DIF-03, DEP-01 to DEP-03, QAL-01, QAL-04, QAL-05
**Success Criteria** (what must be TRUE):
  1. Developer can run `skillctl init && skillctl validate && skillctl push` on a new skill in under 2 minutes
  2. `skillctl scan` catches all 8 security detection patterns (SKL-S001 through SKL-S008) against the 50+ case test corpus
  3. `skillctl diff` between two skill versions correctly flags breaking changes (removed parameters, narrowed types) with visible red highlighting
  4. `skillctl doctor` diagnoses and reports all known environment failure modes
  5. Three or more example skills in /examples pass both `skillctl validate` and `skillctl scan`
**Plans**: Complete

Plans:
- [x] 01-01: CLI foundation (init, validate, push, pull, list, version, doctor)
- [x] 01-02: Skill format, validation, security scanning
- [x] 01-03: Diff, local store, examples

### Phase 2: Registry Server
**Goal**: Teams can deploy a self-hosted registry in under 10 minutes and use it to publish, search, and audit skills remotely
**Depends on**: Phase 1
**Requirements**: SRV-01 to SRV-11, QAL-02
**Success Criteria** (what must be TRUE):
  1. `docker compose up` starts a working registry server with zero external dependencies
  2. `skillctl publish` uploads a validated skill to the remote registry and `skillctl pull` retrieves it over HTTP
  3. `skillctl search` returns matching skills from the remote registry filtered by namespace, tag, or query string
  4. Every mutating operation (publish, delete) is recorded in the append-only audit log with actor, timestamp, and HMAC signature
  5. Token-based auth correctly scopes access: read-only tokens cannot publish, namespace-scoped tokens cannot write to other namespaces
**Plans**: Complete

Plans:
- [x] 02-01: FastAPI server, API endpoints, auth, storage, audit log
- [x] 02-02: Web UI, GitHub backend, device flow auth, Docker

### Phase 3: Eval Suite
**Goal**: Developers can evaluate skill quality across safety, functional correctness, and trigger reliability — with A-F certification grades stored in the registry
**Depends on**: Phase 2 (registry integration for storing eval reports)
**Requirements**: EVL-01 to EVL-12, QAL-03, QAL-06, QAL-07, QAL-08
**Success Criteria** (what must be TRUE):
  1. `skillctl eval audit` scans a skill and produces an A-F grade using the 100-point scoring system
  2. `skillctl eval functional` compares agent performance with vs without a skill and reports quality delta
  3. `skillctl eval report` produces a unified score (40% audit, 40% functional, 20% trigger) with certification tier
  4. `skillctl eval regression` detects score drops between two skill versions and exits non-zero
  5. Eval reports are stored in the registry alongside skill metadata and retrievable via `skillctl show --eval`
**Plans**: Complete

Plans:
- [x] 03-01: Audit, functional, trigger evaluation engines
- [x] 03-02: Unified report, regression, compare, lifecycle, HTML reports

### Phase 4: Registry Governance (v0.2.0)
**Goal**: Platform teams can enforce publish policies, approval workflows, and namespace rules on the registry — ensuring no skill reaches production without meeting governance requirements
**Depends on**: Phase 2 (registry server), Phase 3 (eval suite for grade-gated policies)
**Requirements**: GOV-01 to GOV-10 (re-scoped from original GW + PUB + GOV requirements)
**Success Criteria** (what must be TRUE):
  1. Publish policies enforce minimum eval grade per namespace (e.g., `prod/` requires grade B+)
  2. Approval workflows: skills land in `pending` state, require N approvals before going live
  3. Webhook notifications fire on skill lifecycle events (published, deleted, eval attached, approved)
  4. `skillctl deprecate` marks a skill with a sunset date; registry warns on pull after sunset
  5. Namespace rules: configurable per-namespace policies (who can publish, minimum grade, required tags)
  6. `skillctl policy check` evaluates custom YAML-based rules against skill content
  7. `skillctl audit` shows full event history with time-range filtering and JSON export

**Scope (merged from original Phases 4 + 5, re-scoped):**
- Publish gates: minimum eval grade, required tags, namespace restrictions
- Approval workflows: pending state, `skillctl approve`, role-based authorization
- Webhook notifications: registry POSTs events to subscriber URLs on lifecycle changes
- Deprecation: `skillctl deprecate` with sunset date, warnings on pull
- Namespace policies: YAML-based rules per namespace
- Custom policy engine: simple YAML rule evaluation (not full OPA/Rego — keep it lightweight)
- Audit enhancements: time-range filtering, JSON export, event replay

**Descoped from original Phase 4 (Skills Gateway):**
- MCP server proxy — out of scope (no MCP servers in this implementation)
- Agent identity / per-agent permissions — cloud-layer candidate
- OpenTelemetry spans — cloud-layer candidate
- Rate limiting per agent — cloud-layer candidate

**Descoped from original Phase 5:**
- TypeScript SDK — deferred (can be a community contribution)
- EventBus interface / Kafka/SQS — cloud-layer candidate
- Channel management (pub/sub channels) — replaced by webhook notifications
- Event replay (30 days) — deferred to cloud layer

Plans:
- [ ] 04-01: Publish policies and namespace rules (YAML-based policy engine, grade gates, tag requirements)
- [ ] 04-02: Approval workflows (pending state, approve/reject CLI commands, role-based auth)
- [ ] 04-03: Webhook notifications (subscriber registration, lifecycle event dispatch)
- [ ] 04-04: Deprecation and audit enhancements (sunset dates, time-range filtering, JSON export)

### Phase 5: Skill Optimizer (v0.3.0)
**Goal**: Developers can run `skillctl optimize` to automatically improve a skill's eval score through iterative failure analysis and LLM-generated variants — overnight, unattended
**Depends on**: Phase 3 (eval suite provides scoring infrastructure)
**Requirements**: OPT-01 to OPT-12
**Success Criteria** (what must be TRUE):
  1. `skillctl optimize` reads eval failures, generates 3 variants, evaluates them, and promotes the best — in a single automated loop
  2. An optimization run of 10 iterations on a skill with 20 test scenarios completes without human intervention
  3. Plateau detection correctly halts optimization when 3 consecutive cycles produce no improvement
  4. Cost budget enforcement stops the run before exceeding the configured USD limit
  5. Every promoted variant has a full provenance chain: parent version → failure analysis → hypothesis → eval report → promotion decision
**Plans**: Complete

Plans:
- [x] 06-01: Optimization loop, failure analyzer, variant generator, promotion gate
- [x] 06-02: Budget tracking, LLM client, provenance store

### Phase 6: Optimization Governance (v0.3.0)
**Goal**: Platform teams have full visibility and control over automated skill optimization — audit trails, cost tracking, and publish gates
**Depends on**: Phase 5 (optimizer engine), Phase 2 (registry for audit/publish)
**Requirements**: OPG-01 to OPG-05
**Success Criteria** (what must be TRUE):
  1. Every optimization run is recorded in the audit log with trigger, iteration count, score delta, cost, and promoted version
  2. Optimized skills carry `metadata.optimized_from` linking to source version and run ID
  3. `--dry-run` executes the full loop without promoting or publishing any variant
  4. Registry rejects optimized skills that haven't passed a full eval after optimization (eval-gated publish)
**Plans**: Complete

Plans:
- [x] 07-01: Audit integration, provenance chain, dry-run, eval-gated publish

## Progress

**Execution Order:**
v0.1.0: 1 → 2 → 3
v0.2.0: 4 (depends on Phase 2 + 3)
v0.3.0: 5 (depends on Phase 3) → 6 (depends on Phase 5 + Phase 2)

| Phase | Plans Complete | Status | Milestone | Completed |
|-------|----------------|--------|-----------|-----------|
| 1. CLI and Local Governance | 3/3 | Complete | v0.1.0 | 2026-03-23 |
| 2. Registry Server | 2/2 | Complete | v0.1.0 | 2026-03-23 |
| 3. Eval Suite | 2/2 | Complete | v0.1.0 | 2026-03-23 |
| 4. Registry Governance | 0/4 | Not started | v0.2.0 | - |
| 5. Skill Optimizer | 2/2 | Complete | v0.3.0 | 2026-03-24 |
| 6. Optimization Governance | 1/1 | Complete | v0.3.0 | 2026-03-24 |
