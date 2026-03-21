# Roadmap: skillctl

## Overview

skillctl delivers a governance-first CLI and registry for agent skills in three phases: first a complete single-developer experience (validate, scan, store locally), then a self-hostable team registry server, and finally organization-scale distribution via pub/sub channels and a TypeScript SDK. Each phase is self-contained and shippable. Together they constitute the public v0.1.0 release.

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [ ] **Phase 1: CLI and Local Governance** - Single-developer tool: init, validate, scan, push/pull, diff, dependencies, local registry
- [ ] **Phase 2: Registry Server** - Self-hostable team registry with auth, publish/search, and audit logging
- [ ] **Phase 3: Distribution and Release Readiness** - Pub/sub channels, TypeScript SDK, and v0.1.0 release polish

## Phase Details

### Phase 1: CLI and Local Governance
**Goal**: A single developer can create, validate, security-scan, version-diff, and locally store skills with full governance enforcement -- no network required
**Depends on**: Nothing (first phase)
**Requirements**: CLI-01, CLI-02, CLI-03, CLI-04, CLI-05, CLI-06, CLI-07, FMT-01, FMT-02, FMT-03, FMT-04, FMT-05, VAL-01, VAL-02, VAL-03, VAL-04, VAL-05, VAL-06, SEC-01, SEC-02, SEC-03, SEC-04, SEC-05, SEC-06, SEC-07, SEC-08, SEC-09, SEC-10, REG-01, REG-02, REG-03, REG-04, REG-05, DIF-01, DIF-02, DIF-03, DEP-01, DEP-02, DEP-03, QAL-01, QAL-04, QAL-05
**Success Criteria** (what must be TRUE):
  1. Developer can run `skillctl init && skillctl validate && skillctl push` on a new skill in under 2 minutes
  2. `skillctl scan` catches all 8 security detection patterns (SKL-S001 through SKL-S008) against the 50+ case test corpus
  3. `skillctl diff` between two skill versions correctly flags breaking changes (removed parameters, narrowed types) with visible red highlighting
  4. `skillctl doctor` diagnoses and reports all known environment failure modes (missing auth, unreachable registry, corrupt store)
  5. Three or more example skills in /examples pass both `skillctl validate` and `skillctl scan`
**Plans**: TBD

Plans:
- [ ] 01-01: TBD
- [ ] 01-02: TBD
- [ ] 01-03: TBD

### Phase 2: Registry Server
**Goal**: Teams can deploy a self-hosted registry in under 10 minutes and use it to publish, search, and audit skills remotely
**Depends on**: Phase 1
**Requirements**: SRV-01, SRV-02, SRV-03, SRV-04, SRV-05, SRV-06, SRV-07, SRV-08, SRV-09, SRV-10, SRV-11, QAL-02
**Success Criteria** (what must be TRUE):
  1. `docker compose up` starts a working registry server with zero external dependencies
  2. `skillctl publish` uploads a validated skill to the remote registry and `skillctl pull` retrieves it over HTTP
  3. `skillctl search` returns matching skills from the remote registry filtered by namespace, tag, or query string
  4. Every mutating operation (publish, delete) is recorded in the append-only audit log with actor, timestamp, and HMAC signature
  5. Token-based auth correctly scopes access: read-only tokens cannot publish, namespace-scoped tokens cannot write to other namespaces
**Plans**: TBD

Plans:
- [ ] 02-01: TBD
- [ ] 02-02: TBD

### Phase 3: Distribution and Release Readiness
**Goal**: Organizations can subscribe to skill channels for automatic distribution, TypeScript consumers can integrate via SDK, and the project meets all v0.1.0 launch criteria
**Depends on**: Phase 2
**Requirements**: PUB-01, PUB-02, PUB-03, PUB-04, PUB-05, PUB-06, PUB-07, PUB-08, PUB-09, PUB-10, PUB-11, SDK-01, SDK-02, SDK-03, QAL-03, QAL-06, QAL-07, QAL-08
**Success Criteria** (what must be TRUE):
  1. Subscriber webhook receives a `skill.published` event within 5 seconds of `skillctl channel publish`
  2. Breaking change in a new skill version is detected and blocks auto-update on the channel (requires --force-breaking to override)
  3. `@skillctl/sdk` npm package can connect to the registry, list skills, and subscribe to channel events from TypeScript
  4. README quickstart works end-to-end on macOS and Linux (install to first published skill in under 15 minutes)
  5. `govulncheck ./...` is clean, license headers are present in all source files, and CHANGELOG.md is current
**Plans**: TBD

Plans:
- [ ] 03-01: TBD
- [ ] 03-02: TBD

## Progress

**Execution Order:**
Phases execute in numeric order: 1 -> 2 -> 3

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. CLI and Local Governance | 0/3 | Not started | - |
| 2. Registry Server | 0/2 | Not started | - |
| 3. Distribution and Release Readiness | 0/2 | Not started | - |
