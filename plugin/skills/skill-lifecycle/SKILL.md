---
name: skill-lifecycle
description: >
  Guide the full skill governance lifecycle: validate, security audit, functional eval, optimize, and publish.
  Use when the user is working on agent skills and needs to validate, evaluate, test, or publish them.
  Triggers on mentions of skill quality, skill publishing, skill evaluation, or governance workflows.
---

# Skill Governance Lifecycle

You have access to skillctl MCP tools. Use them to guide the user through the skill governance pipeline.

## Lifecycle stages

Follow this order. Each stage gates the next — do not skip ahead unless the user explicitly asks.

### 1. Validate

Run `skillctl_validate` on the skill directory. Fix any schema errors before proceeding.
Common issues: missing apiVersion, bad semver, missing description, content path vs inline conflict.

### 2. Security audit

Run `skillctl_eval_audit` on the skill. Review the grade (A–F) and findings.
- **A/B grade**: safe to proceed
- **C grade**: review findings with the user, fix CRITICAL items
- **D/F grade**: fix all CRITICAL and WARNING findings before continuing

Help the user understand each finding code (STR-*, SEC-*, PERM-*) and apply the suggested fixes.

### 3. Functional evaluation (optional)

If the skill has `evals/evals.json`, run `skillctl_eval_functional`.
This tests the skill with and without installation, grading on outcome, process, style, and efficiency.

If no evals exist, suggest creating them — offer to help write eval cases.

### 4. Trigger evaluation (optional)

If the skill has `evals/eval_queries.json`, run `skillctl_eval_trigger`.
This measures whether the skill's description causes correct activation (precision and recall).

### 5. Unified report

Run `skillctl_eval_report` to get a combined score (40% audit + 40% functional + 20% trigger).
This gives a single pass/fail decision.

### 6. Optimize (optional)

If the score is below the user's target, suggest `skillctl_optimize`.
This runs an iterative LLM-driven improvement loop that generates variants and promotes the best one.

### 7. Publish

Once the skill passes all gates, run `skillctl_apply` to push to the local store and optionally publish to a registry.
If there are CRITICAL audit findings, `apply` will block — use `--local` to skip the security gate.

## When working with skills in this session

- After any edit to a skill's SKILL.md or skill.yaml, re-run `skillctl_validate` to catch regressions
- After fixing audit findings, re-run `skillctl_eval_audit` to confirm the fix
- Use `skillctl_describe` to inspect a skill's full metadata before making changes
- Use `skillctl_diff` to compare versions when reviewing changes
