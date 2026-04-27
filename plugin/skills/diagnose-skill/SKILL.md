---
name: diagnose-skill
description: >
  Interpret skillctl evaluation results and fix audit findings, functional failures, or trigger issues.
  Use when reviewing eval output, debugging why a skill failed evaluation, understanding finding codes,
  or improving a skill's score. Triggers on "fix audit", "why did eval fail", "improve score",
  "skill findings", or "diagnose skill".
---

# Diagnose Skill Issues

You have access to skillctl MCP tools. Use them to investigate and fix skill problems.

## Diagnosing audit findings

Run `skillctl_eval_audit` and examine the findings. Each finding has a code, severity, and fix hint.

### Finding code families

| Prefix | Category | Examples |
|--------|----------|----------|
| STR-*  | Structure | Missing SKILL.md, bad directory layout, missing frontmatter |
| SEC-*  | Security | Hardcoded secrets, URL injection, unsafe shell commands, data exfiltration patterns |
| PERM-* | Permissions | Overly broad allowed-tools, undeclared capabilities, dangerous tool combinations |

### Severity levels

- **CRITICAL**: blocks publishing, must fix. Security vulnerabilities, data exfiltration risks.
- **WARNING**: degrades score significantly. Best practice violations, missing metadata.
- **INFO**: minor suggestions. Style improvements, optional metadata.

### Common fixes

**SEC-001 (hardcoded secret)**: Remove the secret, use a parameter or environment variable instead.
**SEC-003 (URL injection)**: Validate URLs, restrict to known domains via `.skilleval.yaml` safe_domains.
**PERM-001 (overly broad tools)**: Narrow `allowed-tools` to specific patterns like `Bash(git *)` instead of `Bash(*)`.
**STR-001 (missing SKILL.md)**: Create the file — every skill needs it.
**STR-017 (no frontmatter)**: Add YAML frontmatter with at least a `description` field.

## Diagnosing functional eval failures

Run `skillctl_eval_functional` and examine the benchmark.json output.

Each eval case scores on four dimensions:
- **Outcome** (40%): did the skill produce the correct result?
- **Process** (30%): did it follow the right steps?
- **Style** (20%): is the output well-formatted and clear?
- **Efficiency** (10%): did it avoid unnecessary work?

Low outcome scores mean the skill's instructions are unclear or incomplete.
Low process scores mean the skill is getting the right answer the wrong way.

## Diagnosing trigger failures

Run `skillctl_eval_trigger` and examine precision/recall.

- **Low recall**: the skill's description doesn't match enough relevant queries. Broaden the description.
- **Low precision**: the skill activates on irrelevant queries. Make the description more specific.
- Both: the description needs a complete rewrite focusing on the core use case.

## Improvement workflow

1. Run `skillctl_eval_report` to get the baseline unified score
2. Identify the weakest dimension (audit/functional/trigger)
3. Fix the specific issues found
4. Re-run the relevant eval to confirm improvement
5. If score is still low, consider `skillctl_optimize` for automated improvement

## Comparing versions

Use `skillctl_diff` with two `namespace/name@version` refs to see what changed between versions.
The diff highlights metadata changes, breaking changes (removed params/capabilities), and content diffs.
