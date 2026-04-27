---
name: create-skill
description: >
  Scaffold and author new agent skills with proper skill.yaml and SKILL.md structure.
  Use when the user wants to create a new skill, write a skill from scratch, or convert
  instructions into a skill. Triggers on "create skill", "new skill", "write a skill",
  "scaffold skill", or "make a skill".
---

# Create a New Skill

You have access to skillctl MCP tools. Use `skillctl_create` to scaffold, then help the user fill in the content.

## Workflow

### 1. Scaffold

Ask the user for:
- **Name**: must be `namespace/skill-name` format (lowercase, hyphens ok)
- **Description**: one sentence explaining what the skill does

Then run `skillctl_create` with the name. This generates:
- `skill.yaml` with apiVersion, kind, metadata, and spec stubs
- `SKILL.md` with a placeholder body

### 2. Write the skill content

Help the user write the SKILL.md body. A good skill has:

- **Clear scope**: one task or knowledge domain per skill
- **Actionable instructions**: steps Claude can follow, not vague guidance
- **Tool awareness**: if the skill needs specific tools, declare them in `spec.capabilities`
- **Parameters**: if the skill needs user input, define typed parameters in `spec.parameters`

### 3. Fill in metadata

Update skill.yaml with:
- `version`: start at `0.1.0` for drafts
- `tags`: for discoverability (e.g., `[security, review]`)
- `capabilities`: what tools the skill needs (`read_file`, `write_file`, `network_access`, `exec`, `read_code`)
- `parameters`: any configurable values (name, type, required, default, description)

### 4. Validate

Run `skillctl_validate` on the skill directory. Fix any issues.

### 5. Initial audit

Run `skillctl_eval_audit` to catch security issues early. Common problems in new skills:
- Hardcoded URLs or API keys (SEC-*)
- Overly broad tool permissions (PERM-*)
- Missing structure files (STR-*)

## Skill format reference

```yaml
apiVersion: skillctl.io/v1
kind: Skill
metadata:
  name: namespace/skill-name
  version: 1.0.0
  description: What the skill does
  authors:
    - name: Author Name
  tags: [tag1, tag2]
spec:
  content:
    path: SKILL.md
  capabilities:
    - read_file
    - write_file
  parameters:
    - name: param_name
      type: string
      required: false
      default: "value"
      description: What it controls
```
