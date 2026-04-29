# Multi-IDE Installation Guide

`skillctl install` distributes skills from the local store to AI coding IDEs. It handles path resolution, frontmatter translation, conflict detection, and installation tracking across five supported targets.

## Supported Targets

| Target | Project Path | Global Path | File Extension |
|--------|-------------|-------------|----------------|
| **Claude Code** | `.claude/skills/<name>/SKILL.md` | `~/.claude/skills/<name>/SKILL.md` | `.md` |
| **Cursor** | `.cursor/rules/<name>.mdc` | (not supported) | `.mdc` |
| **Windsurf** | `.windsurf/rules/<name>.md` | `~/.codeium/windsurf/memories/global_rules.md` | `.md` |
| **Copilot** | `.github/instructions/<name>.instructions.md` | (not supported) | `.instructions.md` |
| **Kiro** | `.kiro/steering/<name>.md` | `~/.kiro/steering/<name>.md` | `.md` |

## Frontmatter Translation

Each IDE has its own frontmatter schema. `skillctl install` translates the canonical SKILL.md frontmatter to the target format.

### Claude Code (canonical — no translation)

```yaml
---
name: code-reviewer
description: Reviews PRs for security issues
allowed-tools: Read Grep Bash(git:*)
---
```

### Cursor

| Canonical Field | Cursor Field | Notes |
|-----------------|-------------|-------|
| `description` | `description` | Direct mapping |
| `paths` | `globs` | Renamed; converted to array |
| `paths` (without `disable-model-invocation`) | `alwaysApply: false` | Default when paths set but disable not set |
| `disable-model-invocation` | `alwaysApply: false` | Inverted boolean |
| (no paths, no disable) | `alwaysApply: true` | Default when neither is set |

Claude-only fields (`allowed-tools`, `context`, `model`, `agent`, `effort`, `hooks`, `shell`) are dropped with a stderr warning.

### Windsurf

| Canonical Field | Windsurf Field | Notes |
|-----------------|---------------|-------|
| `description` | `description` | Direct mapping |
| `paths` | `trigger: glob` + `globs` | Sets trigger mode |
| `disable-model-invocation` | `trigger: manual` or `model_decision` | Maps to trigger mode |
| (no paths, no disable) | `trigger: always_on` | Default |

### Copilot

| Canonical Field | Copilot Field | Notes |
|-----------------|--------------|-------|
| `paths` | `applyTo` | Comma-joined string |
| (no paths) | (no frontmatter) | Body only, no wrapper |

Copilot uses minimal frontmatter. Most fields are dropped.

### Kiro

| Canonical Field | Kiro Field | Notes |
|-----------------|-----------|-------|
| `name` | `name` | Added explicitly |
| `description` | `description` | Direct mapping |
| `paths` | `inclusion: fileMatch` + `fileMatchPattern` | Sets inclusion mode |
| `disable-model-invocation` | `inclusion: manual` or `auto` | Maps to inclusion mode |
| (no paths, no disable) | `inclusion: always` | Default |

## Auto-Detection

`skillctl install my-org/reviewer@1.0.0 --target all` auto-detects which IDEs are present:

- **Project scope**: Checks for `.claude/`, `.cursor/`, `.windsurf/`, `.github/`, `.kiro/` directories in the current working directory.
- **Global scope** (`--global`): Installs to all targets that support global installation (Claude Code, Windsurf, Kiro).

## Conflict Detection

Before overwriting, the installer checks whether the installed file was modified externally:

1. On install, the SHA-256 hash of the written content is recorded in `~/.skillctl/installations.json`.
2. On subsequent installs, the current file hash is compared against the recorded hash.
3. If they differ (user edited the file), installation is blocked with a message.
4. Use `--force` to overwrite modified files.

## Installation Tracking

All installations are tracked in `~/.skillctl/installations.json`:

```json
{
  "my-org/reviewer@1.0.0": {
    "claude": {
      "path": "/home/user/project/.claude/skills/reviewer/SKILL.md",
      "scope": "project",
      "installed_at": "2026-04-29T10:00:00+00:00",
      "content_hash": "a1b2c3..."
    },
    "cursor": {
      "path": "/home/user/project/.cursor/rules/reviewer.mdc",
      "scope": "project",
      "installed_at": "2026-04-29T10:00:00+00:00",
      "content_hash": "d4e5f6..."
    }
  }
}
```

The tracker uses file locking (`fcntl.LOCK_EX`) and atomic writes (tempfile + `os.replace`) to prevent corruption from concurrent installs.

## CLI Usage

```bash
# Install to specific target
skillctl install my-org/reviewer@1.0.0 --target claude

# Install to all detected IDEs in current project
skillctl install my-org/reviewer@1.0.0 --target all

# Global installation (available in all projects)
skillctl install my-org/reviewer@1.0.0 --target claude --global

# Force overwrite of externally modified files
skillctl install my-org/reviewer@1.0.0 --target all --force

# Preview without writing
skillctl install my-org/reviewer@1.0.0 --target all --dry-run

# Uninstall
skillctl uninstall my-org/reviewer@1.0.0 --target all

# List all installations
skillctl list --installed
```

## Download and Install from URL

```bash
# Download a SKILL.md from a URL, then install
skillctl install --from-url https://example.com/skills/reviewer/SKILL.md --target claude
```

The downloaded skill is sanitized (name extracted from frontmatter, special characters removed) and saved to a local directory before installation.

## Key Source Files

| File | Role |
|------|------|
| `skillctl/install.py` | Target registry, frontmatter translation, install/uninstall logic, conflict detection |
| `skillctl/store.py` | Content-addressed storage that `install` pulls from |
| `skillctl/manifest.py` | `_parse_frontmatter()` used for content parsing |
