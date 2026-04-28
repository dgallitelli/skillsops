# Landing Page Design

**Date:** 2026-04-28
**Goal:** Single-page landing site for skillsops at dgallitelli.github.io/skillctl/

## Architecture

Single `index.html` in `site/` directory, deployed to `gh-pages` branch via GitHub Actions. Tailwind CSS via CDN. No build tools.

## Sections

1. **Hero**: "SkillsOps" headline, tagline, pip install CTA (click-to-copy), blog + GitHub buttons
2. **Problem**: 3 cards (no quality gate, no eval data, copy-paste across IDEs)
3. **Lifecycle**: horizontal pipeline (create → validate → audit → eval → optimize → publish → install)
4. **Features**: 6 cards in 2x3 grid (security, multi-IDE, SKILL.md, optimizer, export/import, Claude Code plugin)
5. **Quickstart**: dark code block with 5-command flow
6. **Footer**: GitHub, PyPI, blog, license links

## Style

Dark theme (#0f172a base), Tailwind CSS CDN, accent color from logo, clean typography, generous whitespace.

## Deployment

GitHub Actions workflow: on push to main, copies `site/index.html` to gh-pages branch. Pages serves from gh-pages root.

## CTAs (priority order)

1. `pip install skillsops` (hero, click-to-copy)
2. Read the blog series (hero button + footer)
3. Star on GitHub (hero button + footer)
