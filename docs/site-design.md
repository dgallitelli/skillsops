# Landing page design

This pass applies [Taste](https://github.com/Leonxlnx/taste-skill/blob/main/skills/taste-skill/SKILL.md)
to the existing marketing site. It does not add a registry application UI.

## Audit

The starting page uses warm white `#fafaf9`, dark ink `#1c1917`, emerald
`#047857`, Inter / Inter Tight, JetBrains Mono, and small rounded containers.
Its identity is the SkillsOps wordmark and a direct, practical copy voice.
Navigation links to `#problem`, `#capabilities`, `#governance`, and
`#quickstart`. Older `#journey` and `#lifecycle` anchors still resolve.
The conversion path is a local CLI installation.

The first screen is mostly text. Three equal benefit cards, four workflow
cards, and eleven capability cards repeat the same composition. Experimental
utilities compete with everyday tasks. The quickstart requires manual edits
before it can pass. Copy buttons report success even when clipboard access
fails. Content is hidden until JavaScript reveals it. Styles and fonts require
third-party requests. No analytics, structured data, or social image was found
in the starting HTML; the title and description establish the SEO baseline.

## Direction

Preserve the brand, existing anchor IDs, navigation labels, and MPL-2.0
licensing. Use an asymmetric hero with a real CLI capture, an unboxed workflow,
a tabbed product demonstration, a team section, and a runnable quickstart.
Keep advanced capability details accessible in a native disclosure.

- `DESIGN_VARIANCE: 6`: varied composition with familiar navigation.
- `MOTION_INTENSITY: 3`: feedback on interaction; no automatic motion.
- `VISUAL_DENSITY: 4`: concise introductions with details available on demand.
- Native HTML/CSS/JS suits the existing static GitHub Pages deployment.
- Geist and Geist Mono are self-hosted under their included OFL licenses.
- The existing emerald accent is retained, with a lighter dark-mode equivalent.
- Rounded corners are 8px for controls and media; text groups have no boxes.
- System light/dark preference controls the entire page.
- The only elevated layer is the sticky navigation (`z-index: 10`).

## Product evidence

The images are captures of real command output from the included
`examples/code-reviewer` skill, not invented screenshots or generated scores.
`scripts/capture_site_examples.py` runs the CLI in temporary storage, saves the
complete transcripts, renders them with Rich, and captures the output with
Chromium. Light and dark images use the same transcript. A deterministic zip
contains the unmodified example files for the quickstart.

No stock photography or AI imagery is needed: actual CLI output is the useful
visual evidence for this product. React, motion libraries, and icon libraries
are unnecessary for this static page. Readable text labels replace icons.

## Verification

Check desktop, tablet, and narrow mobile layouts in both themes. Exercise
keyboard tabs, native disclosures, copy success and failure, anchor navigation,
reduced-motion preference, and JavaScript-disabled rendering. Run the exact
quickstart against an extracted download. Check local resource links and run
Lighthouse before publishing.

Results for this pass:

- Browser checks passed at 320, 390, 768, 1024, and 1440px in both themes.
- Axe reported no WCAG A/AA violations in either theme at the narrowest size.
- Keyboard tabs, disclosures, clipboard success/failure, download, and
  JavaScript-disabled reading were checked.
- The downloaded archive matched the example source; validation, audit,
  local storage, and both editor installations passed without manual edits.
- Local mobile Lighthouse scored 100 for performance, accessibility,
  best practices, and SEO: LCP 1.7s, CLS 0, total blocking time 0ms.
  These are lab measurements, not production field metrics.
