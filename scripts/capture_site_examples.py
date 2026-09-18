"""Capture real CLI examples for the static landing page.

Run with the repository importable and Rich + Playwright installed, e.g.:
  PYTHONPATH=/path/to/browser-tools python scripts/capture_site_examples.py
Uses a local Chromium executable from SITE_CHROMIUM when provided.
"""

import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import zipfile

from rich.console import Console
from rich.terminal_theme import TerminalTheme
from playwright.sync_api import sync_playwright

REPO = Path(__file__).resolve().parents[1]
ASSETS = REPO / "site/assets"
EXAMPLE = REPO / "examples/code-reviewer"


def main():
    ASSETS.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(ASSETS / "code-reviewer.zip", "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(EXAMPLE.iterdir()):
            info = zipfile.ZipInfo(f"code-reviewer/{path.name}", (2026, 9, 18, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, path.read_bytes())

    with tempfile.TemporaryDirectory(prefix="skillsops-site-") as temp:
        root = Path(temp)
        workspace = root / "code-reviewer"
        shutil.copytree(EXAMPLE, workspace)
        (root / "user").mkdir()
        bootstrap = (
            "from pathlib import Path; "
            f"Path.home=classmethod(lambda cls: Path({str(root / 'user')!r})); "
            "from skillctl.cli import main; main()"
        )
        env = {k: v for k, v in os.environ.items() if not k.startswith("SKILLCTL_")}
        env["PYTHONPATH"] = str(REPO)

        def run(*args):
            result = subprocess.run(
                [sys.executable, "-c", bootstrap, *args], cwd=workspace,
                env=env, capture_output=True, text=True, check=True,
            )
            return "$ skillctl " + " ".join(args) + "\n" + result.stdout

        audit = run("eval", "audit", ".")
        run("validate")
        run("apply", "--local")
        install = run("install", "my-org/code-reviewer@0.1.0", "--target", "claude,cursor")
        run("bump", "--patch")
        with (workspace / "SKILL.md").open("a") as file:
            file.write("\nCall out missing tests for changes to error handling.\n")
        run("apply", "--local")
        diff = run("diff", "my-org/code-reviewer@0.1.0", "my-org/code-reviewer@0.1.1")

        themes = {
            "light": ((246, 247, 244), (28, 25, 23)),
            "dark": ((31, 35, 32), (237, 239, 233)),
        }
        with sync_playwright() as playwright:
            executable = os.environ.get("SITE_CHROMIUM")
            browser = playwright.chromium.launch(
                executable_path=executable, args=["--no-sandbox"],
            )
            page = browser.new_page(viewport={"width": 960, "height": 1600}, device_scale_factor=1.5)
            for name, output in {"audit": audit, "diff": diff, "install": install}.items():
                (ASSETS / f"{name}.txt").write_text(output)
                for mode, (background, foreground) in themes.items():
                    console = Console(record=True, width=88, file=io.StringIO())
                    console.print(output, markup=False, highlight=False, end="")
                    theme = TerminalTheme(background, foreground, [foreground] * 8)
                    rendered = console.export_html(inline_styles=True, theme=theme)
                    # Render the actual transcript, without simulated window chrome.
                    rendered = rendered.replace("</head>", """<style>
                      body { margin: 0; }
                      pre { padding: 32px; margin: 0; font: 15px/1.7 monospace;
                            white-space: pre-wrap; overflow-wrap: anywhere; }
                    </style></head>""")
                    page.set_content(rendered)
                    page.locator("pre").screenshot(path=str(ASSETS / f"{name}-{mode}.png"))
                print(f"Captured {name}: {len(output.splitlines())} lines")
            browser.close()


if __name__ == "__main__":
    main()
