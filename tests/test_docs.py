"""Drift tests for the documentation site.

Every fenced bash block in docs/ that references tests/fixtures/ must run
cleanly from the repository root. The pages quote exact CLI output, so a
behavior change that breaks a documented command breaks this test instead of
shipping silently.

Blocks are skipped, with the reason recorded in the test id report, when they
need a tool that is not installed (wat2wasm, jq, xxd on minimal dev boxes) or
reference a script the page tells the reader to create by hand (scan_dir.py,
/tmp/make_component.py, and friends). CI runners have jq and xxd preinstalled,
so the full set runs there.
"""

import os
import re
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
_DOCS_DIR = _REPO_ROOT / "docs"

_BASH_BLOCK_RE = re.compile(r"```bash\n(.*?)\n?```", re.DOTALL)
# Tools that documented blocks may invoke but a minimal env may lack. CI
# installs with pip, so poetry is absent there; wat2wasm and jq/xxd depend on
# the runner image.
_OPTIONAL_TOOLS = ("jq", "xxd", "wat2wasm", "poetry")
# Scripts that lessons instruct the reader to write themselves.
_READER_CREATED_SCRIPT_RE = re.compile(r"\b[\w./-]+\.py\b")


def _extract_blocks() -> list[tuple[str, int, str]]:
    """Return (page, block_index, code) for every bash fence in docs/."""
    blocks: list[tuple[str, int, str]] = []
    for page in sorted(_DOCS_DIR.glob("*.md")):
        text = page.read_text(encoding="utf-8")
        for index, match in enumerate(_BASH_BLOCK_RE.finditer(text)):
            blocks.append((page.name, index, match.group(1)))
    return blocks


def _skip_reason(code: str) -> str | None:
    if "tests/fixtures" not in code:
        return "no fixture reference"
    for tool in _OPTIONAL_TOOLS:
        # Skip only when the tool is actually invoked, not merely mentioned.
        if re.search(rf"(^|\s|/|;|&&|\|){tool}\s", code) and not shutil.which(tool):
            return f"{tool} not installed"
    # The fixture build script shells out to wat2wasm internally, so the word
    # regex above cannot see the dependency.
    if "tests/fixtures/build.py" in code and not shutil.which("wat2wasm"):
        return "wat2wasm not installed (fixture rebuild)"
    for match in _READER_CREATED_SCRIPT_RE.finditer(code):
        script = match.group(0)
        if not Path(script).exists() and not (_REPO_ROOT / script).exists():
            return f"reader-created script {script}"
    return None


@pytest.fixture(scope="module")
def cli_shim(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Expose wasm-tools on PATH without requiring an installed console script."""
    bin_dir = tmp_path_factory.mktemp("bin")
    shim = bin_dir / "wasm-tools"
    shim.write_text(
        textwrap.dedent(
            """\
            #!/usr/bin/env bash
            exec "${PYTHON:-python3}" -m wasm_tools.cli "$@"
            """
        ),
        encoding="utf-8",
    )
    shim.chmod(0o755)
    return bin_dir


@pytest.mark.parametrize(
    "page,index,code",
    [
        pytest.param(page, index, code, id=f"{page}#{index}")
        for page, index, code in _extract_blocks()
    ],
)
def test_documented_bash_block_runs_clean(
    page: str, index: int, code: str, cli_shim: Path
) -> None:
    reason = _skip_reason(code)
    if reason is not None:
        pytest.skip(reason)

    env = {
        **os.environ,
        "PATH": f"{cli_shim}{os.pathsep}{os.environ['PATH']}",
        "PYTHONPATH": str(_REPO_ROOT),
    }
    result = subprocess.run(
        ["bash", "-c", "set -o pipefail\n" + code],
        cwd=_REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, (
        f"{page} bash block #{index} failed (exit {result.returncode}):\n"
        f"{code}\n--- stderr ---\n{result.stderr}"
    )
