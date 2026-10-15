"""Optional decompilation via Ghidra's headless analyzer.

Enabled when Ghidra is available (GHIDRA_HOME env var or `ghidra_home` arg).
Imports the target into a throwaway project, runs auto-analysis, and exports
pseudo-C with a bundled Ghidra script. Ghidra analyzes statically; the target
is not executed.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from ..util import AnalysisError

_SCRIPT_DIR = Path(__file__).resolve().parent.parent / "ghidra_scripts"
_SCRIPT_NAME = "DecompileExport.py"


def _find_ghidra(ghidra_home: str | None) -> Path:
    home = ghidra_home or os.environ.get("GHIDRA_HOME") or os.environ.get("GHIDRA_INSTALL_DIR")
    if not home:
        raise AnalysisError(
            "Ghidra not configured. Set GHIDRA_HOME to your Ghidra install directory "
            "(the folder containing support/analyzeHeadless), or pass ghidra_home."
        )
    home_p = Path(home)
    exe = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
    headless = home_p / "support" / exe
    if not headless.exists():
        raise AnalysisError(f"analyzeHeadless not found at {headless}. Check GHIDRA_HOME.")
    return headless


def decompile(
    path_str: str,
    function: str | None = None,
    ghidra_home: str | None = None,
    timeout: int = 900,
) -> str:
    """Decompile `function` (by name/address) or the whole program to pseudo-C.

    Returns the decompiled text. Analysis of a large binary can take minutes.
    """
    headless = _find_ghidra(ghidra_home)
    target = Path(path_str).resolve()

    if not _SCRIPT_DIR.exists():
        raise AnalysisError(f"Bundled Ghidra script dir missing: {_SCRIPT_DIR}")

    work = Path(tempfile.mkdtemp(prefix="reverence_ghidra_"))
    out_file = work / "decompiled.c"
    try:
        script_args = [str(out_file), function or "__ALL__"]
        cmd = [
            str(headless),
            str(work),
            "reverence_tmp",
            "-import", str(target),
            "-scriptPath", str(_SCRIPT_DIR),
            "-postScript", _SCRIPT_NAME, *script_args,
            "-deleteProject",
            "-analysisTimeoutPerFile", str(max(60, timeout - 60)),
        ]
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            cwd=str(work),
        )
        if out_file.exists():
            text = out_file.read_text(encoding="utf-8", errors="replace")
            note = "" if text.strip() else "\n(no decompiler output — function not found?)"
            return (f"Ghidra decompilation of {target.name}"
                    f"{f' :: {function}' if function else ' (all functions)'}\n"
                    f"{'=' * 60}\n{text}{note}")
        # No output file — surface analyzer logs to help diagnose.
        tail = (proc.stdout or "")[-2000:] + "\n" + (proc.stderr or "")[-2000:]
        raise AnalysisError(f"Ghidra produced no output. Analyzer log tail:\n{tail}")
    except subprocess.TimeoutExpired:
        raise AnalysisError(f"Ghidra analysis timed out after {timeout}s.")
    finally:
        shutil.rmtree(work, ignore_errors=True)
