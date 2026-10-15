"""Optional radare2 bridge via r2pipe.

Opens targets read-only and in *static* mode only (never -d / debug). A guard
rejects the debug command family so a target is never run under this tool.
Requires the external `radare2` (`r2`) binary and the r2pipe package.
"""

from __future__ import annotations

from pathlib import Path

from ..util import AnalysisError

try:
    import r2pipe
except ImportError:  # pragma: no cover
    r2pipe = None

# Debug-family prefixes that could execute the target; refused outright.
_FORBIDDEN = ("d", "ood", "doo", "=!")


def _require():
    if r2pipe is None:
        raise AnalysisError(
            "r2pipe is not installed. `pip install r2pipe` and install radare2 "
            "(https://github.com/radareorg/radare2)."
        )


def _is_forbidden(cmd: str) -> bool:
    c = cmd.strip()
    if not c:
        return True
    # Debug subsystem in r2 is the 'd' command family.
    first = c.split()[0]
    if first.startswith("d") and first not in ("db?",):  # all 'd*' are debug
        return True
    return any(tok in c for tok in ("ood", "doo", "=!"))


def r2_run(path_str: str, commands: list[str], analyze: bool = True) -> str:
    """Run a sequence of static r2 commands and return concatenated output.

    Examples of useful static commands:
      iI (info), ii (imports), iE (exports), iz (strings in data),
      afl (list functions, needs analyze), pdf @ main (disasm function),
      axt @ sym.foo (xrefs), / <bytes> (search).
    """
    _require()
    p = Path(path_str)
    for cmd in commands:
        if _is_forbidden(cmd):
            raise AnalysisError(
                f"Refused command '{cmd}': this tool is static-only and blocks the "
                f"radare2 debug command family."
            )
    r2 = r2pipe.open(str(p), flags=["-2"])  # -2 silences stderr; no -d
    try:
        out = []
        if analyze:
            r2.cmd("aaa")  # full static analysis
        for cmd in commands:
            res = r2.cmd(cmd)
            out.append(f"$ {cmd}\n{res.rstrip()}")
        return "\n\n".join(out) if out else "(no output)"
    finally:
        r2.quit()
