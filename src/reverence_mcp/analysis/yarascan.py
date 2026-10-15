"""Optional YARA scanning (yara-python).

Match a target against inline rules or a .yar rules file. Rules are compiled
and run against the file as data.
"""

from __future__ import annotations

from pathlib import Path

from ..util import AnalysisError

try:
    import yara
except ImportError:  # pragma: no cover
    yara = None


def _require():
    if yara is None:
        raise AnalysisError("yara-python is not installed. `pip install yara-python`.")


def yara_scan(path_str: str, rules_source: str | None = None, rules_file: str | None = None) -> str:
    _require()
    if not rules_source and not rules_file:
        raise AnalysisError("Provide either rules_source (inline YARA) or rules_file (path to .yar).")
    try:
        rules = yara.compile(filepath=rules_file) if rules_file else yara.compile(source=rules_source)
    except yara.SyntaxError as e:
        raise AnalysisError(f"YARA rule syntax error: {e}")

    target = Path(path_str)
    matches = rules.match(str(target))
    if not matches:
        return f"No YARA matches in {target.name}."

    out = [f"{len(matches)} rule(s) matched {target.name}:"]
    for m in matches:
        out.append(f"\nrule {m.rule}  tags={list(m.tags)}  meta={dict(m.meta)}")
        strings = getattr(m, "strings", []) or []
        for s in strings[:50]:
            # Newer yara-python: StringMatch with .identifier and .instances
            if hasattr(s, "instances"):
                for inst in s.instances[:20]:
                    data = bytes(inst.matched_data)[:32]
                    out.append(f"    {s.identifier} @ 0x{inst.offset:x}: {data!r}")
            else:  # legacy tuple (offset, identifier, data)
                try:
                    off, ident, data = s
                    out.append(f"    {ident} @ 0x{off:x}: {bytes(data)[:32]!r}")
                except Exception:
                    out.append(f"    {s}")
    return "\n".join(out)
