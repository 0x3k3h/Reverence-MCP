"""ELF and Mach-O analysis via LIEF.

LIEF's API has shifted between releases, so every field access is defensive:
we prefer the documented attribute and fall back rather than crash the tool.
Static parse only — nothing is loaded or executed.
"""

from __future__ import annotations

from pathlib import Path

from ..util import AnalysisError, truncate_note

try:
    import lief
except ImportError:  # pragma: no cover
    lief = None


def _require():
    if lief is None:
        raise AnalysisError("lief is not installed. `pip install lief`.")


def _fmt_name(binary) -> str:
    try:
        return str(binary.format).split(".")[-1]
    except Exception:
        return "?"


def _safe(fn, default="?"):
    try:
        v = fn()
        return v if v is not None else default
    except Exception:
        return default


def _list_block(title: str, items, limit: int, render) -> str:
    items = list(items)
    lines = [f"{title} ({len(items)}):"]
    for it in items[:limit]:
        try:
            lines.append("  " + render(it))
        except Exception:
            continue
    return "\n".join(lines) + truncate_note(min(limit, len(items)), len(items), title.lower())


def _elf_report(b, limit: int) -> str:
    h = b.header
    out = [f"ELF: {_safe(lambda: str(h.file_type).split('.')[-1])}"]
    out.append(f"  arch       : {_safe(lambda: str(h.machine_type).split('.')[-1])}")
    out.append(f"  class      : {_safe(lambda: str(h.identity_class).split('.')[-1])}")
    out.append(f"  endian     : {_safe(lambda: str(h.identity_data).split('.')[-1])}")
    out.append(f"  entrypoint : 0x{_safe(lambda: b.entrypoint, 0):x}")
    out.append(f"  PIE        : {_safe(lambda: b.is_pie)}")
    out.append(f"  NX         : {_safe(lambda: b.has_nx)}")
    if _safe(lambda: b.has_interpreter, False):
        out.append(f"  interpreter: {_safe(lambda: b.interpreter)}")

    libs = _safe(lambda: list(b.libraries), [])
    if libs:
        out.append("")
        out.append("Needed libraries:\n  " + "\n  ".join(str(x) for x in libs))

    out.append("")
    out.append(_list_block(
        "Sections", _safe(lambda: b.sections, []), limit,
        lambda s: f"0x{s.virtual_address:08x} {s.size:>8} {str(s.type).split('.')[-1]:<14} {s.name}",
    ))
    out.append("")
    out.append(_list_block(
        "Imported functions", _safe(lambda: b.imported_functions, []), limit,
        lambda f: str(getattr(f, 'name', f)),
    ))
    out.append("")
    out.append(_list_block(
        "Exported functions", _safe(lambda: b.exported_functions, []), limit,
        lambda f: str(getattr(f, 'name', f)),
    ))
    return "\n".join(out)


def _macho_report(b, limit: int) -> str:
    h = b.header
    out = [f"Mach-O: {_safe(lambda: str(h.file_type).split('.')[-1])}"]
    out.append(f"  cpu        : {_safe(lambda: str(h.cpu_type).split('.')[-1])}")
    out.append(f"  entrypoint : 0x{_safe(lambda: b.entrypoint, 0):x}")
    out.append(f"  PIE        : {_safe(lambda: b.is_pie)}")
    out.append(f"  NX         : {_safe(lambda: b.has_nx)}")
    if _safe(lambda: b.has_code_signature, False):
        out.append("  signed     : yes (code signature load command present)")

    libs = _safe(lambda: [l.name for l in b.libraries], [])
    if libs:
        out.append("")
        out.append("Linked libraries:\n  " + "\n  ".join(str(x) for x in libs))

    out.append("")
    out.append(_list_block(
        "Segments", _safe(lambda: b.segments, []), limit,
        lambda s: f"0x{s.virtual_address:012x} {s.virtual_size:>10} {s.name}",
    ))
    out.append("")
    out.append(_list_block(
        "Imported functions", _safe(lambda: b.imported_functions, []), limit,
        lambda f: str(getattr(f, 'name', f)),
    ))
    out.append("")
    out.append(_list_block(
        "Exported functions", _safe(lambda: b.exported_functions, []), limit,
        lambda f: str(getattr(f, 'name', f)),
    ))
    return "\n".join(out)


def lief_info(path_str: str, limit: int = 300, want: str | None = None) -> str:
    """Parse an ELF or Mach-O. `want` optionally asserts the format (elf/macho)."""
    _require()
    p = Path(path_str)
    binary = lief.parse(str(p))
    if binary is None:
        raise AnalysisError("LIEF could not parse this file as ELF/PE/Mach-O.")

    # Mach-O fat binaries: lief returns a FatBinary; report each slice.
    if binary.__class__.__name__ == "FatBinary" or hasattr(binary, "at"):
        try:
            slices = list(binary)
        except TypeError:
            slices = [binary.at(i) for i in range(binary.size)]
        reports = []
        for i, sl in enumerate(slices):
            reports.append(f"=== Mach-O slice {i} ===\n" + _macho_report(sl, limit))
        return "\n\n".join(reports)

    fmt = _fmt_name(binary)
    if want == "elf" and fmt != "ELF":
        raise AnalysisError(f"Expected ELF, but this file is {fmt}.")
    if want == "macho" and fmt != "MACHO":
        raise AnalysisError(f"Expected Mach-O, but this file is {fmt}.")

    if fmt == "ELF":
        return _elf_report(binary, limit)
    if fmt == "MACHO":
        return _macho_report(binary, limit)
    if fmt == "PE":
        raise AnalysisError("This is a PE file — use the pe_info tool for full detail.")
    raise AnalysisError(f"Unsupported format for this tool: {fmt}")
