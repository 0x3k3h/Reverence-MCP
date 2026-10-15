"""PE / PE32+ analysis for Windows .exe/.dll/.sys via `pefile`.

Reports headers, sections (with per-section entropy), imports, exports,
security mitigations (ASLR/DEP/CFG/SEH), Authenticode signing state, TLS
callbacks, embedded PDB path, and a short list of suspicious indicators.
The file is parsed as data; it is never loaded or executed.
"""

from __future__ import annotations

import datetime as _dt
from pathlib import Path

from ..util import AnalysisError, human_size, truncate_note

try:
    import pefile
except ImportError:  # pragma: no cover
    pefile = None


_MACHINE = {
    0x014C: "x86 (I386)",
    0x8664: "x86-64 (AMD64)",
    0x01C0: "ARM",
    0x01C4: "ARMv7 (Thumb)",
    0xAA64: "ARM64",
    0x0200: "IA64",
    0x5032: "RISC-V 32",
    0x5064: "RISC-V 64",
}
_SUBSYSTEM = {
    1: "Native (driver)",
    2: "Windows GUI",
    3: "Windows Console (CUI)",
    5: "OS/2 CUI",
    7: "POSIX CUI",
    9: "Windows CE GUI",
    10: "EFI application",
    14: "Xbox",
}


def _require():
    if pefile is None:
        raise AnalysisError("pefile is not installed. `pip install pefile`.")


def _mitigations(dllchars: int) -> list[str]:
    flags = {
        0x0020: "HIGH_ENTROPY_VA (64-bit ASLR)",
        0x0040: "DYNAMIC_BASE (ASLR)",
        0x0080: "FORCE_INTEGRITY",
        0x0100: "NX_COMPAT (DEP)",
        0x0200: "NO_ISOLATION",
        0x0400: "NO_SEH",
        0x0800: "NO_BIND",
        0x1000: "APPCONTAINER",
        0x2000: "WDM_DRIVER",
        0x4000: "GUARD_CF (Control Flow Guard)",
        0x8000: "TERMINAL_SERVER_AWARE",
    }
    on = [name for bit, name in flags.items() if dllchars & bit]
    # Call out notable *missing* protections
    missing = []
    if not (dllchars & 0x0040):
        missing.append("no ASLR")
    if not (dllchars & 0x0100):
        missing.append("no DEP")
    if not (dllchars & 0x4000):
        missing.append("no CFG")
    result = on[:]
    if missing:
        result.append("WEAK: " + ", ".join(missing))
    return result


def pe_info(path_str: str, max_imports: int = 300, max_exports: int = 300) -> str:
    _require()
    p = Path(path_str)
    try:
        pe = pefile.PE(str(p), fast_load=True)
    except pefile.PEFormatError as e:
        raise AnalysisError(f"Not a valid PE file: {e}")

    pe.parse_data_directories(directories=[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"],
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"],
    ])

    fh = pe.FILE_HEADER
    oh = pe.OPTIONAL_HEADER
    machine = _MACHINE.get(fh.Machine, f"0x{fh.Machine:04x}")
    is_dll = bool(fh.Characteristics & 0x2000)
    is_driver = bool(oh.Subsystem == 1)
    ts = fh.TimeDateStamp
    try:
        ts_str = _dt.datetime.fromtimestamp(ts, _dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OSError, OverflowError, ValueError):
        ts_str = "invalid/zeroed"

    out: list[str] = []
    out.append(f"PE: {p.name}")
    out.append(f"  type        : {'DLL' if is_dll else ('driver' if is_driver else 'EXE')}")
    out.append(f"  machine     : {machine}")
    out.append(f"  magic       : {'PE32+' if oh.Magic == 0x20B else 'PE32'}")
    out.append(f"  subsystem   : {_SUBSYSTEM.get(oh.Subsystem, oh.Subsystem)}")
    out.append(f"  entrypoint  : 0x{oh.AddressOfEntryPoint:08x} (RVA)")
    out.append(f"  image base  : 0x{oh.ImageBase:x}")
    out.append(f"  image size  : {human_size(oh.SizeOfImage)}")
    out.append(f"  timestamp   : {ts_str} (0x{ts:08x})")
    out.append(f"  imphash     : {pe.get_imphash() or '(none)'}")
    out.append(f"  mitigations : {', '.join(_mitigations(oh.DllCharacteristics)) or '(none set)'}")

    # Authenticode (does a certificate table exist?)
    try:
        sec = oh.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
        signed = sec.VirtualAddress != 0 and sec.Size != 0
        out.append(f"  signed      : {'yes — embedded certificate table present' if signed else 'no cert table'}"
                   f"{f' ({human_size(sec.Size)})' if signed else ''}")
    except Exception:
        pass

    # Embedded PDB path (CodeView debug record)
    pdb = _pdb_path(pe)
    if pdb:
        out.append(f"  pdb         : {pdb}")

    # TLS callbacks (a classic anti-debug / early-exec vector)
    tls = _tls_callbacks(pe, oh.ImageBase)
    if tls:
        out.append(f"  TLS callbacks: {', '.join(hex(a) for a in tls)}")

    # Sections
    out.append("")
    out.append(f"Sections ({len(pe.sections)}):")
    out.append("  name      vaddr      vsize      rawsize    entropy  flags")
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode("latin-1", "replace") or "(unnamed)"
        ent = s.get_entropy()
        warn = " PACKED?" if ent >= 7.2 else ""
        wx = ""
        ch = s.Characteristics
        if (ch & 0x20000000) and (ch & 0x80000000):  # EXEC + WRITE
            wx = " W^X-VIOLATION(RWX)"
        out.append(
            f"  {name:<9} 0x{s.VirtualAddress:08x} 0x{s.Misc_VirtualSize:08x} "
            f"0x{s.SizeOfRawData:08x} {ent:6.3f}{warn}{wx}"
        )

    # Imports
    out.append("")
    out.append(_imports_block(pe, max_imports))

    # Exports
    exp = _exports_block(pe, max_exports)
    if exp:
        out.append("")
        out.append(exp)

    pe.close()
    return "\n".join(out)


def _pdb_path(pe) -> str | None:
    try:
        for dbg in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []):
            entry = getattr(dbg, "entry", None)
            if entry is not None and hasattr(entry, "PdbFileName"):
                return entry.PdbFileName.rstrip(b"\x00").decode("latin-1", "replace")
    except Exception:
        pass
    return None


def _tls_callbacks(pe, image_base: int) -> list[int]:
    out = []
    try:
        tls = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
        if tls and tls.struct.AddressOfCallBacks:
            rva = tls.struct.AddressOfCallBacks - image_base
            data = pe.get_data(rva, 64)
            ptr_size = 8 if pe.OPTIONAL_HEADER.Magic == 0x20B else 4
            for i in range(0, len(data), ptr_size):
                val = int.from_bytes(data[i : i + ptr_size], "little")
                if val == 0:
                    break
                out.append(val)
    except Exception:
        pass
    return out


def _imports_block(pe, limit: int) -> str:
    entries = getattr(pe, "DIRECTORY_ENTRY_IMPORT", None)
    if not entries:
        return "Imports: none (static binary, or import directory stripped/packed)"
    lines = ["Imports:"]
    shown = 0
    total = 0
    for dll in entries:
        dll_name = dll.dll.decode("latin-1", "replace") if dll.dll else "(unknown)"
        funcs = dll.imports or []
        total += len(funcs)
        names = []
        for imp in funcs:
            if shown >= limit:
                break
            if imp.name:
                names.append(imp.name.decode("latin-1", "replace"))
            else:
                names.append(f"#ordinal {imp.ordinal}")
            shown += 1
        lines.append(f"  {dll_name}  ({len(funcs)}): {', '.join(names)}")
        if shown >= limit:
            break
    lines.append(f"  [total imported symbols: {total}]")
    tail = truncate_note(shown, total, "import symbols")
    return "\n".join(lines) + tail


def _exports_block(pe, limit: int) -> str:
    exp = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if not exp:
        return ""
    syms = exp.symbols or []
    lines = [f"Exports ({len(syms)}):"]
    for s in syms[:limit]:
        name = s.name.decode("latin-1", "replace") if s.name else f"#ordinal {s.ordinal}"
        lines.append(f"  0x{s.address:08x}  ord={s.ordinal}  {name}")
    return "\n".join(lines) + truncate_note(min(limit, len(syms)), len(syms), "exports")
