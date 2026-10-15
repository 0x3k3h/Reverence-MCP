"""Disassembly via Capstone.

Two entry points:
  * disassemble()        — raw window at a file offset, explicit or auto arch.
  * disassemble_entry()  — resolve a PE/ELF entry point to its file offset and
                           virtual address, then disassemble from there.
Capstone decodes bytes; it does not run them.
"""

from __future__ import annotations

import struct
from pathlib import Path

from ..util import AnalysisError, read_bytes

try:
    import capstone
except ImportError:  # pragma: no cover
    capstone = None

# name -> (cs arch, cs mode)
_ARCH_TABLE = {}


def _build_table():
    if not _ARCH_TABLE and capstone is not None:
        _ARCH_TABLE.update({
            "x86": (capstone.CS_ARCH_X86, capstone.CS_MODE_32),
            "x64": (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
            "arm": (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
            "thumb": (capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB),
            "arm64": (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
        })


def _require():
    if capstone is None:
        raise AnalysisError("capstone is not installed. `pip install capstone`.")
    _build_table()


def detect_arch(p: Path) -> str:
    """Guess a Capstone arch key ('x86','x64','arm','arm64') from file headers."""
    head = read_bytes(p, 0, 64)
    if head[:2] == b"MZ" and len(head) >= 0x40:
        pe_off = struct.unpack_from("<I", head, 0x3C)[0]
        m = read_bytes(p, pe_off, 6)
        if m[:4] == b"PE\x00\x00":
            machine = struct.unpack_from("<H", m, 4)[0]
            return {0x014C: "x86", 0x8664: "x64", 0x01C0: "arm",
                    0x01C4: "thumb", 0xAA64: "arm64"}.get(machine, "x64")
    if head[:4] == b"\x7fELF":
        is64 = head[4] == 2
        little = head[5] == 1
        e_machine = struct.unpack_from("<H" if little else ">H", head, 18)[0]
        return {3: "x86", 62: "x64", 40: "arm", 183: "arm64"}.get(
            e_machine, "x64" if is64 else "x86")
    # Mach-O
    if head[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
        cpu = struct.unpack_from("<I", head, 4)[0]
        return {0x7: "x86", 0x01000007: "x64", 0xC: "arm", 0x0100000C: "arm64"}.get(cpu, "x64")
    return "x64"


def _disasm_bytes(code: bytes, arch: str, base: int, limit: int) -> str:
    cs_arch, cs_mode = _ARCH_TABLE[arch]
    md = capstone.Cs(cs_arch, cs_mode)
    md.detail = False
    lines = []
    n = 0
    for insn in md.disasm(code, base):
        lines.append(f"  0x{insn.address:08x}  {insn.bytes.hex():<20} {insn.mnemonic:<9} {insn.op_str}")
        n += 1
        if n >= limit:
            break
    if not lines:
        return "(capstone produced no instructions — wrong arch, data region, or packed code?)"
    return "\n".join(lines)


def disassemble(
    path_str: str,
    offset: int = 0,
    count: int = 64,
    arch: str = "auto",
    base_addr: int | None = None,
) -> str:
    _require()
    p = Path(path_str)
    if arch == "auto":
        arch = detect_arch(p)
    if arch not in _ARCH_TABLE:
        raise AnalysisError(f"Unknown arch '{arch}'. Choose from: {', '.join(_ARCH_TABLE)} or 'auto'.")
    count = max(1, min(count, 2000))
    # Read enough bytes: up to 16 bytes/instr for x86.
    code = read_bytes(p, offset, count * 16)
    base = base_addr if base_addr is not None else offset
    header = f"disasm {arch} @ file offset 0x{offset:x} (display base 0x{base:x}), up to {count} insns:\n"
    return header + _disasm_bytes(code, arch, base, count)


def disassemble_entry(path_str: str, count: int = 80) -> str:
    """Resolve and disassemble a PE or ELF entry point."""
    _require()
    p = Path(path_str)
    head = read_bytes(p, 0, 4)

    if head[:2] == b"MZ":
        return _entry_pe(p, count)
    if head[:4] == b"\x7fELF":
        return _entry_elf(p, count)
    raise AnalysisError("Entry-point resolution supports PE and ELF. "
                        "For other formats use the disassemble tool with an explicit offset.")


def _entry_pe(p: Path, count: int) -> str:
    try:
        import pefile
    except ImportError:
        raise AnalysisError("pefile needed for PE entry-point resolution.")
    pe = pefile.PE(str(p), fast_load=True)
    ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    image_base = pe.OPTIONAL_HEADER.ImageBase
    try:
        file_off = pe.get_offset_from_rva(ep_rva)
    except Exception:
        raise AnalysisError("Could not map entry-point RVA to a file offset (packed?).")
    arch = detect_arch(p)
    va = image_base + ep_rva
    pe.close()
    code = read_bytes(p, file_off, count * 16)
    header = (f"PE entry point: RVA 0x{ep_rva:x} -> file 0x{file_off:x}, VA 0x{va:x}, arch {arch}\n")
    return header + _disasm_bytes(code, arch, va, count)


def _entry_elf(p: Path, count: int) -> str:
    try:
        import lief
    except ImportError:
        raise AnalysisError("lief needed for ELF entry-point resolution.")
    b = lief.parse(str(p))
    if b is None:
        raise AnalysisError("lief could not parse this ELF.")
    va = b.entrypoint
    file_off = None
    try:
        file_off = b.virtual_address_to_offset(va)
    except Exception:
        # Manual segment walk
        for seg in b.segments:
            start = seg.virtual_address
            if start <= va < start + seg.virtual_size:
                file_off = seg.file_offset + (va - start)
                break
    if file_off is None:
        raise AnalysisError("Could not map ELF entry VA to a file offset.")
    arch = detect_arch(p)
    code = read_bytes(p, int(file_off), count * 16)
    header = f"ELF entry point: VA 0x{va:x} -> file 0x{int(file_off):x}, arch {arch}\n"
    return header + _disasm_bytes(code, arch, va, count)
