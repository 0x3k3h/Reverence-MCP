"""File identification: format sniffing by magic bytes, hashes, entropy.

Deliberately dependency-free (no libmagic) so it works out of the box on
Windows. Covers the formats a reverse engineer meets most often.
"""

from __future__ import annotations

import struct
from pathlib import Path

from ..util import (
    file_hashes,
    human_size,
    read_bytes,
    shannon_entropy,
)


def _match_magic(head: Path, data: bytes) -> str:
    """Best-effort format label from the first bytes of a file."""
    # (signature-at-offset-0 checks first)
    sigs: list[tuple[bytes, str]] = [
        (b"MZ", "DOS/PE executable (Windows .exe/.dll/.sys — MZ header)"),
        (b"\x7fELF", "ELF (Linux/Unix executable or shared object)"),
        (b"\xca\xfe\xba\xbe", "Mach-O universal (fat) binary / Java class"),
        (b"\xcf\xfa\xed\xfe", "Mach-O 64-bit (little-endian)"),
        (b"\xce\xfa\xed\xfe", "Mach-O 32-bit (little-endian)"),
        (b"\xfe\xed\xfa\xcf", "Mach-O 64-bit (big-endian)"),
        (b"\xfe\xed\xfa\xce", "Mach-O 32-bit (big-endian)"),
        (b"\x00asm", "WebAssembly module (.wasm)"),
        (b"dex\n", "Android Dalvik DEX"),
        (b"PK\x03\x04", "ZIP archive (also .jar/.apk/.docx/.nupkg)"),
        (b"PK\x05\x06", "ZIP archive (empty)"),
        (b"Rar!\x1a\x07", "RAR archive"),
        (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
        (b"\x1f\x8b", "gzip stream"),
        (b"\xfd7zXZ\x00", "XZ stream"),
        (b"BZh", "bzip2 stream"),
        (b"\x89PNG\r\n\x1a\n", "PNG image"),
        (b"GIF8", "GIF image"),
        (b"\xff\xd8\xff", "JPEG image"),
        (b"%PDF", "PDF document"),
        (b"\xed\xab\xee\xdb", "RPM package"),
        (b"!<arch>\n", "ar archive / .deb / static .a library"),
        (b"\xd0\xcf\x11\xe0", "OLE2 / MS Compound File (legacy .doc/.xls, MSI)"),
        (b"<?xml", "XML document"),
        (b"#!", "Script with shebang"),
    ]
    for sig, label in sigs:
        if data.startswith(sig):
            # Refine .NET vs native for PE and fat-mach vs java-class
            if sig == b"MZ":
                return _refine_pe(label, data)
            if sig == b"\xca\xfe\xba\xbe":
                # Java class files are also CAFEBABE; distinguish by next bytes.
                if len(data) >= 8 and data[4:6] == b"\x00\x00":
                    return "Java .class file"
                return label
            return label

    # Text heuristics
    sample = data[:4096]
    if b"\x00" not in sample:
        try:
            sample.decode("utf-8")
            return "Text / source (UTF-8, no format magic)"
        except UnicodeDecodeError:
            pass
    return "Unknown / raw binary (no recognized magic)"


def _refine_pe(label: str, data: bytes) -> str:
    """Read the PE header offset at 0x3c and report machine + .NET if present."""
    try:
        if len(data) < 0x40:
            return label
        pe_off = struct.unpack_from("<I", data, 0x3C)[0]
        if len(data) < pe_off + 24 or data[pe_off : pe_off + 4] != b"PE\x00\x00":
            return "DOS MZ executable (no PE header — 16-bit or stub)"
        machine = struct.unpack_from("<H", data, pe_off + 4)[0]
        characteristics = struct.unpack_from("<H", data, pe_off + 22)[0]
        machines = {
            0x014C: "x86 (32-bit)",
            0x8664: "x86-64 (64-bit)",
            0x01C0: "ARM",
            0xAA64: "ARM64",
            0x0200: "IA-64",
        }
        arch = machines.get(machine, f"machine 0x{machine:04x}")
        kind = "DLL" if (characteristics & 0x2000) else "EXE"
        return f"PE32{'+' if machine == 0x8664 else ''} {kind} — {arch} (Windows)"
    except Exception:
        return label


def identify(path_str: str) -> str:
    p = Path(path_str)
    size = p.stat().st_size
    # Read enough to reach the PE header (e_lfanew at 0x3c can point past 0x100)
    # and to run the text heuristics on a real sample.
    head = read_bytes(p, 0, 4096)
    fmt = _match_magic(p, head)
    hashes = file_hashes(p)

    # Whole-file entropy on a bounded sample (first + last window) is cheap and
    # usually enough to flag packing.
    sample = read_bytes(p, 0, min(size, 8 * 1024 * 1024))
    ent = shannon_entropy(sample)
    packed = ""
    if ent >= 7.2:
        packed = "  <- high: likely packed/compressed/encrypted"
    elif ent >= 6.5:
        packed = "  <- elevated"

    out = [
        f"File:    {p.resolve()}",
        f"Size:    {human_size(size)} ({size} bytes)",
        f"Format:  {fmt}",
        "",
        f"MD5:     {hashes['md5']}",
        f"SHA1:    {hashes['sha1']}",
        f"SHA256:  {hashes['sha256']}",
        "",
        f"Entropy: {ent:.3f} bits/byte (sampled {human_size(len(sample))}){packed}",
        "",
        "First bytes:",
        "  " + " ".join(f"{b:02x}" for b in head[:32]),
    ]
    return "\n".join(out)
