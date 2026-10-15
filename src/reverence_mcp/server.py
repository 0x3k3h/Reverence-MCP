"""Reverence MCP server.

Exposes static reverse-engineering tools over MCP (stdio) for Claude Code,
OpenCode, and any other MCP client. Every tool performs static analysis only:
targets are read as data and never executed or loaded.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from . import __version__
from .analysis import binfmt, decompile, disasm, identify, pe, radare, strings, web, yarascan
from .util import AnalysisError, hexdump, read_bytes, resolve_target

mcp = FastMCP("reverence")


def _err(e: Exception) -> str:
    if isinstance(e, AnalysisError):
        return f"[reverence] {e}"
    return f"[reverence] unexpected error: {type(e).__name__}: {e}"


def _have(mod: str) -> bool:
    return importlib.util.find_spec(mod) is not None


# --------------------------------------------------------------------------
# Triage / overview
# --------------------------------------------------------------------------

@mcp.tool()
def capabilities() -> str:
    """List which analysis engines are available in this install.

    Use this first if a tool reports a missing dependency, to see what is
    installed (pefile, lief, capstone, jsbeautifier) and which optional
    external engines are present (radare2/r2pipe, Ghidra, YARA)."""
    import shutil

    rows = [
        ("pefile (PE/DLL)", _have("pefile")),
        ("lief (ELF/Mach-O)", _have("lief")),
        ("capstone (disasm)", _have("capstone")),
        ("jsbeautifier (JS)", _have("jsbeautifier")),
        ("r2pipe (radare2 bridge)", _have("r2pipe")),
        ("radare2 binary (r2)", bool(shutil.which("r2") or shutil.which("radare2"))),
        ("yara-python", _have("yara")),
    ]
    import os
    ghidra = os.environ.get("GHIDRA_HOME") or os.environ.get("GHIDRA_INSTALL_DIR")
    lines = [f"Reverence v{__version__} — engine availability:"]
    for name, ok in rows:
        lines.append(f"  [{'x' if ok else ' '}] {name}")
    lines.append(f"  [{'x' if ghidra else ' '}] Ghidra (GHIDRA_HOME={ghidra or 'unset'})")
    return "\n".join(lines)


@mcp.tool()
def analyze(path: str) -> str:
    """One-shot triage of a binary: identification + format summary + notable
    strings + entry-point disassembly. Start here when handed an unknown file
    (.exe/.dll/.so/.dylib/.wasm/etc.); then drill in with the specific tools."""
    try:
        p = resolve_target(path)
        sections = [identify.identify(str(p))]

        head = read_bytes(p, 0, 4)
        fmt_block = ""
        try:
            if head[:2] == b"MZ":
                fmt_block = pe.pe_info(str(p), max_imports=120, max_exports=60)
            elif head[:4] == b"\x7fELF":
                fmt_block = binfmt.lief_info(str(p), limit=120, want="elf")
            elif head[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe",
                              b"\xca\xfe\xba\xbe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce"):
                fmt_block = binfmt.lief_info(str(p), limit=120, want="macho")
            elif head[:4] == b"\x00asm":
                fmt_block = web.wasm_info(str(p))
        except AnalysisError as e:
            fmt_block = f"(format-specific analysis unavailable: {e})"
        if fmt_block:
            sections.append("\n" + "=" * 70 + "\n" + fmt_block)

        try:
            sections.append("\n" + "=" * 70 + "\nNotable strings:\n" +
                            strings.extract_strings(str(p), minlen=6, limit=60, highlight=True))
        except Exception:
            pass

        if head[:2] == b"MZ" or head[:4] == b"\x7fELF":
            try:
                sections.append("\n" + "=" * 70 + "\nEntry point:\n" +
                                disasm.disassemble_entry(str(p), count=40))
            except Exception as e:
                sections.append(f"\n(entry disasm skipped: {e})")
        return "\n".join(sections)
    except Exception as e:
        return _err(e)


@mcp.tool()
def identify_file(path: str) -> str:
    """Identify a file: format (by magic bytes), size, MD5/SHA1/SHA256 hashes,
    and entropy (flags likely packing/encryption). Cheap first look."""
    try:
        return identify.identify(str(resolve_target(path)))
    except Exception as e:
        return _err(e)


@mcp.tool()
def extract_strings(
    path: str,
    minlen: int = 5,
    limit: int = 400,
    offset: int = 0,
    length: int | None = None,
    include_wide: bool = True,
    highlight: bool = False,
) -> str:
    """Extract printable strings (ASCII + UTF-16LE) with file offsets.

    minlen: minimum run length. limit: max strings returned. offset/length:
    restrict to a byte window. include_wide: also pull UTF-16 (important on
    Windows). highlight: tag URLs, paths, registry keys, module names, and
    suspicious Win32 APIs."""
    try:
        return strings.extract_strings(
            str(resolve_target(path)), minlen, limit, offset, length, include_wide, highlight)
    except Exception as e:
        return _err(e)


@mcp.tool()
def hexdump_file(path: str, offset: int = 0, length: int = 256) -> str:
    """Hex + ASCII dump of a byte window (like `hexdump -C`). offset may be
    negative to read from the end of the file."""
    try:
        p = resolve_target(path)
        length = max(1, min(length, 65536))
        data = read_bytes(p, offset, length)
        base = offset if offset >= 0 else max(0, p.stat().st_size + offset)
        return hexdump(data, base=base) or "(no data at that offset)"
    except Exception as e:
        return _err(e)


# --------------------------------------------------------------------------
# Format-specific
# --------------------------------------------------------------------------

@mcp.tool()
def pe_info(path: str, max_imports: int = 300, max_exports: int = 300) -> str:
    """Full PE/PE32+ analysis for Windows .exe/.dll/.sys: headers, machine,
    subsystem, entry point, timestamp, imphash, security mitigations
    (ASLR/DEP/CFG/SEH), Authenticode signing state, PDB path, TLS callbacks,
    sections with per-section entropy, imports (by DLL), and exports."""
    try:
        return pe.pe_info(str(resolve_target(path)), max_imports, max_exports)
    except Exception as e:
        return _err(e)


@mcp.tool()
def elf_info(path: str, limit: int = 300) -> str:
    """ELF analysis (Linux/Unix): header, arch, PIE/NX, interpreter, needed
    libraries, sections, imported and exported functions."""
    try:
        return binfmt.lief_info(str(resolve_target(path)), limit, want="elf")
    except Exception as e:
        return _err(e)


@mcp.tool()
def macho_info(path: str, limit: int = 300) -> str:
    """Mach-O analysis (macOS/iOS), including fat/universal binaries: header,
    CPU type, PIE/NX, code-signature presence, linked libraries, segments,
    imports and exports."""
    try:
        return binfmt.lief_info(str(resolve_target(path)), limit, want="macho")
    except Exception as e:
        return _err(e)


# --------------------------------------------------------------------------
# Disassembly / decompilation
# --------------------------------------------------------------------------

@mcp.tool()
def disassemble(
    path: str,
    offset: int = 0,
    count: int = 64,
    arch: str = "auto",
    base_addr: int | None = None,
) -> str:
    """Disassemble a window of machine code from a file offset with Capstone.

    arch: auto|x86|x64|arm|thumb|arm64 (auto detects from the file header).
    count: number of instructions. base_addr: virtual address to show as the
    first instruction's address (defaults to the file offset)."""
    try:
        return disasm.disassemble(str(resolve_target(path)), offset, count, arch, base_addr)
    except Exception as e:
        return _err(e)


@mcp.tool()
def disassemble_entrypoint(path: str, count: int = 80) -> str:
    """Resolve a PE or ELF entry point to its file offset and virtual address,
    then disassemble from there. The fastest way to see where execution
    begins."""
    try:
        return disasm.disassemble_entry(str(resolve_target(path)), count)
    except Exception as e:
        return _err(e)


@mcp.tool()
def radare2(path: str, commands: list[str], analyze: bool = True) -> str:
    """Run static radare2 commands via r2pipe (requires the r2 binary).

    Opens the target read-only in static mode; the debug command family is
    refused. analyze=True runs `aaa` first. Useful commands: iI (info),
    ii (imports), iE (exports), afl (functions), 'pdf @ main' (disasm a
    function), 'axt @ sym.name' (xrefs), '/ <bytes>' (search)."""
    try:
        return radare.r2_run(str(resolve_target(path)), commands, analyze)
    except Exception as e:
        return _err(e)


@mcp.tool()
def ghidra_decompile(
    path: str,
    function: str | None = None,
    ghidra_home: str | None = None,
    timeout: int = 900,
) -> str:
    """Decompile to pseudo-C with Ghidra's headless analyzer (requires Ghidra;
    set GHIDRA_HOME). function: a name or address to decompile just one
    function; omit to decompile all (slower). Large binaries take minutes."""
    try:
        return decompile.decompile(str(resolve_target(path)), function, ghidra_home, timeout)
    except Exception as e:
        return _err(e)


# --------------------------------------------------------------------------
# Web app / scripts
# --------------------------------------------------------------------------

@mcp.tool()
def deobfuscate_javascript(path: str | None = None, code: str | None = None, indicators: bool = True) -> str:
    """Beautify/unminify JavaScript and flag suspicious patterns (eval,
    Function(), base64, char-code building, hex/unicode blobs, network calls,
    anti-debug). Provide either a file `path` or inline `code`."""
    try:
        if path:
            text = read_bytes(resolve_target(path), 0, 16 * 1024 * 1024).decode("utf-8", "replace")
        elif code is not None:
            text = code
        else:
            return "[reverence] Provide either path or code."
        return web.deobfuscate_js(text, indicators)
    except Exception as e:
        return _err(e)


@mcp.tool()
def wasm_info(path: str, limit: int = 200) -> str:
    """Parse a WebAssembly (.wasm) module: version, section layout, and
    imported/exported names (functions, memories, globals, tables)."""
    try:
        return web.wasm_info(str(resolve_target(path)), limit)
    except Exception as e:
        return _err(e)


@mcp.tool()
def fetch_web_asset(url: str, max_bytes: int = 4 * 1024 * 1024) -> str:
    """Read-only GET of a remote text/script/wasm asset so it can be analyzed
    (e.g. a site's bundle.js). Returns the content and content-type; it is not
    executed. http(s) only."""
    try:
        return web.fetch_text(url, max_bytes)
    except Exception as e:
        return _err(e)


@mcp.tool()
def yara_scan(path: str, rules_source: str | None = None, rules_file: str | None = None) -> str:
    """Scan a file with YARA (requires yara-python). Provide inline
    `rules_source` or a path to a `.yar` file in `rules_file`. Returns matched
    rules with string offsets."""
    try:
        return yarascan.yara_scan(str(resolve_target(path)), rules_source, rules_file)
    except Exception as e:
        return _err(e)


def main() -> None:
    """Console entry point: serve over stdio."""
    mcp.run()


if __name__ == "__main__":
    main()
