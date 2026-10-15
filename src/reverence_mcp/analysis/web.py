"""Web-app reverse engineering: JS beautify/deobfuscate, WASM, asset fetch.

Static analysis of client-side code. The fetch helper performs a read-only
GET so you can pull a script/wasm asset for inspection; it does not execute it.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..util import AnalysisError, human_size, read_bytes

try:
    import jsbeautifier
except ImportError:  # pragma: no cover
    jsbeautifier = None

# Behaviours worth flagging in client-side JS.
_JS_INDICATORS = [
    (re.compile(r"\beval\s*\("), "eval() — dynamic code execution"),
    (re.compile(r"\bnew\s+Function\s*\("), "Function() constructor — dynamic code"),
    (re.compile(r"\batob\s*\(|\bbtoa\s*\("), "base64 encode/decode"),
    (re.compile(r"String\.fromCharCode"), "char-code string building (obfuscation)"),
    (re.compile(r"\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){4,}"), "\\xNN hex-escaped string blobs"),
    (re.compile(r"\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){4,}"), "\\uNNNN unicode-escaped blobs"),
    (re.compile(r"document\.cookie"), "cookie access"),
    (re.compile(r"localStorage|sessionStorage"), "web storage access"),
    (re.compile(r"XMLHttpRequest|\bfetch\s*\(|navigator\.sendBeacon"), "network calls"),
    (re.compile(r"new\s+WebSocket\s*\("), "WebSocket"),
    (re.compile(r"\bWebAssembly\b"), "WebAssembly usage"),
    (re.compile(r"crypto\.subtle|CryptoJS|forge\."), "crypto library"),
    (re.compile(r"_0x[0-9a-f]{4,}", re.I), "hex-named identifiers (obfuscator-style)"),
    (re.compile(r"debugger\b"), "debugger statement (anti-debug)"),
]


def _indicator_scan(text: str) -> str:
    hits = []
    for rx, label in _JS_INDICATORS:
        c = len(rx.findall(text))
        if c:
            hits.append(f"  [{c:>4}] {label}")
    if not hits:
        return "Indicators: none of the common patterns matched."
    return "Indicators:\n" + "\n".join(hits)


def deobfuscate_js(text: str, indicators: bool = True) -> str:
    if jsbeautifier is None:
        raise AnalysisError("jsbeautifier is not installed. `pip install jsbeautifier`.")
    opts = jsbeautifier.default_options()
    opts.indent_size = 2
    opts.unescape_strings = True
    pretty = jsbeautifier.beautify(text, opts)
    parts = []
    if indicators:
        parts.append(_indicator_scan(text))
        parts.append("-" * 60)
    parts.append(pretty)
    return "\n".join(parts)


# ---- WASM ----------------------------------------------------------------

def _leb128(data: bytes, pos: int):
    """Decode an unsigned LEB128 at pos. Returns (value, new_pos)."""
    result = 0
    shift = 0
    while pos < len(data):
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            break
        shift += 7
    return result, pos


_WASM_SECTIONS = {
    0: "custom", 1: "type", 2: "import", 3: "function", 4: "table",
    5: "memory", 6: "global", 7: "export", 8: "start", 9: "element",
    10: "code", 11: "data", 12: "data-count",
}
_WASM_EXTKIND = {0: "func", 1: "table", 2: "mem", 3: "global"}


def wasm_info(path_str: str, limit: int = 200) -> str:
    p = Path(path_str)
    data = read_bytes(p, 0, None)
    if data[:4] != b"\x00asm":
        raise AnalysisError("Not a WebAssembly module (missing \\0asm magic).")
    version = int.from_bytes(data[4:8], "little")
    out = [f"WASM module: {p.name}", f"  version: {version}", f"  size: {human_size(len(data))}", ""]

    pos = 8
    sections = []
    imports = []
    exports = []
    while pos < len(data):
        if pos >= len(data):
            break
        sec_id = data[pos]
        pos += 1
        size, pos = _leb128(data, pos)
        payload = data[pos : pos + size]
        sections.append((sec_id, size))
        if sec_id == 2:  # import
            imports = _parse_wasm_imports(payload)
        elif sec_id == 7:  # export
            exports = _parse_wasm_exports(payload)
        pos += size

    out.append("Sections:")
    for sid, size in sections:
        out.append(f"  {_WASM_SECTIONS.get(sid, f'id{sid}'):<12} {human_size(size)}")

    if imports:
        out.append("")
        out.append(f"Imports ({len(imports)}):")
        for mod, name, kind in imports[:limit]:
            out.append(f"  {kind:<6} {mod}.{name}")
    if exports:
        out.append("")
        out.append(f"Exports ({len(exports)}):")
        for name, kind in exports[:limit]:
            out.append(f"  {kind:<6} {name}")
    return "\n".join(out)


def _read_name(data: bytes, pos: int):
    n, pos = _leb128(data, pos)
    s = data[pos : pos + n].decode("utf-8", "replace")
    return s, pos + n


def _parse_wasm_imports(data: bytes):
    out = []
    count, pos = _leb128(data, 0)
    for _ in range(count):
        try:
            mod, pos = _read_name(data, pos)
            name, pos = _read_name(data, pos)
            kind = _WASM_EXTKIND.get(data[pos], str(data[pos]))
            pos += 1
            # skip the type index / limits (coarse: consume one LEB for most kinds)
            _, pos = _leb128(data, pos)
            out.append((mod, name, kind))
        except Exception:
            break
    return out


def _parse_wasm_exports(data: bytes):
    out = []
    count, pos = _leb128(data, 0)
    for _ in range(count):
        try:
            name, pos = _read_name(data, pos)
            kind = _WASM_EXTKIND.get(data[pos], str(data[pos]))
            pos += 1
            _, pos = _leb128(data, pos)
            out.append((name, kind))
        except Exception:
            break
    return out


# ---- fetch ----------------------------------------------------------------

def fetch_text(url: str, max_bytes: int = 4 * 1024 * 1024) -> str:
    """Read-only GET of a text/script asset for analysis (does not execute it)."""
    import urllib.request

    if not re.match(r"^https?://", url, re.I):
        raise AnalysisError("Only http(s) URLs are supported.")
    req = urllib.request.Request(url, headers={"User-Agent": "reverence-mcp/0.1 (static-analysis)"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            ctype = resp.headers.get("Content-Type", "?")
            raw = resp.read(max_bytes + 1)
    except Exception as e:
        raise AnalysisError(f"Fetch failed: {e}")
    truncated = len(raw) > max_bytes
    raw = raw[:max_bytes]
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("latin-1", "replace")
    note = f"\n\n… truncated at {human_size(max_bytes)}." if truncated else ""
    return f"URL: {url}\nContent-Type: {ctype}\nBytes: {len(raw)}\n{'=' * 60}\n{text}{note}"
