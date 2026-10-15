"""Shared helpers: safe file access, hashing, entropy, formatting.

Everything here treats the target purely as bytes on disk. Nothing in this
module (or the package) executes or loads the target.
"""

from __future__ import annotations

import hashlib
import math
import os
from collections import Counter
from pathlib import Path

# Hard cap on how many bytes any single tool call will read into memory for
# scanning operations (strings, entropy windows, disasm). Hashing streams and
# is not bound by this.
MAX_READ_BYTES = 256 * 1024 * 1024  # 256 MiB


class AnalysisError(Exception):
    """Raised for user-facing, non-fatal problems (bad path, wrong format…)."""


def resolve_target(path: str) -> Path:
    """Validate and return a path to an existing regular file.

    Raises AnalysisError with a readable message instead of leaking tracebacks
    through the MCP channel.
    """
    if not path or not path.strip():
        raise AnalysisError("No path provided.")
    p = Path(os.path.expanduser(path.strip())).resolve()
    if not p.exists():
        raise AnalysisError(f"Path does not exist: {p}")
    if p.is_dir():
        raise AnalysisError(f"Path is a directory, not a file: {p}")
    if not p.is_file():
        raise AnalysisError(f"Not a regular file: {p}")
    return p


def read_bytes(path: Path, offset: int = 0, length: int | None = None) -> bytes:
    """Read a bounded window of a file. offset<0 counts from EOF."""
    size = path.stat().st_size
    if offset < 0:
        offset = max(0, size + offset)
    if offset > size:
        return b""
    if length is None:
        length = min(size - offset, MAX_READ_BYTES)
    length = max(0, min(length, MAX_READ_BYTES))
    with path.open("rb") as fh:
        fh.seek(offset)
        return fh.read(length)


def file_hashes(path: Path) -> dict[str, str]:
    """Stream the file and return md5/sha1/sha256 (and imphash if PE, elsewhere)."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte (0..8). >7.2 often means packed/encrypted."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def human_size(n: int) -> str:
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    f = float(n)
    for u in units:
        if f < 1024 or u == units[-1]:
            return f"{f:.0f} {u}" if u == "B" else f"{f:.2f} {u}"
        f /= 1024
    return f"{n} B"


def hexdump(data: bytes, base: int = 0, width: int = 16) -> str:
    """Classic `hexdump -C` style output."""
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        # pad hex column so ascii aligns
        hex_part = hex_part.ljust(width * 3 - 1)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{base + i:08x}  {hex_part}  |{ascii_part}|")
    return "\n".join(lines)


def truncate_note(shown: int, total: int, unit: str = "entries") -> str:
    """Footer telling the caller output was cut and how to page further."""
    if shown >= total:
        return ""
    return f"\n… showing {shown} of {total} {unit} (raise the limit or use offset to see more)."
