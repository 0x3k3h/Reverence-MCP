"""Printable-string extraction (ASCII + UTF-16LE) with file offsets.

Mirrors `strings` but also pulls wide (UTF-16LE) strings, which matter a lot
for Windows binaries, and can flag interesting indicators (URLs, paths,
registry keys, crypto constants, suspicious APIs).
"""

from __future__ import annotations

import re
from pathlib import Path

from ..util import read_bytes, truncate_note

_ASCII_RE = re.compile(rb"[\x20-\x7e]{%d,}")
# UTF-16LE: printable ascii byte followed by 0x00, repeated.
_WIDE_RE = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}")

# Indicators worth surfacing when `highlight` is on.
_INTEREST = [
    (re.compile(r"\bhttps?://[^\s\"'<>]+", re.I), "url"),
    (re.compile(r"\b(?:[A-Za-z]:\\\\|[A-Za-z]:\\)[^\s\"'<>|?*]+", re.I), "win-path"),
    (re.compile(r"\bHKEY_[A-Z_]+\\[^\s\"']+", re.I), "registry"),
    (re.compile(r"\b[A-Za-z0-9.\-]+\.(?:dll|sys|exe|so|dylib)\b", re.I), "module"),
    (re.compile(r"\b(?:cmd\.exe|powershell|/bin/sh|/bin/bash)\b", re.I), "shell"),
    (re.compile(r"\b(?:VirtualAlloc|WriteProcessMemory|CreateRemoteThread|LoadLibrary"
                r"|GetProcAddress|WinExec|ShellExecute|URLDownloadToFile|CryptEncrypt"
                r"|RegSetValue|SetWindowsHookEx|NtUnmapViewOfSection)\w*", re.I), "api"),
    (re.compile(r"\b(?:[13bc][a-km-zA-HJ-NP-Z1-9]{25,39}|0x[a-fA-F0-9]{40})\b"), "crypto-addr?"),
]


def _scan(data: bytes, pattern: re.Pattern, minlen: int, wide: bool):
    for m in pattern.finditer(data):
        raw = m.group()
        if wide:
            text = raw[::2].decode("ascii", "replace")
        else:
            text = raw.decode("ascii", "replace")
        yield m.start(), ("w" if wide else "a"), text


def extract_strings(
    path_str: str,
    minlen: int = 5,
    limit: int = 400,
    offset: int = 0,
    length: int | None = None,
    include_wide: bool = True,
    highlight: bool = False,
) -> str:
    p = Path(path_str)
    data = read_bytes(p, offset, length)
    if not data:
        return "(no data in the requested window)"

    minlen = max(1, min(minlen, 64))
    ascii_re = re.compile(_ASCII_RE.pattern % minlen)
    found = list(_scan(data, ascii_re, minlen, wide=False))
    if include_wide:
        wide_re = re.compile(_WIDE_RE.pattern % minlen)
        found += list(_scan(data, wide_re, minlen, wide=True))
    found.sort(key=lambda t: t[0])

    total = len(found)
    shown = found[:limit]

    if highlight:
        tagged = []
        for off, kind, text in shown:
            tags = sorted({name for rx, name in _INTEREST if rx.search(text)})
            suffix = f"   [{', '.join(tags)}]" if tags else ""
            tagged.append(f"{offset + off:#010x} {kind} {text}{suffix}")
        body = "\n".join(tagged)
    else:
        body = "\n".join(f"{offset + off:#010x} {kind} {text}" for off, kind, text in shown)

    header = (
        f"strings: minlen={minlen} window=[{offset:#x}, +{len(data)}] "
        f"ascii+{'wide' if include_wide else 'ascii-only'} — {total} found\n"
        f"(offset  a=ascii/w=wide  text)\n"
    )
    return header + body + truncate_note(len(shown), total, "strings")
