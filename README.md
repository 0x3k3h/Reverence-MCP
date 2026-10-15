# Reverence — Reverse-Engineering MCP Server

An [MCP](https://modelcontextprotocol.io) server that gives Claude Code,
OpenCode, and any other MCP client a toolbox for **static reverse engineering**
of binaries, executables, DLLs, shared objects, and web-app code.

> **Static analysis only.** Every tool reads the target as *data*. Reverence
> never executes, loads, or runs the files it inspects. The optional radare2
> bridge is locked to static mode (the debug command family is refused), and
> Ghidra runs headless auto-analysis without running the target.

## What it can do

| Tool | Purpose |
|------|---------|
| `capabilities` | Report which engines are installed (run this if a tool says a dependency is missing). |
| `analyze` | One-shot triage: identify + format summary + notable strings + entry-point disassembly. **Start here.** |
| `identify_file` | Format (magic bytes), size, MD5/SHA1/SHA256, entropy (packing hint). |
| `extract_strings` | ASCII **and** UTF-16LE strings with offsets; optional highlighting of URLs, paths, registry keys, and suspicious Win32 APIs. |
| `hexdump_file` | `hexdump -C`-style window (supports negative offsets). |
| `pe_info` | **Windows .exe/.dll/.sys**: headers, machine, subsystem, entry point, imphash, ASLR/DEP/CFG/SEH mitigations, Authenticode state, PDB path, TLS callbacks, per-section entropy, imports/exports. |
| `elf_info` | **Linux/Unix ELF**: header, arch, PIE/NX, interpreter, needed libs, sections, imports/exports. |
| `macho_info` | **macOS/iOS Mach-O** (incl. fat binaries): CPU, PIE/NX, code-signature, libs, segments, imports/exports. |
| `disassemble` | Capstone disassembly of a byte window; `auto` arch detection (x86/x64/arm/thumb/arm64). |
| `disassemble_entrypoint` | Resolve a PE/ELF entry point and disassemble from it. |
| `radare2` | Run **static** r2 commands via r2pipe *(needs the `r2` binary)*. |
| `ghidra_decompile` | Decompile to pseudo-C with Ghidra headless *(needs `GHIDRA_HOME`)*. |
| `deobfuscate_javascript` | Beautify/unminify JS and flag eval/Function/base64/anti-debug patterns. |
| `wasm_info` | Parse a `.wasm` module: sections, imports, exports. |
| `fetch_web_asset` | Read-only GET of a remote script/wasm bundle for analysis. |
| `yara_scan` | Match a file against inline or file-based YARA rules *(needs `yara-python`)*. |

## Install

Requires Python 3.10+ and [uv](https://docs.astral.sh/uv/).

### Zero-clone (recommended) — run straight from GitHub

No clone, no manual venv. Point your MCP client at:

```
uvx --from git+https://github.com/0x3k3h/reverence-mcp.git reverence-mcp
```

`uvx` fetches, builds, caches, and runs the server on demand — same command on
Windows, macOS, and Linux. To include the optional engines:

```
uvx --from "reverence-mcp[extras] @ git+https://github.com/0x3k3h/reverence-mcp.git" reverence-mcp
```

### Local checkout (for development)

```bash
git clone https://github.com/0x3k3h/reverence-mcp.git
cd reverence-mcp
uv sync            # add --extra extras for r2pipe + yara-python
```

Or with plain pip:

```bash
python -m venv .venv
.venv\Scripts\activate      # Windows ( source .venv/bin/activate on Unix )
pip install -e ".[extras]"
```

### Optional external tools

- **radare2** — install the `r2` binary from <https://github.com/radareorg/radare2>; `r2pipe` (the Python bridge) comes with the `extras` group.
- **Ghidra** — install from <https://ghidra-sre.org> and set `GHIDRA_HOME` to the install directory (the one containing `support/analyzeHeadless`).

Run `capabilities` any time to see what's active.

## Wiring it into a client

The server speaks MCP over stdio. The zero-clone launch command is:

```
uvx --from git+https://github.com/0x3k3h/reverence-mcp.git reverence-mcp
```

Copy-paste client config:

- **OpenCode** — [`docs/opencode.md`](docs/opencode.md) · ready file: [`examples/opencode.json`](examples/opencode.json)
- **Claude Code** — [`docs/claude-code.md`](docs/claude-code.md) · ready file: [`examples/claude-code.mcp.json`](examples/claude-code.mcp.json)

Quickest path, Claude Code:

```bash
claude mcp add reverence -s user -- uvx --from git+https://github.com/0x3k3h/reverence-mcp.git reverence-mcp
```

## Quick start

```
analyze  C:\Windows\System32\notepad.exe
pe_info  C:\path\to\sample.dll
extract_strings  C:\path\to\sample.exe  highlight=true  minlen=6
disassemble_entrypoint  C:\path\to\sample.exe
deobfuscate_javascript  path=C:\path\to\bundle.min.js
```

## Responsible use

Reverence is for authorized work: analyzing your own software, malware analysis
and defensive research, CTFs, interoperability, and security review of code you
have permission to examine. Point it at files you're allowed to analyze, and
handle real-world malware samples in an isolated environment — Reverence reads
them statically but anything *else* you do with them is on you.

## License

MIT
