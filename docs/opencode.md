# Using Reverence with OpenCode

OpenCode reads MCP servers from an `opencode.json` config - either project-local
(in your project root) or global (`~/.config/opencode/opencode.json`). Reverence
is a **local** (stdio) MCP server.

## Recommended - zero-clone via `uvx`

Requires [uv](https://docs.astral.sh/uv/) on your PATH. No clone, no venv to
manage; same config on Windows, macOS, and Linux. Add a `mcp` block:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "reverence": {
      "type": "local",
      "command": [
        "uvx",
        "--from",
        "git+https://github.com/0x3k3h/Reverence-MCP.git",
        "reverence-mcp"
      ],
      "enabled": true
    }
  }
}
```

This is the ready-to-copy [`examples/opencode.json`](../examples/opencode.json).

### With the optional engines (radare2 bridge + YARA)

```json
"command": [
  "uvx",
  "--from",
  "reverence-mcp[extras] @ git+https://github.com/0x3k3h/Reverence-MCP.git",
  "reverence-mcp"
]
```

### Enabling Ghidra decompilation

Add an `environment` block pointing at your Ghidra install:

```json
"reverence": {
  "type": "local",
  "command": ["uvx", "--from", "git+https://github.com/0x3k3h/Reverence-MCP.git", "reverence-mcp"],
  "enabled": true,
  "environment": { "GHIDRA_HOME": "C:\\tools\\ghidra_11.1" }
}
```

## Alternative - local checkout

After `git clone` + `uv sync`, point at the generated console script:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "reverence": {
      "type": "local",
      "command": ["/abs/path/to/Reverence-MCP/.venv/bin/reverence-mcp"],
      "enabled": true
    }
  }
}
```

On Windows the script is `...\.venv\Scripts\reverence-mcp.exe` (use
double-backslashes in JSON). You can also launch via
`["uv", "run", "--directory", "/abs/path/to/Reverence-MCP", "reverence-mcp"]`.

## Verify

Start OpenCode in a project that has the config. The Reverence tools
(`analyze`, `pe_info`, `disassemble`, ...) become available to the model. Ask:

> analyze C:\Windows\System32\notepad.exe with reverence

OpenCode will prompt to allow the MCP tool calls the first time.

## Notes

- `type: "local"` servers communicate over stdio - no ports or URLs involved.
- The first `uvx` launch builds and caches the package, so it takes a few extra
  seconds; later launches are fast.
- To temporarily disable without deleting the block, set `"enabled": false`.
