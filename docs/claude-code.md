# Using Reverence with Claude Code

Reverence is a stdio MCP server.

## Recommended — zero-clone via `uvx`

Requires [uv](https://docs.astral.sh/uv/) on your PATH. No clone, no venv to
manage; the same command works on Windows, macOS, and Linux.

### Via the CLI

```bash
claude mcp add reverence -s user -- uvx --from git+https://github.com/0x3k3h/reverence-mcp.git reverence-mcp
```

`-s user` makes it available in all your projects. Use `-s project` to write a
shareable `.mcp.json` into the repo instead, or `-s local` (default) for just
this project.

### Via `.mcp.json` (project-scoped, shareable)

Create `.mcp.json` in your project root — this is the ready-to-copy
[`examples/claude-code.mcp.json`](../examples/claude-code.mcp.json):

```json
{
  "mcpServers": {
    "reverence": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/0x3k3h/reverence-mcp.git",
        "reverence-mcp"
      ]
    }
  }
}
```

### With the optional engines (radare2 bridge + YARA)

Replace the `args` with:

```json
"args": ["--from", "reverence-mcp[extras] @ git+https://github.com/0x3k3h/reverence-mcp.git", "reverence-mcp"]
```

### Enabling Ghidra decompilation

Add an `env` block to the server entry:

```json
"env": { "GHIDRA_HOME": "C:\\tools\\ghidra_11.1" }
```

## Alternative — local checkout

After `git clone` + `uv sync`, point straight at the generated console script:

```bash
claude mcp add reverence -- C:\path\to\reverence-mcp\.venv\Scripts\reverence-mcp.exe
```

On macOS/Linux use `/path/to/reverence-mcp/.venv/bin/reverence-mcp`.

## Verify

```bash
claude mcp list
```

You should see `reverence: … - √ Connected`. Then, in a session:

> Use reverence to analyze C:\Windows\System32\notepad.exe

The `analyze` / `pe_info` / `disassemble_entrypoint` tools should fire.

> **Note:** a newly added server is picked up by *new* sessions — a running
> session won't see its tools until it reloads MCP servers.
