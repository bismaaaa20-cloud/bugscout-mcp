# bugscout-mcp

A quick bug and error checker that an AI runs before handing over your code.
Bugs only, not a security scanner. Works on Windows, macOS and Linux.
Not related to other projects that share the BugScout name.

## What it does

The AI calls `gate_check` on a script and gets one of three verdicts:

- **SEND**: nothing found.
- **SEND_WITH_NOTE**: no blockers, small issues to mention.
- **DO_NOT_SEND**: syntax error, freeze, crash on start or destructive bug. Fix first.

Checks: syntax (Python, JSON, JS, Bash, Zsh, Go, Lua, PHP, Ruby, PowerShell; C/C++,
TypeScript, Java, Rust with `--enable-compilers`), loops that never wait or exit,
undefined names (Python), destructive commands (`rm -rf`, `Remove-Item -Recurse`),
and cross-platform bugs (CRLF in shell scripts, Windows path escapes, files opened
without encoding).

It does **not** check security. That stays the job of the AI you connect.

## Install

You need [uv](https://docs.astral.sh/uv/) and git on your computer. Nothing else.
The first run downloads BugScout, later runs start right away.

### Claude Desktop

Add this to `claude_desktop_config.json`, then fully restart the app:

- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "bugscout": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/bismaaaa20-cloud/bugscout-mcp",
        "bugscout-mcp"
      ]
    }
  }
}
```

### Claude Code

```
claude mcp add bugscout -- uvx --from git+https://github.com/bismaaaa20-cloud/bugscout-mcp bugscout-mcp
```

### Other apps

Any app that runs local MCP servers works: command `uvx`, arguments
`--from git+https://github.com/bismaaaa20-cloud/bugscout-mcp bugscout-mcp`.

### Let it read files (optional)

By default only the code the AI sends is checked. To let it check files in a
folder, add `"--root", "C:/path/to/project"` to `args` (Claude Desktop), or
`--root .` at the end of the Claude Code command.

Check what is detected on your computer:

```
uvx --from git+https://github.com/bismaaaa20-cloud/bugscout-mcp bugscout-mcp --doctor
```

## Options

| Flag | Meaning |
|---|---|
| `--root PATH` | Folder the file tools may read (file tools are off without it) |
| `--workers N` | Files checked in parallel, 1 to 16 (default 10) |
| `--enable-compilers` | Turn on gcc/clang, tsc, javac, rustfmt checkers |
| `--transport streamable-http` | Remote mode, needs `BUGSCOUT_TOKEN` (16+ chars) |
| `--doctor` | Print OS, Python and installed checkers, then exit |

## Limits

Findings are heuristics: they can miss bugs and sometimes flag good code.
Resource limits for checkers apply on macOS and Linux only.
It runs on your computer, so it does not work in the Claude website or phone app.

## License

MIT
