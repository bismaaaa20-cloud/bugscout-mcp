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

- **Windows:** double-click `setup.bat`
- **macOS:** double-click `setup.command` (run `chmod +x setup.command` once if blocked)
- **Linux:** `python3 install.py`

Then fully restart Claude Desktop. Needs Python 3.10+. Claude Code is registered too.

Manual setup:

```
pip install mcp
claude mcp add bugscout -- python /path/to/bugscout_mcp.py --root .
```

Check what is detected on your computer: `python bugscout_mcp.py --doctor`

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

## License

MIT
