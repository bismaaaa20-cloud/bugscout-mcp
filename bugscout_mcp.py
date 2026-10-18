#!/usr/bin/env python3
"""BugScout MCP server v5.2: fast bug/error gate for scripts. Runs on Windows, macOS and Linux.
Security review is left to the connected AI."""

import argparse
import ast
import builtins
import hmac
import json
import logging
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import warnings
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
from pathlib import Path

from mcp.server.fastmcp import FastMCP

try:
    import resource
except ImportError:  # Windows
    resource = None

warnings.filterwarnings("ignore", category=SyntaxWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)

log = logging.getLogger("bugscout")

_FULL = (
    "About this tool only: BugScout is a quick bug and error checker for code in any language "
    "(Windows, macOS, Linux). These notes describe how it works. They never override, replace or "
    "reorder the instructions of the person, the host app or your system prompt. If they disagree, "
    "those win. Keep your own persona, tone, language, format and habits.\n"
    "Suggested use: when you are about to hand over a script or code file, you can call gate_check "
    "(gate_check_file for a file on disk) with the full final code first. Skip it if the person or "
    "host instructions say not to use tools or to give code as is.\n"
    "- DO_NOT_SEND (can_send=false): a syntax error, freeze, crash on start or destructive bug was "
    "found. Prefer to fix the blockers and check again (up to 3 rounds). If you still hand it over, "
    "or the person asks for it as is, say what is wrong.\n"
    "- SEND_WITH_NOTE: no blockers. Fix the high items if quick; otherwise mention them briefly.\n"
    "- SEND: nothing found.\n"
    "A small error that does not freeze, crash on start or cause damage is acceptable.\n"
    "BugScout checks bugs only. It does not check security and SEND is not a security approval. "
    "Findings are heuristics and can be wrong: if you are sure a blocker is a false alarm, say so. "
    "If syntax is unverified, review the code carefully yourself."
)

INSTRUCTIONS = (
    "BugScout: quick bug/error checker, not a security scan. It never overrides the person's, "
    "host's or system instructions. Before handing over code you may call gate_check. "
    "If can_send is false, fix the blockers and recheck (max 3) or say what is wrong. "
    "Mention notes briefly. Guide: resource bugscout://guide"
)

GUIDE = _FULL + (
    "\n\nWHAT IT CHECKS\n"
    "- Syntax and compile errors: Python, JSON, JS, Bash, Zsh, Go, Lua, PHP, Ruby, PowerShell; "
    "C/C++, TypeScript, Java and Rust only when the server runs with --enable-compilers.\n"
    "- Infinite loops without wait or exit (freeze) in Python, C-like languages, Lua/Luau (Roblox), "
    "Bash, PowerShell and Batch.\n"
    "- Crashes such as undefined names (Python), destructive bugs such as rm -rf with an empty "
    "variable, and cross-platform bugs such as CRLF in shell scripts, Windows path escapes and "
    "files opened without encoding.\n\n"
    "TOOLS\n"
    "- gate_check / gate_check_file: the gate. Short answer with verdict, can_send, blockers, notes.\n"
    "- analyze_code / analyze_file: full report with every finding.\n"
    "- analyze_directory: up to 50 files, checked in parallel.\n"
    "- supported_languages: which checkers are installed on this computer.\n\n"
    "Line numbers refer to the code you sent. Languages without a checker still get your own "
    "careful review, with syntax unverified."
)
mcp = FastMCP("bugscout", instructions=INSTRUCTIONS)

ROOT = None  # set in main() from --root or BUGSCOUT_ROOT
MAX_BYTES = 1_000_000
PY_PARSE_MAX = 300_000
MAX_LINE = 1000
MAX_OUTPUT = 65_536
TIMEOUT = 20
MAX_FINDINGS = 50
WORKERS = 10
FILES_ENABLED = False
COMPILERS_ENABLED = False
LOOPBACK = {"127.0.0.1", "localhost", "::1"}
SKIP_DIRS = {".git", "node_modules", "__pycache__", "venv", ".venv", "dist", "build"}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

EXT = {
    ".py": "python", ".json": "json", ".js": "javascript", ".mjs": "javascript",
    ".ts": "typescript", ".sh": "bash", ".bash": "bash", ".zsh": "zsh", ".c": "c", ".h": "c",
    ".cpp": "cpp", ".cc": "cpp", ".hpp": "cpp", ".go": "go", ".rs": "rust", ".lua": "lua",
    ".luau": "luau", ".php": "php", ".rb": "ruby", ".java": "java", ".pl": "perl",
    ".cs": "csharp", ".kt": "kotlin", ".ps1": "powershell", ".psm1": "powershell",
    ".bat": "batch", ".cmd": "batch", ".vbs": "vbscript",
}
SHEBANG = {"python": "python", "node": "javascript", "nodejs": "javascript", "bash": "bash",
           "sh": "bash", "dash": "bash", "zsh": "zsh", "ruby": "ruby", "perl": "perl",
           "php": "php", "lua": "lua", "luajit": "lua", "pwsh": "powershell"}
ALIASES = {"js": "javascript", "ts": "typescript", "py": "python", "c++": "cpp", "c#": "csharp",
           "sh": "bash", "shell": "bash", "rs": "rust", "rb": "ruby", "roblox": "luau",
           "ps": "powershell", "ps1": "powershell", "pwsh": "powershell", "cmd": "batch",
           "bat": "batch", "vbs": "vbscript"}

PS_PARSE = ("$e=$null;$t=$null;"
            "[void][System.Management.Automation.Language.Parser]::ParseFile($env:BUGSCOUT_FILE,[ref]$t,[ref]$e);"
            "foreach($x in $e){'line '+$x.Extent.StartLineNumber+': '+$x.Message};"
            "if($e.Count -gt 0){exit 1}")

# PARSE_ONLY checkers only parse the file (they never run it). "a|b" = try a, then b.
# OPT_IN checkers resolve includes/imports and stay off unless --enable-compilers.
PARSE_ONLY = {
    "javascript": (".js", ["node", "--check", "{f}"]),
    "bash": (".sh", ["bash", "-n", "{f}"]),
    "zsh": (".zsh", ["zsh", "-n", "{f}"]),
    "go": (".go", ["gofmt", "-e", "{f}"]),
    "lua": (".lua", ["luac", "-p", "{f}"]),
    "php": (".php", ["php", "-l", "{f}"]),
    "ruby": (".rb", ["ruby", "-c", "{f}"]),
    "powershell": (".ps1", ["pwsh|powershell", "-NoProfile", "-NonInteractive", "-Command", PS_PARSE]),
}
OPT_IN = {
    "typescript": (".ts", ["tsc", "--noEmit", "{f}"]),
    "c": (".c", ["gcc|clang|cc", "-fsyntax-only", "-Wall", "-Wextra", "{f}"]),
    "cpp": (".cpp", ["g++|clang++", "-fsyntax-only", "-Wall", "-Wextra", "{f}"]),
    "java": (".java", ["javac", "-proc:none", "-d", "{d}", "{f}"]),
    "rust": (".rs", ["rustfmt", "--edition", "2021", "--emit", "stdout", "{f}"]),
}
STDOUT_ERRORS = {"typescript", "php", "powershell"}
ENV_NOISE = re.compile(r"No such file or directory|Cannot find (?:module|name)|does not exist|"
                       r"cannot find symbol|unresolved|TS2307|TS2304|TS2580")

LAUNCHER = (  # POSIX only: applies resource limits, then replaces itself with the checker
    "import os,resource,sys\n"
    "t=int(sys.argv[1])\n"
    "for lim,val in ((resource.RLIMIT_CPU,(t,t+2)),(resource.RLIMIT_FSIZE,(10**7,10**7)),"
    "(resource.RLIMIT_CORE,(0,0))):\n"
    "    try: resource.setrlimit(lim,val)\n"
    "    except (ValueError,OSError): pass\n"
    "try: os.execv(sys.argv[2],sys.argv[2:])\n"
    "except OSError: os._exit(127)\n"
)
WIN_ENV_KEYS = {"SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "PROGRAMFILES", "PROGRAMFILES(X86)",
                "PROGRAMDATA", "ALLUSERSPROFILE", "PROCESSOR_ARCHITECTURE", "OS"}

# ---- bug heuristics -------------------------------------------------------------------
BRACE_LANGS = {"javascript", "typescript", "c", "cpp", "java", "go", "rust", "csharp",
               "kotlin", "php", "powershell"}
LOOP_RX = re.compile(r"\bwhile\s*\(\s*(?:true|True|TRUE|1|\$true|\$True)\s*\)\s*\{|"
                     r"\bfor\s*\(\s*;\s*;\s*\)\s*\{")
GO_LOOP = re.compile(r"\bfor\s*\{")
RUST_LOOP = re.compile(r"\bloop\s*\{|\bwhile\s+true\s*\{")
BRACE_EXIT = re.compile(
    r"\b(?:break|return|throw|await|yield|exit|abort|panic|sleep|usleep|Sleep|nanosleep|wait|"
    r"Wait|recv|recvfrom|accept|read|readLine|readline|getline|gets|fgets|scanf|select|poll|"
    r"join|setTimeout|goto|die|Read-Host|ReadKey)\b|<-")
LUA_LOOP = re.compile(r"^\s*while\s+(?:true|1)\s+do\b")
LUA_EXIT = re.compile(r"(?i)\b(?:wait|break|return|sleep|yield|error)\b")
BASH_LOOP = re.compile(r"^\s*while\s+(?:true|:|\[\s*1\s*\])\s*;?\s*(?:do\b)?")
BASH_EXIT = re.compile(r"\b(?:sleep|read|break|exit|return|wait|inotifywait|timeout)\b")
BATCH_LABEL = re.compile(r"^\s*:([A-Za-z_][\w.-]*)\s*$")
BATCH_GOTO = re.compile(r"(?i)\bgoto\s+:?([A-Za-z_][\w.-]*)")
BATCH_EXIT = re.compile(r"(?i)\b(?:if|timeout|pause|choice|ping|sleep|exit|more)\b|set\s+/p|goto\s+:eof")
BATCH_RM = re.compile(r"(?i)\b(?:rd|rmdir)\b[^\n]*\s/s\b[^\n]*%\w+%")
BATCH_GUARD = re.compile(r"(?i)\bif\s+(?:not\s+)?(?:defined|exist|\"%)")
BLOCKING_CALLS = {"sleep", "wait", "wait_for", "input", "recv", "recvfrom", "accept", "read",
                  "readline", "readlines", "join", "select", "poll", "exit", "_exit", "quit",
                  "communicate", "acquire", "serve_forever", "run_forever", "mainloop",
                  "run_until_complete"}
RM_RX = re.compile(r"\brm\s+-[a-zA-Z]*[rR][a-zA-Z]*\s+(.*)")
VAR_ARG = re.compile(r"(?:^|\s)[\"']?\$\{?[A-Za-z_]\w*\}?(?:/\S*)?")
WIN_PATH_BUG = re.compile(r"^[A-Za-z]:[\n\r\t\x07\x08\x0b\x0c]")

_RAW_PATTERNS = [
    (None, r"\brm\s+-[a-zA-Z]*[rR][a-zA-Z]*\s+(?:--no-preserve-root\s+)?[\"']?(?:/|/\*|~|~/\*)[\"']?(?=\s|;|$|\"|')",
     "critical", "rm -rf on root or home", "Deletes the whole system or the home folder."),
    ({"bash", "zsh"}, r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", "critical", "Fork bomb",
     "Freezes the machine."),
    ({"powershell"}, r"(?i)\bRemove-Item\b[^\n]*-Recurse[^\n]*\s[\"']?(?:[A-Za-z]:\\?|\\|/|~)[\"']?(?=\s|;|$|\"|')",
     "critical", "Remove-Item -Recurse on a drive root or home", "Deletes the whole drive or home folder."),
    ({"batch"}, r"(?i)\b(?:rd|rmdir|del|erase)\b[^\n]*\s[\"']?[A-Za-z]:\\?\*?[\"']?(?=\s|$)",
     "critical", "Delete on a drive root", "Deletes the whole drive."),
    ({"c", "cpp", "javascript", "typescript", "java", "php", "csharp"},
     r"\bif\s*\(\s*[A-Za-z_]\w*\s*=(?!=)\s*[^=\s]", "medium", "Assignment inside condition",
     "'=' assigns a value. Did you mean '=='?"),
    ({"c", "cpp", "java", "javascript", "typescript", "go", "rust", "kotlin"},
     r"\"[A-Za-z]:\\[ntrfvab]", "high", "Windows path with a backslash escape",
     "'\\n' or '\\t' in a path becomes a control character. Use '\\\\' or forward slashes."),
]
PATTERNS = [(l, re.compile(r), s, t, w) for l, r, s, t, w in _RAW_PATTERNS]

ADVICE = {
    "DO_NOT_SEND": "Blockers found. Prefer to fix them and call gate_check again before handing the "
                   "code over. If the person wants it as is, hand it over and say what is wrong.",
    "SEND_WITH_NOTE": "No blockers. Fix the high items if it is quick, or mention them briefly.",
    "SEND": "No blockers found.",
}


def finding(line, severity, title, why, source="static"):
    return {"line": line, "severity": severity, "title": title, "why": why, "source": source}


def too_big(code):
    return len(code.encode("utf-8", "replace")) > MAX_BYTES


def normalize(code):
    if code.startswith("\ufeff"):
        code = code[1:]
    return code.replace("\r\n", "\n").replace("\r", "\n")


def shebang_language(first):
    tokens = first[2:].split()
    if not tokens:
        return None
    prog = os.path.basename(tokens[0])
    if prog == "env":
        rest = [t for t in tokens[1:] if not t.startswith("-") and "=" not in t]
        if not rest:
            return None
        prog = os.path.basename(rest[0])
    m = re.match(r"[a-z]+", prog.lower())
    return SHEBANG.get(m.group(0)) if m else None


def detect_language(code, hint="", filename=""):
    hint = hint.strip().lower()
    if hint:
        return ALIASES.get(hint, hint)
    if filename:
        lang = EXT.get(Path(filename).suffix.lower())
        if lang:
            return lang
    first = code.splitlines()[0] if code.strip() else ""
    if first.startswith("#!"):
        return shebang_language(first) or "unknown"
    return "unknown"


# ---- running checkers (Windows, macOS, Linux) -----------------------------------------
def search_path():
    parts = os.environ.get("PATH", "").split(os.pathsep)
    if os.name == "posix":  # GUI apps on macOS start with a short PATH
        for extra in ("/opt/homebrew/bin", "/usr/local/bin", "/usr/local/go/bin",
                      os.path.expanduser("~/go/bin"), os.path.expanduser("~/.cargo/bin")):
            if extra not in parts and os.path.isdir(extra):
                parts.append(extra)
    return os.pathsep.join(p for p in parts if p)


def resolve_exe(spec):
    for name in spec.split("|"):
        exe = shutil.which(name, path=search_path())
        if not exe:
            continue
        if os.name == "nt" and name == "bash" and "\\system32\\" in exe.lower():
            continue  # the WSL launcher cannot read Windows paths
        return exe
    return None


def build_env(cwd):
    env = {"PATH": search_path(), "LANG": "C"}
    if os.name == "nt":
        for key, val in os.environ.items():
            if key.upper() in WIN_ENV_KEYS:
                env[key] = val
        for key in ("TEMP", "TMP", "USERPROFILE", "HOME", "APPDATA", "LOCALAPPDATA"):
            env[key] = cwd
    else:
        env["HOME"] = cwd
        env["TMPDIR"] = cwd
    return env


def kill_tree(proc):
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                           capture_output=True, timeout=10)
        else:
            import signal
            os.killpg(proc.pid, signal.SIGKILL)
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        proc.kill()
    except OSError:
        pass
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass


def run_limited(argv, cwd, out_path, err_path, extra_env):
    kwargs = {}
    if os.name == "posix":
        kwargs["start_new_session"] = True
        if resource is not None and sys.executable:
            argv = [sys.executable, "-I", "-c", LAUNCHER, str(TIMEOUT)] + argv
    else:
        kwargs["creationflags"] = (getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                                   | getattr(subprocess, "CREATE_NO_WINDOW", 0))
    env = build_env(cwd)
    env.update(extra_env)
    with open(out_path, "wb") as so, open(err_path, "wb") as se:
        proc = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                stdout=so, stderr=se, **kwargs)
        try:
            proc.wait(timeout=TIMEOUT)
        except subprocess.TimeoutExpired:
            kill_tree(proc)
            raise
    return proc.returncode


def read_capped(path):
    try:
        with open(path, "rb") as fh:
            return fh.read(MAX_OUTPUT).decode("utf-8", "replace")
    except OSError:
        return ""


def unchecked(msg):
    return {"checked": False, "ok": None, "messages": [msg]}


def parse_python(code):
    if len(code.encode("utf-8", "replace")) > PY_PARSE_MAX:
        return None, unchecked(f"Python file larger than {PY_PARSE_MAX} bytes: syntax check skipped.")
    try:
        return ast.parse(code), {"checked": True, "ok": True, "messages": []}
    except SyntaxError as exc:
        return None, {"checked": True, "ok": False, "messages": [f"line {exc.lineno}: {exc.msg}"]}
    except (ValueError, RecursionError, MemoryError) as exc:
        return None, unchecked(f"Parser failed: {type(exc).__name__}")


def check_json(code):
    try:
        json.loads(code)
        return {"checked": True, "ok": True, "messages": []}
    except json.JSONDecodeError as exc:
        return {"checked": True, "ok": False, "messages": [f"line {exc.lineno}: {exc.msg}"]}
    except (ValueError, RecursionError, MemoryError) as exc:
        return unchecked(f"Parser failed: {type(exc).__name__}")


def run_checker(code, lang):
    if lang == "json":
        return check_json(code)
    spec = PARSE_ONLY.get(lang)
    if spec is None and lang in OPT_IN:
        if not COMPILERS_ENABLED:
            return unchecked(f"Checker for '{lang}' is disabled (start the server with --enable-compilers).")
        spec = OPT_IN[lang]
    if spec is None:
        return unchecked(f"No syntax checker for '{lang}'.")
    ext, cmd = spec
    exe = resolve_exe(cmd[0])
    if exe is None:
        return unchecked(f"'{cmd[0].replace('|', ' or ')}' is not installed or not usable on this computer.")
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        name = "snippet"
        if lang == "java":
            m = re.search(r"public\s+(?:final\s+|abstract\s+)*(?:class|interface|enum|record)\s+(\w+)", code)
            name = m.group(1) if m else "Main"
        path = os.path.join(tmp, name + ext)
        out_p, err_p = os.path.join(tmp, "_out.txt"), os.path.join(tmp, "_err.txt")
        try:
            with open(path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(code)
            argv = [exe] + [a.replace("{f}", path).replace("{d}", tmp) for a in cmd[1:]]
            rc = run_limited(argv, tmp, out_p, err_p, {"BUGSCOUT_FILE": path})
        except subprocess.TimeoutExpired:
            return unchecked("Checker timed out.")
        except OSError as exc:
            log.warning("Checker failed to run: %s", exc)
            return unchecked("Checker failed to run.")
        if os.name == "posix" and rc == 127:
            return unchecked("Checker could not be started.")
        if rc is not None and rc < 0:
            return unchecked("Checker was killed by a signal (resource limit or crash), not a syntax verdict.")
        text = read_capped(out_p if lang in STDOUT_ERRORS else err_p).replace(tmp, "<tmp>")
    msgs = [ln for ln in text.splitlines() if ln.strip()][:10]
    return {"checked": True, "ok": rc == 0, "messages": msgs}


def syntax_findings(syntax, lang):
    out = []
    msgs = syntax.get("messages", [])
    if not syntax.get("checked"):
        return out
    if syntax["ok"] is False:
        m = re.match(r"line (\d+)", msgs[0]) if msgs else None
        err_lines = [x for x in msgs if re.search(r"\berror\b|error TS|error\[", x, re.I)]
        noisy = lang in OPT_IN and err_lines and all(ENV_NOISE.search(x) for x in err_lines)
        out.append(finding(int(m.group(1)) if m else 0, "high" if noisy else "critical",
                           "Missing dependency in snippet" if noisy else "Syntax or compile error",
                           "; ".join(msgs[:3])[:300], "syntax"))
    else:
        for x in msgs[:5]:
            out.append(finding(0, "low", "Checker warning", x[:200], "syntax"))
    return out


# ---- bug detectors --------------------------------------------------------------------
def _call_name(node):
    f = node.func
    if isinstance(f, ast.Attribute):
        return f.attr
    if isinstance(f, ast.Name):
        return f.id
    return ""


def loop_can_exit(loop):
    def visit(node, depth):
        if isinstance(node, (ast.Return, ast.Raise, ast.Yield, ast.YieldFrom, ast.Await)):
            return True
        if isinstance(node, ast.Break) and depth == 0:
            return True
        if isinstance(node, ast.Call) and _call_name(node) in BLOCKING_CALLS:
            return True
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            return False
        nxt = depth + 1 if isinstance(node, (ast.For, ast.AsyncFor, ast.While)) else depth
        return any(visit(c, nxt) for c in ast.iter_child_nodes(node))
    return any(visit(s, 0) for s in loop.body)


def text_io_without_encoding(n):
    if any(isinstance(a, ast.Starred) for a in n.args) or any(k.arg is None for k in n.keywords):
        return False
    if any(k.arg == "encoding" for k in n.keywords):
        return False
    if isinstance(n.func, ast.Attribute) and n.func.attr in ("read_text", "write_text"):
        return True
    if isinstance(n.func, ast.Name) and n.func.id == "open":
        mode = n.args[1] if len(n.args) >= 2 else next((k.value for k in n.keywords if k.arg == "mode"), None)
        if mode is None:
            return True
        return isinstance(mode, ast.Constant) and isinstance(mode.value, str) and "b" not in mode.value
    return False


def undefined_name_findings(tree):
    bound = set(dir(builtins)) | {"__file__", "__name__", "__doc__", "__spec__", "__builtins__",
                                  "__path__", "__package__", "__loader__", "__debug__", "__class__"}
    loads = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Name):
            if isinstance(n.ctx, ast.Load):
                loads.append(n)
            else:
                bound.add(n.id)
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound.add(n.name)
        elif isinstance(n, ast.arg):
            bound.add(n.arg)
        elif isinstance(n, (ast.Import, ast.ImportFrom)):
            for a in n.names:
                if a.name == "*":
                    return []
                bound.add((a.asname or a.name).split(".")[0])
        elif isinstance(n, ast.ExceptHandler) and n.name:
            bound.add(n.name)
        elif isinstance(n, (ast.Global, ast.Nonlocal)):
            bound.update(n.names)
        elif type(n).__name__ in ("MatchAs", "MatchStar", "TypeVar", "ParamSpec",
                                  "TypeVarTuple") and getattr(n, "name", None):
            bound.add(n.name)
        elif type(n).__name__ == "MatchMapping" and n.rest:
            bound.add(n.rest)
    seen, out = set(), []
    for n in sorted(loads, key=lambda x: (x.lineno, x.col_offset)):
        if n.id not in bound and n.id not in seen:
            seen.add(n.id)
            out.append(finding(n.lineno, "high", f"Undefined name '{n.id}'",
                               "Raises NameError when this line runs.", "ast"))
        if len(out) >= 20:
            break
    return out


def python_findings(tree):
    out = []
    if tree is None:
        return out
    enc_count = 0
    try:
        for n in ast.walk(tree):
            if isinstance(n, ast.While) and isinstance(n.test, ast.Constant) and n.test.value:
                if not loop_can_exit(n):
                    out.append(finding(n.lineno, "critical", "Infinite loop without exit or wait",
                                       "Nothing in the loop can stop or pause it, so the program freezes.", "ast"))
            elif isinstance(n, ast.ExceptHandler) and n.type is None:
                out.append(finding(n.lineno, "medium", "Bare except",
                                   "Also catches KeyboardInterrupt and SystemExit.", "ast"))
            elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                defaults = n.args.defaults + [d for d in n.args.kw_defaults if d is not None]
                if any(isinstance(d, (ast.List, ast.Dict, ast.Set)) for d in defaults):
                    out.append(finding(n.lineno, "medium", "Mutable default argument",
                                       "The default is shared across calls.", "ast"))
            elif isinstance(n, ast.Assert) and isinstance(n.test, ast.Tuple) and n.test.elts:
                out.append(finding(n.lineno, "high", "Assert on a tuple",
                                   "A non-empty tuple is always true, so it never fails.", "ast"))
            elif isinstance(n, ast.Constant) and isinstance(n.value, str) and WIN_PATH_BUG.match(n.value):
                out.append(finding(n.lineno, "high", "Windows path with a backslash escape",
                                   "'\\n' or '\\t' in a path becomes a control character. Use a raw string or '/'.", "ast"))
            elif isinstance(n, ast.Call) and enc_count < 5 and text_io_without_encoding(n):
                enc_count += 1
                out.append(finding(n.lineno, "medium", "Text file opened without encoding",
                                   "Windows uses cp1252 by default, so non-ASCII text can crash. Pass encoding='utf-8'.", "ast"))
            elif isinstance(n, ast.Compare):
                operands = [n.left] + n.comparators
                for i, op in enumerate(n.ops):
                    if isinstance(op, (ast.Eq, ast.NotEq)) and any(
                            isinstance(x, ast.Constant) and x.value is None
                            for x in (operands[i], operands[i + 1])):
                        out.append(finding(n.lineno, "low", "Comparing to None with ==",
                                           "Use 'is None' or 'is not None'.", "ast"))
                        break
        out.extend(undefined_name_findings(tree))
    except RecursionError:
        log.warning("AST too deep for bug checks")
    return out


def match_brace(code, start, quotes, hash_comments=False):
    depth, i, n, in_str = 0, start, len(code), None
    while i < n:
        c = code[i]
        if in_str:
            if c == "\\" or (c == "`" and hash_comments):
                i += 2
                continue
            if c == in_str:
                in_str = None
        elif c in quotes:
            in_str = c
        elif code.startswith("//", i) or (hash_comments and c == "#"):
            j = code.find("\n", i)
            i = n if j == -1 else j
            continue
        elif code.startswith("/*", i):
            j = code.find("*/", i + 2)
            i = n if j == -1 else j + 2
            continue
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return n


def brace_loop_findings(code, lang):
    out = []
    rxs = [LOOP_RX] + ([GO_LOOP] if lang == "go" else []) + ([RUST_LOOP] if lang == "rust" else [])
    quotes = {"rust": "\"", "powershell": "\"'"}.get(lang, "\"'`")
    for rx in rxs:
        for m in rx.finditer(code):
            body = code[m.end():match_brace(code, m.end() - 1, quotes, lang == "powershell")]
            if not BRACE_EXIT.search(body):
                out.append(finding(code.count("\n", 0, m.start()) + 1, "critical",
                                   "Infinite loop without exit or wait",
                                   "Nothing in the loop can stop or pause it, so the program freezes.", "loop"))
    return out


def block_freeze_findings(code, start_rx, end_word, exit_rx):
    lines = code.splitlines()
    out = []
    for i, line in enumerate(lines):
        m = start_rx.search(line[:MAX_LINE])
        if not m:
            continue
        indent = len(line) - len(line.lstrip())
        body = [line[m.end():]]
        for nxt in lines[i + 1:i + 301]:
            if nxt.strip().startswith(end_word) and len(nxt) - len(nxt.lstrip()) <= indent:
                break
            body.append(nxt)
        if not exit_rx.search("\n".join(body)):
            out.append(finding(i + 1, "critical", "Infinite loop without wait or exit",
                               "The loop never waits or stops, so the script freezes (in Roblox it times out).",
                               "loop"))
    return out


def batch_findings(code):
    lines = code.splitlines()
    out = []
    labels = {}
    for i, line in enumerate(lines):
        m = BATCH_LABEL.match(line)
        if m:
            labels.setdefault(m.group(1).lower(), i)
    for j, line in enumerate(lines):
        m = BATCH_GOTO.search(line)
        if not m or m.group(1).lower() == "eof":
            continue
        i = labels.get(m.group(1).lower())
        if i is not None and i < j and not BATCH_EXIT.search("\n".join(lines[i:j + 1])):
            out.append(finding(j + 1, "critical", "Endless goto loop without wait or exit",
                               "The loop never waits or stops, so the window freezes.", "loop"))
    if not BATCH_GUARD.search(code):
        for i, line in enumerate(lines, 1):
            if BATCH_RM.search(line[:MAX_LINE]):
                out.append(finding(i, "critical", "rd /s with an unguarded variable",
                                   "If the variable is empty this deletes the wrong folder. Check it with 'if defined' first.",
                                   "static"))
    return out


def bash_rm_findings(code):
    if re.search(r"^\s*set\s+-[a-zA-Z]*u", code, re.M):
        return []
    out = []
    for i, line in enumerate(code.splitlines(), 1):
        line = line[:MAX_LINE]
        m = RM_RX.search(line)
        if m and ":?" not in line and VAR_ARG.search(m.group(1)):
            out.append(finding(i, "critical", "rm -rf with an unguarded variable",
                               "If the variable is empty this deletes the wrong folder. Use ${VAR:?} or set -u.",
                               "static"))
    return out


def pattern_findings(code, lang):
    out = []
    for i, line in enumerate(code.splitlines(), 1):
        line = line[:MAX_LINE]
        for langs, rx, sev, title, why in PATTERNS:
            if (langs is None or lang in langs) and rx.search(line):
                out.append(finding(i, sev, title, why))
        if len(out) >= MAX_FINDINGS:
            break
    return out


@lru_cache(maxsize=32)
def analyze(code, language="", filename=""):
    crlf = "\r" in code
    code = normalize(code)
    lang = detect_language(code, language, filename)
    tree = None
    if lang == "python":
        tree, syntax = parse_python(code)
    else:
        syntax = run_checker(code, lang)
    found = syntax_findings(syntax, lang)
    if lang == "python":
        found += python_findings(tree)
    elif lang in BRACE_LANGS:
        found += brace_loop_findings(code, lang)
    elif lang in ("lua", "luau"):
        found += block_freeze_findings(code, LUA_LOOP, "end", LUA_EXIT)
    elif lang in ("bash", "zsh"):
        found += block_freeze_findings(code, BASH_LOOP, "done", BASH_EXIT) + bash_rm_findings(code)
        if crlf:
            found.append(finding(1, "critical", "Windows line endings (CRLF) in a shell script",
                                 "bash reads every line ending as '\\r' and fails. Convert the file to LF.", "static"))
    elif lang == "batch":
        found += batch_findings(code)
    found += pattern_findings(code, lang)
    found.sort(key=lambda f: (SEV_ORDER.get(f["severity"], 5), f["line"]))
    blockers = [f for f in found if f["severity"] == "critical"]
    high = any(f["severity"] == "high" for f in found)
    verdict = "DO_NOT_SEND" if blockers else ("SEND_WITH_NOTE" if high else "SEND")
    verified = bool(syntax.get("checked"))
    advice = ADVICE[verdict]
    if not verified:
        advice += " Syntax could not be verified for this language: read the code carefully yourself first."
    return {"language": lang, "lines": len(code.splitlines()), "verdict": verdict,
            "can_send": not blockers, "syntax_verified": verified, "syntax": syntax,
            "blockers": blockers[:20], "findings": found[:MAX_FINDINGS],
            "truncated": max(0, len(found) - MAX_FINDINGS), "advice": advice}


def _brief(f):
    return {"line": f["line"], "severity": f["severity"], "title": f["title"], "why": f["why"][:120]}


def gate_view(res):
    view = {"verdict": res["verdict"], "can_send": res["can_send"]}
    if not res["syntax_verified"]:
        view["unverified"] = True
    if res["blockers"]:
        view["blockers"] = [_brief(f) for f in res["blockers"][:5]]
        view["advice"] = "Fix blockers, recheck."
    notes = [f for f in res["findings"] if f["severity"] != "critical"][:5]
    if notes:
        view["notes"] = [_brief(f) for f in notes]
    return view


# ---- files ----------------------------------------------------------------------------
def safe_path(p):
    if ROOT is None:
        raise ValueError("No root folder configured. Start the server with --root or BUGSCOUT_ROOT.")
    path = Path(p)
    if not path.is_absolute():
        path = ROOT / path
    path = path.resolve()
    if path != ROOT and ROOT not in path.parents:
        raise ValueError("Path is outside the allowed root.")
    return path


def rel(path):
    try:
        return str(path.relative_to(ROOT)) or "."
    except (ValueError, TypeError):
        return path.name


def decode_text(data):
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):  # UTF-16 (PowerShell redirects, Notepad)
        return data.decode("utf-16", "replace")
    return data.decode("utf-8-sig", "replace")


def read_text(path):
    flags = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
             | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
    fd = os.open(str(path), flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError("Not a regular file.")
        if st.st_size > MAX_BYTES:
            raise ValueError(f"File larger than {MAX_BYTES} bytes.")
        with os.fdopen(fd, "rb") as fh:
            fd = -1
            data = fh.read(MAX_BYTES + 1)
    finally:
        if fd != -1:
            os.close(fd)
    if len(data) > MAX_BYTES:
        raise ValueError(f"File larger than {MAX_BYTES} bytes.")
    return decode_text(data)


def is_link(path):
    isjunction = getattr(os.path, "isjunction", lambda p: False)
    return os.path.islink(path) or isjunction(path)


def collect_files(base, limit):
    files = []
    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames
                             if d not in SKIP_DIRS and not d.startswith(".")
                             and not is_link(os.path.join(dirpath, d)))
        for name in sorted(filenames):
            fp = Path(dirpath) / name
            if name.startswith(".") or fp.suffix.lower() not in EXT or fp.is_symlink():
                continue
            try:
                fp.resolve().relative_to(ROOT)
            except (ValueError, OSError, RuntimeError):
                continue
            if len(files) >= limit:
                return files, True
            files.append(fp)
    return files, False


def file_error(exc, what="read file"):
    if isinstance(exc, ValueError):
        return {"error": str(exc)}
    if isinstance(exc, RuntimeError):
        return {"error": "Invalid path."}
    log.warning("Cannot %s: %s", what, exc)
    return {"error": f"Cannot {what} ({type(exc).__name__})."}


# ---- MCP tools ------------------------------------------------------------------------
@mcp.tool()
def gate_check(code: str, language: str = "") -> dict:
    """Quick bug/error check before handing over code. Not a security scan. Returns verdict
    and can_send. Leave language empty to auto-detect."""
    if too_big(code):
        return {"error": f"Code larger than {MAX_BYTES} bytes.", "can_send": False}
    return gate_view(analyze(code, language, ""))


@mcp.tool()
def gate_check_file(path: str) -> dict:
    """Same as gate_check, for a file inside the allowed root folder."""
    if not FILES_ENABLED:
        return {"error": "File tools are disabled on this server.", "can_send": False}
    try:
        p = safe_path(path)
        if not p.is_file():
            return {"error": "Not a file.", "can_send": False}
        return {"file": rel(p), **gate_view(analyze(read_text(p), "", p.name))}
    except (ValueError, RuntimeError, OSError) as exc:
        return {**file_error(exc), "can_send": False}


@mcp.tool()
def analyze_code(code: str, language: str = "") -> dict:
    """Full bug report for a snippet in any language (every finding, not just the gate view)."""
    if too_big(code):
        return {"error": f"Code larger than {MAX_BYTES} bytes."}
    return analyze(code, language, "")


@mcp.tool()
def analyze_file(path: str) -> dict:
    """Full bug report for one file inside the allowed root folder."""
    if not FILES_ENABLED:
        return {"error": "File tools are disabled on this server."}
    try:
        p = safe_path(path)
        if not p.is_file():
            return {"error": "Not a file."}
        return {"file": rel(p), **analyze(read_text(p), "", p.name)}
    except (ValueError, RuntimeError, OSError) as exc:
        return file_error(exc)


def scan_one(f):
    try:
        res = analyze(read_text(f), "", f.name)
        return {"file": rel(f), "language": res["language"], "verdict": res["verdict"],
                "can_send": res["can_send"], "syntax_ok": res["syntax"]["ok"],
                "findings": res["findings"][:50], "truncated": res["truncated"]}
    except (ValueError, RuntimeError, OSError) as exc:
        return {"file": rel(f), **file_error(exc)}


@mcp.tool()
def analyze_directory(path: str = ".", max_files: int = 10) -> dict:
    """Check up to max_files (1-50) source files under a folder, in parallel."""
    if not FILES_ENABLED:
        return {"error": "File tools are disabled on this server."}
    try:
        base = safe_path(path)
        if not base.is_dir():
            return {"error": "Not a folder."}
        limit = max(1, min(int(max_files), 50))
        files, more = collect_files(base, limit)
        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            results = list(pool.map(scan_one, files))
        verdicts = {}
        for r in results:
            v = r.get("verdict", "ERROR")
            verdicts[v] = verdicts.get(v, 0) + 1
        return {"scanned": len(results), "more_files_not_scanned": more,
                "verdicts": verdicts, "results": results}
    except (ValueError, TypeError, OverflowError, RuntimeError, OSError) as exc:
        return file_error(exc, "scan folder")


def checker_table():
    info = {"python": {"installed": True, "enabled": True},
            "json": {"installed": True, "enabled": True}}
    for table, enabled in ((PARSE_ONLY, True), (OPT_IN, COMPILERS_ENABLED)):
        for lang, (_, cmd) in table.items():
            info[lang] = {"installed": resolve_exe(cmd[0]) is not None, "enabled": enabled}
    return info


@mcp.tool()
def supported_languages() -> dict:
    """List this computer's OS, which syntax checkers are installed/enabled, and where
    freeze detection applies."""
    import platform
    return {"os": f"{platform.system()} {platform.release()} ({platform.machine()})",
            "syntax_checkers": checker_table(),
            "freeze_detection": sorted(BRACE_LANGS | {"python", "lua", "luau", "bash", "zsh", "batch"}),
            "note": "Other languages are still reviewed by the AI, but syntax is unverified."}


@mcp.prompt()
def send_script(request: str) -> str:
    """Write a script, gate it with BugScout, and only then deliver it."""
    return ("Write the script for the request below. Before delivering it, call gate_check on it. "
            "If can_send is false, fix the blockers and check again (max 3 rounds). Deliver only "
            f"when can_send is true, and mention any notes briefly.\n\nRequest: {request}")


@mcp.resource("bugscout://guide")
def guide() -> str:
    """What BugScout is for and how an AI should use it."""
    return GUIDE


# ---- HTTP guard -----------------------------------------------------------------------
def host_only(value):
    value = value.strip().lower()
    if value.startswith("["):
        end = value.find("]")
        return value[:end + 1] if end != -1 else value
    return value.split(":")[0]


class GuardedApp:
    """ASGI wrapper for HTTP mode: Host check, Origin check (blocks browsers), bearer token."""

    def __init__(self, app, token, hosts, origins):
        self.app = app
        self.token = token.encode("utf-8")
        self.hosts = hosts
        self.origins = origins

    @staticmethod
    async def deny(send, status, text):
        body = text.encode("utf-8")
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"content-type", b"text/plain"),
                                (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            await self.app(scope, receive, send)
            return
        if scope["type"] != "http":
            return
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]}
        if host_only(headers.get("host", "")) not in self.hosts:
            await self.deny(send, 421, "Host not allowed")
            return
        origin = headers.get("origin")
        if origin is not None and origin.lower() not in self.origins:
            await self.deny(send, 403, "Origin not allowed")
            return
        supplied = headers.get("authorization", "").encode("utf-8")
        if not hmac.compare_digest(supplied, b"Bearer " + self.token):
            await self.deny(send, 401, "Unauthorized")
            return
        await self.app(scope, receive, send)


def run_http(args, token, level):
    import uvicorn
    hosts = {"127.0.0.1", "localhost", "[::1]"} | {h.lower() for h in args.allowed_host}
    hosts.add(host_only(args.host))
    origins = {o.lower() for o in args.allowed_origin}
    app = GuardedApp(mcp.streamable_http_app(), token, hosts, origins)
    uvicorn.run(app, host=args.host, port=args.port,
                log_level=logging.getLevelName(level).lower())


def doctor(root_arg):
    import platform
    print(f"OS:      {platform.system()} {platform.release()} ({platform.machine()})")
    print(f"Python:  {sys.version.split()[0]} at {sys.executable}")
    print(f"Root:    {root_arg or '(not set: file tools disabled)'}")
    for table, tag in ((PARSE_ONLY, "on"), (OPT_IN, "opt-in")):
        for lang, (_, cmd) in table.items():
            print(f"{lang:<11} {tag:<7} {resolve_exe(cmd[0]) or 'not found'}")
    print("python/json  on      built in")


def parse_args(argv):
    p = argparse.ArgumentParser(description="BugScout MCP server (bug/error gate)")
    p.add_argument("--root", default="", help="Folder the file tools may read (or env BUGSCOUT_ROOT)")
    p.add_argument("--transport", choices=["stdio", "streamable-http"], default="stdio")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--workers", type=int, default=10, help="Parallel file checks (1-16)")
    p.add_argument("--token", default="",
                   help="Bearer token for HTTP (min 16 chars). Prefer env BUGSCOUT_TOKEN.")
    p.add_argument("--allowed-host", action="append", default=[])
    p.add_argument("--allowed-origin", action="append", default=[])
    p.add_argument("--allow-files", action="store_true",
                   help="Enable file tools over HTTP (stdio always has them)")
    p.add_argument("--enable-compilers", action="store_true",
                   help="Enable gcc/clang, tsc, javac, rustfmt checkers")
    p.add_argument("--unsafe-public", action="store_true",
                   help="Allow a non-loopback host. Needs a TLS reverse proxy in front.")
    p.add_argument("--doctor", action="store_true", help="Print OS, Python and installed checkers, then exit")
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--debug", action="store_true")
    return p.parse_args(argv)


def main(argv=None):
    global ROOT, FILES_ENABLED, COMPILERS_ENABLED, WORKERS
    args = parse_args(argv)
    level = logging.DEBUG if args.debug else (logging.INFO if args.verbose else logging.WARNING)
    logging.basicConfig(level=level, stream=sys.stderr,
                        format="%(asctime)s %(levelname)s %(message)s")
    root_arg = args.root or os.environ.get("BUGSCOUT_ROOT", "")
    COMPILERS_ENABLED = args.enable_compilers
    if args.doctor:
        doctor(root_arg)
        return 0
    if root_arg:
        ROOT = Path(root_arg).expanduser().resolve()
        if not ROOT.is_dir():
            log.error("Root folder does not exist: %s", ROOT)
            return 2
        if ROOT == Path(ROOT.anchor):
            log.error("Refusing a drive or filesystem root as the root folder.")
            return 2
    else:
        log.warning("No --root or BUGSCOUT_ROOT: file tools are disabled. Code tools still work.")
    FILES_ENABLED = ROOT is not None and (args.transport == "stdio" or args.allow_files)
    WORKERS = max(1, min(args.workers, 16))
    log.info("root=%s files=%s compilers=%s workers=%d transport=%s",
             ROOT, FILES_ENABLED, COMPILERS_ENABLED, WORKERS, args.transport)
    mcp.settings.host = args.host
    mcp.settings.port = args.port
    if args.transport == "stdio":
        mcp.run(transport="stdio")
        return 0
    token = os.environ.get("BUGSCOUT_TOKEN") or args.token
    if len(token) < 16:
        log.error("HTTP mode needs a token of at least 16 characters (env BUGSCOUT_TOKEN or --token).")
        return 2
    if args.host not in LOOPBACK and not args.unsafe_public:
        log.error("Refusing non-loopback host. Put a TLS reverse proxy in front, then pass --unsafe-public.")
        return 2
    run_http(args, token, level)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
