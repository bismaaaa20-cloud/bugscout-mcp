"""Smoke test for bugscout-mcp: starts the real MCP server and calls it like an AI client would."""
import asyncio
import json
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

TESTS = [
    ("loop with sleep", "import time\nwhile True:\n    time.sleep(1)\n", "python", "SEND"),
    ("loop without pause", "x = 1\nwhile True:\n    x += 1\n", "python", "DO_NOT_SEND"),
    ("undefined name", "print(abc)\n", "python", "SEND_WITH_NOTE"),
    ("syntax error", "def f(:\n    pass\n", "python", "DO_NOT_SEND"),
    ("Lua loop without wait", "while true do\n  print('x')\nend\n", "lua", "DO_NOT_SEND"),
    ("bash rm with variable", "#!/bin/bash\nrm -rf $DIR/*\n", "", "DO_NOT_SEND"),
    ("no language given", "x = 1\nwhile True:\n    x += 1\n", "", "DO_NOT_SEND"),
]


async def main():
    params = StdioServerParameters(command=sys.executable, args=["-m", "bugscout_mcp"])
    failed = 0
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            print("server:", init.serverInfo.name, "| instructions chars:", len(init.instructions or ""))
            tools = await session.list_tools()
            print("tools:", sorted(t.name for t in tools.tools))
            for name, code, lang, want in TESTS:
                res = await session.call_tool("gate_check", {"code": code, "language": lang})
                got = json.loads(res.content[0].text).get("verdict")
                ok = got == want
                failed += 0 if ok else 1
                print("PASS" if ok else "FAIL", "-", name, "-> got", got, "| expected", want)
    print()
    print("RESULT:", "all passed" if not failed else f"{failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
