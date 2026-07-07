"""Airlock Stage 1 scratch client.

Connects to a fixture server over stdio, enumerates its prompts, resources, and
tools, and prints their full contents. This is the Stage 1 proof of the surface,
not the real Phase 1 scanner (that lives at src/airlock/scan/client.py).

Usage:
  uv run python fixtures/scratch_client.py [server_script]

server_script defaults to fixtures/vulnerable_server.py. Contents are printed both
rendered and as repr(), so invisible payloads (zero-width and unicode tag chars)
show up as \\u200b / \\U000e00xx escapes in the terminal.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

HERE = Path(__file__).resolve().parent
DEFAULT_SERVER = HERE / "vulnerable_server.py"


def _rule(title: str) -> None:
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def _dump_text(label: str, text: str) -> None:
    print(f"\n--- {label} (rendered) ---")
    print(text)
    print(f"\n--- {label} (repr, invisible chars visible) ---")
    print(repr(text))


async def inspect_server(server_script: Path) -> None:
    params = StdioServerParameters(command=sys.executable, args=[str(server_script)])
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            _rule(f"SERVER: {server_script.name}")

            tools = await session.list_tools()
            print(f"\nTools ({len(tools.tools)}):")
            for tool in tools.tools:
                print(f"  - {tool.name}: {tool.description}")

            prompts = await session.list_prompts()
            print(f"\nPrompts ({len(prompts.prompts)}):")
            for prompt in prompts.prompts:
                args = ", ".join(a.name for a in (prompt.arguments or []))
                print(f"  - {prompt.name}({args}): {prompt.description}")

            resources = await session.list_resources()
            print(f"\nResources ({len(resources.resources)}):")
            for resource in resources.resources:
                print(f"  - {resource.uri}: {resource.name}")

            # Read each resource using the uri returned by list_resources, which is
            # already a validated AnyUrl. This avoids any normalization mismatch from
            # hand-building the uri.
            for resource in resources.resources:
                result = await session.read_resource(resource.uri)
                for i, content in enumerate(result.contents):
                    text = getattr(content, "text", None)
                    if text is None:
                        print(f"\nResource {resource.uri} content[{i}] is non-text.")
                        continue
                    _dump_text(f"resource {resource.uri} content[{i}]", text)

            # Render each prompt. Fill required string arguments with a placeholder.
            for prompt in prompts.prompts:
                arguments = {a.name: "TCK-1" for a in (prompt.arguments or [])}
                result = await session.get_prompt(prompt.name, arguments=arguments)
                for i, message in enumerate(result.messages):
                    content = message.content
                    text = getattr(content, "text", str(content))
                    _dump_text(f"prompt {prompt.name} message[{i}] ({message.role})", text)


def main() -> int:
    server_script = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else DEFAULT_SERVER
    if not server_script.exists():
        print(f"error: server script not found: {server_script}", file=sys.stderr)
        return 2
    asyncio.run(inspect_server(server_script))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
