"""MCP server — expose all Argus modules to MCP-compatible clients."""

import json
import asyncio
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from argus.core.registry import Registry, auto_discover


async def run_mcp():
    """Run the MCP server exposing all Argus modules as tools."""
    auto_discover()
    server = Server("argus")

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        tools = []
        for name in Registry.names():
            mod = Registry.get(name)
            tools.append(Tool(
                name=name,
                description=mod.description,
                inputSchema={
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": f"The {mod.input_type} to investigate",
                        },
                    },
                    "required": ["target"],
                },
            ))
        return tools

    @server.call_tool()
    async def call_tool(name: str, arguments: dict) -> list[TextContent]:
        mod = Registry.get(name)
        if not mod:
            return [TextContent(type="text", text=f"Unknown tool: {name}")]
        target = arguments.get("target", "")
        try:
            findings = mod.run(target)
            result = json.dumps([f.to_dict() for f in findings], indent=2)
            return [TextContent(type="text", text=result)]
        except Exception as e:
            return [TextContent(type="text", text=f"Error: {e}")]

    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())