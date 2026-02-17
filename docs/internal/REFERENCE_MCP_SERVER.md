# MCP Server Reference

This file contains a reference MCP server implementation from `/path/to/rag-mcp/src/rag_mcp/server.py`.

Use this as a template for implementing the OpenCTI MCP server.

## Key Patterns

### 1. Server Setup

```python
from mcp.server import Server
from mcp.types import Tool, TextContent
import mcp.server.stdio

app = Server("server-name")
```

### 2. List Tools

```python
@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="tool_name",
            description="What the tool does",
            inputSchema={
                "type": "object",
                "properties": {
                    "param1": {
                        "type": "string",
                        "description": "Parameter description"
                    },
                    "param2": {
                        "type": "integer",
                        "description": "Optional param",
                        "default": 10
                    }
                },
                "required": ["param1"]
            }
        ),
        # ... more tools
    ]
```

### 3. Call Tool Handler

```python
@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name == "tool_name":
        param1 = arguments.get("param1", "")
        param2 = arguments.get("param2", 10)

        # Do work (use asyncio.to_thread for sync code)
        result = await asyncio.to_thread(sync_function, param1, param2)

        # Format result
        return [TextContent(
            type="text",
            text=format_result(result)
        )]

    return [TextContent(type="text", text=f"Unknown tool: {name}")]
```

### 4. Main Entry Point

```python
async def main():
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options()
        )

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
```

## Example: RAG-MCP Server Tools

From `/path/to/rag-mcp/src/rag_mcp/server.py`:

```python
@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="search",
            description="Search the IR knowledge base using semantic similarity",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Natural language search query"
                    },
                    "top_k": {
                        "type": "integer",
                        "description": "Number of results (default 5, max 50)",
                        "default": 5
                    },
                    "source": {
                        "type": "string",
                        "description": "Filter by source (e.g., 'sigma', 'mitre')"
                    },
                    "technique": {
                        "type": "string",
                        "description": "Filter by MITRE technique ID"
                    },
                    "platform": {
                        "type": "string",
                        "description": "Filter by platform"
                    }
                },
                "required": ["query"]
            }
        ),
        Tool(
            name="list_sources",
            description="List available knowledge sources",
            inputSchema={"type": "object", "properties": {}}
        ),
        Tool(
            name="get_stats",
            description="Get index statistics",
            inputSchema={"type": "object", "properties": {}}
        )
    ]
```

## Async Wrapper for Sync Code

Since `pycti` is synchronous but MCP is async:

```python
import asyncio

# Wrap sync OpenCTI calls
async def search_indicators(query: str, limit: int = 10):
    return await asyncio.to_thread(
        octi_client.search_indicators,
        query,
        limit
    )
```

## Error Handling

Return errors as text content, don't raise:

```python
@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    try:
        # ... do work
    except ValueError as e:
        return [TextContent(type="text", text=f"Validation error: {e}")]
    except ConnectionError as e:
        return [TextContent(type="text", text=f"OpenCTI connection failed: {e}")]
    except Exception as e:
        return [TextContent(type="text", text=f"Error: {e}")]
```

## Full RAG-MCP Server for Reference

Read the complete implementation:
```bash
cat /path/to/rag-mcp/src/rag_mcp/server.py
```
