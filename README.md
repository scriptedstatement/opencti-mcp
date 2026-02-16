# OpenCTI MCP Server

An MCP (Model Context Protocol) server providing comprehensive threat intelligence access to OpenCTI for Claude Code and other MCP clients.

> **Note:** This is a proof-of-concept project for exploring AI-assisted incident response capabilities. Not intended for production use without additional validation and hardening appropriate to your environment.

## Installation Options

### Option A: As Part of Claude-IR (Recommended)

This MCP is designed as a component of the [Claude-IR](https://github.com/scriptedstatement/claude-ir) AI-assisted incident response workstation.

```bash
git clone https://github.com/scriptedstatement/claude-ir.git
cd claude-ir
claude
# Then type: read and follow docs/SETUP_GUIDE.md
```

**Benefits of Claude-IR installation:**
- Guided setup with component selection
- Pre-configured MCP integration
- Works alongside forensic-rag-mcp (knowledge search) and windows-triage-mcp (file validation)
- Forensic discipline rules and investigation workflows

**Note:** This MCP requires an OpenCTI instance. See `SETUP.md` for guidance on connecting to or deploying OpenCTI.

### Option B: Standalone Installation

Use standalone when you only need threat intelligence lookups without the full IR workstation.

```bash
git clone https://github.com/scriptedstatement/opencti-mcp.git
cd opencti-mcp

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install
pip install -e .

# Configure (requires OpenCTI instance - see SETUP.md)
export OPENCTI_TOKEN="your-api-token"
export OPENCTI_URL="http://localhost:8080"

# Run server
python -m opencti_mcp
```

**For OpenCTI setup guidance:** See `SETUP.md`

## Features

### Search Operations (32 tools, 28 visible in read-only mode)

| Category | Tools | Description |
|----------|-------|-------------|
| **Unified Search** | `search_threat_intel` | Search across all entity types |
| **Threats** | `search_threat_actor`, `search_campaign` | APT groups, campaigns |
| **Arsenal** | `search_malware`, `search_tool`, `search_vulnerability` | Malware, tools, CVEs |
| **Techniques** | `search_attack_pattern`, `search_course_of_action` | MITRE ATT&CK, mitigations |
| **Observations** | `search_observable`, `search_sighting` | IOCs, detection events |
| **Events** | `search_incident` | Security incidents |
| **Analysis** | `search_reports`, `search_grouping`, `search_note` | Reports, groupings, notes |
| **Entities** | `search_organization`, `search_sector` | Organizations, industries |
| **Locations** | `search_location` | Countries, regions, cities |
| **Infrastructure** | `search_infrastructure` | C2, hosting, botnets |

### Entity Operations

| Tool | Description |
|------|-------------|
| `lookup_ioc` | Get full IOC context with relationships |
| `lookup_hash` | Look up file hash (MD5/SHA1/SHA256) |
| `get_entity` | Get any entity by ID |
| `get_relationships` | Get entity relationships |
| `get_recent_indicators` | Get indicators from last N days |

### Write Operations (requires `OPENCTI_READ_ONLY=false`)

| Tool | Description |
|------|-------------|
| `create_indicator` | Create new IOC |
| `create_note` | Add analyst note to entities |
| `create_sighting` | Record detection event |
| `trigger_enrichment` | Trigger VirusTotal/Shodan enrichment |

### System Operations

| Tool | Description |
|------|-------------|
| `get_health` | Check OpenCTI connectivity |
| `list_connectors` | List enrichment connectors |
| `get_network_status` | View adaptive metrics and recommendations |
| `force_reconnect` | Force reconnection (clears caches, resets circuit breaker) |
| `get_cache_stats` | View response cache statistics |

## Advanced Filtering

All search tools support advanced filtering:

```json
{
  "query": "APT29",
  "limit": 10,
  "offset": 0,
  "labels": ["tlp:amber", "apt"],
  "confidence_min": 70,
  "created_after": "2024-01-01",
  "created_before": "2024-12-31"
}
```

## Configuration

Settings are loaded via `Config.load()` classmethod (`config.py`) with `SecretStr` token protection and helper parsers for typed env vars.

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENCTI_URL` | `http://localhost:8080` | OpenCTI instance URL |
| `OPENCTI_TOKEN` | - | API token (required) |
| `OPENCTI_READ_ONLY` | `true` | Disable write operations |
| `OPENCTI_TIMEOUT` | `60` | Request timeout in seconds |
| `OPENCTI_MAX_RESULTS` | `100` | Maximum results per query |
| `OPENCTI_MAX_RETRIES` | `3` | Retry attempts for failures |
| `OPENCTI_RETRY_DELAY` | `1.0` | Initial retry delay (seconds) |
| `OPENCTI_RETRY_MAX_DELAY` | `30.0` | Maximum retry delay (seconds) |
| `OPENCTI_SSL_VERIFY` | `true` | Verify SSL certificates |
| `OPENCTI_CIRCUIT_THRESHOLD` | `5` | Failures before circuit opens |
| `OPENCTI_CIRCUIT_TIMEOUT` | `60` | Seconds before circuit recovery |
| `OPENCTI_EXTRA_OBSERVABLE_TYPES` | - | Custom observable types (comma-separated) |
| `OPENCTI_EXTRA_PATTERN_TYPES` | - | Custom pattern types (comma-separated) |
| `OPENCTI_LOG_FORMAT` | `json` | Log format: "json" or "text" |

### Feature Flags

Control optional features via environment variables (prefix: `FF_`):

| Variable | Default | Description |
|----------|---------|-------------|
| `FF_STARTUP_VALIDATION` | `true` | Test API connectivity on server start |
| `FF_RESPONSE_CACHING` | `false` | Cache search results (reduces API calls) |
| `FF_GRACEFUL_DEGRADATION` | `true` | Return cached results when service unavailable |
| `FF_NEGATIVE_CACHING` | `true` | Cache "not found" results |

### Token Configuration

**Option 1: Environment variable (recommended for production)**
```bash
export OPENCTI_TOKEN="your-api-token"
```

**Option 2: Token file**
```bash
mkdir -p ~/.config/opencti-mcp
echo "your-api-token" > ~/.config/opencti-mcp/token
chmod 600 ~/.config/opencti-mcp/token
```

**Option 3: .env file (development)**
```
OPENCTI_TOKEN=your-api-token
```

### Custom Types for Extended OpenCTI

If your OpenCTI instance has custom observable types or pattern types (e.g., proprietary IOC formats, additional detection languages), configure them via environment variables:

```bash
# Add custom observable types (case-sensitive, comma-separated)
export OPENCTI_EXTRA_OBSERVABLE_TYPES="Internal-Host,Cloud-Resource,Custom-IOC"

# Add custom pattern types (case-insensitive, comma-separated)
export OPENCTI_EXTRA_PATTERN_TYPES="osquery,kql,custom-sig"
```

These extend the built-in allow-lists without removing standard STIX types.

### Claude Code Configuration

Add to your MCP settings (`~/.config/claude-code/settings.json`):

```json
{
  "mcpServers": {
    "opencti": {
      "command": "/path/to/venv/bin/python",
      "args": ["-m", "opencti_mcp"],
      "cwd": "/path/to/opencti-mcp",
      "env": {
        "PYTHONPATH": "/path/to/opencti-mcp/src",
        "OPENCTI_TOKEN": "your-api-token",
        "OPENCTI_URL": "http://localhost:8080",
        "OPENCTI_READ_ONLY": "true"
      }
    }
  }
}
```

## Project Structure

```
opencti-mcp/
├── src/opencti_mcp/
│   ├── __init__.py       # Package exports
│   ├── __main__.py       # Entry point (with startup validation)
│   ├── server.py         # MCP server (32 tools)
│   ├── client.py         # OpenCTI API client (with caching)
│   ├── config.py         # Configuration management
│   ├── validation.py     # Input validation
│   ├── errors.py         # Error hierarchy
│   ├── logging.py        # Structured logging
│   ├── adaptive.py       # Network metrics
│   ├── cache.py          # TTL-based response caching
│   └── feature_flags.py  # Feature flag management
├── tests/                # Test suite (1530 tests)
├── docs/                 # Documentation
├── README.md             # This file
├── CLAUDE.md             # Development guide
├── IMPLEMENTATION.md     # Technical architecture
└── pyproject.toml        # Package configuration
```

## Development

### Run Tests

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run all tests
pytest

# With coverage
pytest --cov=opencti_mcp --cov-report=html

# Type checking
mypy src/opencti_mcp
```

### Test with MCP Inspector

```bash
npx @anthropic/mcp-inspector python -m opencti_mcp
```

### Key Commands

```bash
# Run MCP server
python -m opencti_mcp

# Test connection (original CLI)
python opencti_query.py "APT29" --type threat_actor

# Quick health check
python -c "from opencti_mcp import OpenCTIClient, Config; c = OpenCTIClient(Config.load()); print('OK' if c.is_available() else 'FAIL')"
```

## Production Considerations

### Recommended Settings for Remote/Cloud Instances

```bash
export OPENCTI_TIMEOUT=120         # Higher for cloud (default 60 may be tight for complex queries)
export OPENCTI_MAX_RETRIES=3       # Retry on transient failures
export OPENCTI_SSL_VERIFY=true     # Always for production
export OPENCTI_READ_ONLY=true      # Unless writes needed
```

> **Cloud users:** If you experience timeouts or circuit breaker trips, increase `OPENCTI_TIMEOUT` to 120-180. Complex threat intel queries on remote instances can take 60+ seconds under load.

### Adaptive Metrics

Use `get_network_status` tool to view:
- Latency statistics (P50/P95/P99)
- Success rates
- Circuit breaker state
- Recommended timeout/retry settings

## Requirements

- Python 3.10+
- OpenCTI 6.x instance
- pycti 6.x
- mcp 1.x

## Acknowledgments

Development assisted by Claude (Anthropic).

## License

MIT
