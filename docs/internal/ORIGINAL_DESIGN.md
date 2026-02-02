# OpenCTI MCP Server - Design Document

**Version:** 1.0
**Status:** DRAFT - Pending Approval
**Author:** Claude Code
**Date:** 2026-01-31

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Requirements](#2-requirements)
3. [Architecture](#3-architecture)
4. [Security Design](#4-security-design)
5. [API Design (MCP Tools)](#5-api-design-mcp-tools)
6. [Error Handling](#6-error-handling)
7. [Testing Strategy](#7-testing-strategy)
8. [Implementation Plan](#8-implementation-plan)
9. [Risks and Mitigations](#9-risks-and-mitigations)
10. [Appendices](#appendices)

---

## 1. Executive Summary

### 1.1 Purpose

Convert the existing `opencti_query.py` CLI tool into a production-quality MCP (Model Context Protocol) server that provides threat intelligence capabilities to Claude Code and other MCP clients.

### 1.2 Goals

| Priority | Goal | Success Criteria |
|----------|------|------------------|
| P0 | Security-first design | No credential leakage, input validation, safe error handling |
| P0 | Reliable OpenCTI integration | Graceful degradation, connection pooling, timeout handling |
| P1 | Complete feature parity with CLI | All CLI features accessible via MCP tools |
| P1 | Production-quality code | Type hints, comprehensive tests, structured logging |
| P2 | Extensibility | Easy to add new tools, maintain, and debug |

### 1.3 Non-Goals

- Real-time streaming of threat intel (batch queries only)
- Write operations to OpenCTI (read-only access)
- Caching layer (OpenCTI handles caching internally)
- Multi-tenant support (single OpenCTI instance)

---

## 2. Requirements

### 2.1 Functional Requirements

#### FR-1: Threat Intelligence Search

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-1.1 | Search indicators (IOCs) by value or pattern | P0 |
| FR-1.2 | Search threat actors by name or alias | P0 |
| FR-1.3 | Search malware families | P0 |
| FR-1.4 | Search MITRE ATT&CK techniques | P0 |
| FR-1.5 | Search vulnerabilities (CVEs) | P0 |
| FR-1.6 | Search threat intelligence reports | P1 |
| FR-1.7 | Unified search across all entity types | P1 |

#### FR-2: IOC Context

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-2.1 | Get full context for an IOC including relationships | P0 |
| FR-2.2 | Retrieve related threat actors for an IOC | P0 |
| FR-2.3 | Retrieve related malware for an IOC | P0 |
| FR-2.4 | Retrieve MITRE techniques associated with IOC | P1 |

#### FR-3: Temporal Queries

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-3.1 | Get recent indicators from last N days | P1 |
| FR-3.2 | Filter results by creation/modification date | P2 |

#### FR-4: Enrichment (Optional)

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-4.1 | List available enrichment connectors | P2 |
| FR-4.2 | Trigger enrichment for an observable | P2 |

### 2.2 Non-Functional Requirements

#### NFR-1: Security

| ID | Requirement | Acceptance Criteria |
|----|-------------|---------------------|
| NFR-1.1 | Credential protection | Token never logged, never in error messages |
| NFR-1.2 | Input validation | All inputs validated before processing |
| NFR-1.3 | Safe error handling | No internal details leaked to clients |
| NFR-1.4 | No arbitrary code execution | Only predefined GraphQL queries |

#### NFR-2: Reliability

| ID | Requirement | Acceptance Criteria |
|----|-------------|---------------------|
| NFR-2.1 | Graceful degradation | Server works offline (returns appropriate errors) |
| NFR-2.2 | Connection resilience | Auto-reconnect on transient failures |
| NFR-2.3 | Timeout handling | All external calls have configurable timeouts |
| NFR-2.4 | Resource limits | Memory/CPU bounded under load |

#### NFR-3: Observability

| ID | Requirement | Acceptance Criteria |
|----|-------------|---------------------|
| NFR-3.1 | Structured logging | JSON logging with correlation IDs |
| NFR-3.2 | Error categorization | Distinct error types for debugging |
| NFR-3.3 | Health check | Verify OpenCTI connectivity |

#### NFR-4: Maintainability

| ID | Requirement | Acceptance Criteria |
|----|-------------|---------------------|
| NFR-4.1 | Type safety | Full type hints, mypy clean |
| NFR-4.2 | Test coverage | >80% line coverage |
| NFR-4.3 | Documentation | Docstrings on all public functions |

---

## 3. Architecture

### 3.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           MCP Clients                                    │
│                    (Claude Code, MCP Inspector, etc.)                    │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │ MCP Protocol (stdio)
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        OpenCTI MCP Server                                │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │                         server.py                                    ││
│  │  - MCP protocol handling                                            ││
│  │  - Tool dispatch                                                     ││
│  │  - Input validation                                                  ││
│  │  - Error handling                                                    ││
│  └────────────────────────────┬────────────────────────────────────────┘│
│                               │                                          │
│  ┌────────────────────────────▼────────────────────────────────────────┐│
│  │                         client.py                                    ││
│  │  - OpenCTI API abstraction                                          ││
│  │  - Connection management                                             ││
│  │  - Query builders                                                    ││
│  │  - Result formatting                                                 ││
│  └────────────────────────────┬────────────────────────────────────────┘│
│                               │                                          │
│  ┌────────────────────────────▼────────────────────────────────────────┐│
│  │                         config.py                                    ││
│  │  - Credential management                                             ││
│  │  - Configuration loading                                             ││
│  │  - Validation                                                        ││
│  └─────────────────────────────────────────────────────────────────────┘│
└───────────────────────────────┬─────────────────────────────────────────┘
                                │ GraphQL API
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                            OpenCTI                                       │
│                    (Docker @ localhost:8080)                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐ │
│  │ MITRE ATT&CK│  │ abuse.ch    │  │ CISA KEV    │  │ 15+ connectors  │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Module Structure

```
opencti-mcp/
├── src/
│   └── opencti_mcp/
│       ├── __init__.py           # Package exports, version
│       ├── __main__.py           # Entry point: python -m opencti_mcp
│       ├── server.py             # MCP server, tool handlers
│       ├── client.py             # OpenCTI API client
│       ├── config.py             # Configuration management
│       ├── validation.py         # Input validation utilities
│       ├── errors.py             # Custom exception hierarchy
│       └── logging.py            # Structured logging setup
├── tests/
│   ├── conftest.py               # Fixtures
│   ├── test_server.py            # Server tool tests
│   ├── test_client.py            # Client method tests
│   ├── test_validation.py        # Input validation tests
│   ├── test_integration.py       # End-to-end tests
│   └── test_security.py          # Security-focused tests
├── pyproject.toml                # Package configuration
├── CLAUDE.md                     # Claude Code guidance
├── DESIGN.md                     # This document
└── README.md                     # User documentation
```

### 3.3 Component Responsibilities

#### 3.3.1 server.py

**Purpose:** MCP protocol handling and tool dispatch

**Responsibilities:**
- Register MCP tools with schemas
- Validate input arguments
- Dispatch to client methods
- Format responses as TextContent
- Handle errors safely (no internal leakage)

**Key Classes:**
```python
class OpenCTIMCPServer:
    """MCP server for OpenCTI threat intelligence."""

    def __init__(self, config: Config) -> None: ...
    async def run(self) -> None: ...

    # Tool handlers (private)
    async def _search_threat_intel(self, query: str, ...) -> dict: ...
    async def _lookup_ioc(self, ioc: str, ...) -> dict: ...
    # ... etc
```

#### 3.3.2 client.py

**Purpose:** OpenCTI API abstraction

**Responsibilities:**
- Manage pycti client lifecycle
- Execute GraphQL queries
- Handle connection failures gracefully
- Format raw results into structured dicts
- Implement retry logic for transient failures

**Key Classes:**
```python
class OpenCTIClient:
    """Thread-safe OpenCTI API client."""

    def __init__(self, config: Config) -> None: ...
    def is_available(self) -> bool: ...

    # Search methods
    def search_indicators(self, query: str, limit: int = 10) -> list[dict]: ...
    def search_threat_actors(self, query: str, limit: int = 10) -> list[dict]: ...
    def search_malware(self, query: str, limit: int = 10) -> list[dict]: ...
    # ... etc

    # Context methods
    def get_indicator_context(self, value: str) -> dict: ...
    def get_relationships(self, entity_id: str) -> list[dict]: ...
```

#### 3.3.3 config.py

**Purpose:** Configuration and credential management

**Responsibilities:**
- Load configuration from environment/files
- Validate configuration values
- Provide secure credential access
- Support multiple credential sources

**Key Classes:**
```python
@dataclass(frozen=True)
class Config:
    """Immutable server configuration."""

    opencti_url: str
    opencti_token: SecretStr  # Never logged
    timeout_seconds: int = 30
    max_results: int = 100

    @classmethod
    def load(cls) -> "Config": ...

    def validate(self) -> None: ...
```

#### 3.3.4 validation.py

**Purpose:** Input validation utilities

**Responsibilities:**
- Validate input lengths
- Validate IOC formats
- Sanitize inputs
- Provide clear validation errors

**Key Functions:**
```python
def validate_length(value: str, max_length: int, field: str) -> None: ...
def validate_ioc_format(value: str) -> tuple[bool, str, str]: ...
def validate_hash(value: str) -> bool: ...
def validate_limit(value: int, max_value: int = 100) -> int: ...
```

#### 3.3.5 errors.py

**Purpose:** Custom exception hierarchy

**Design:**
```python
class OpenCTIMCPError(Exception):
    """Base exception for OpenCTI MCP."""
    pass

class ConfigurationError(OpenCTIMCPError):
    """Configuration or credential error."""
    pass

class ConnectionError(OpenCTIMCPError):
    """OpenCTI connection failure."""
    pass

class ValidationError(OpenCTIMCPError):
    """Input validation failure."""
    pass

class QueryError(OpenCTIMCPError):
    """Query execution failure."""
    pass
```

### 3.4 Data Flow

```
1. MCP Client sends tool call
   │
   ▼
2. server.py receives call
   │
   ├─▶ Validate input lengths (security)
   │
   ├─▶ Validate input formats (IOC type, hash format)
   │
   ▼
3. Dispatch to client.py method
   │
   ├─▶ Check OpenCTI availability
   │
   ├─▶ Build GraphQL query
   │
   ├─▶ Execute with timeout
   │
   ├─▶ Handle errors (retry transient, fail permanent)
   │
   ▼
4. Format response
   │
   ├─▶ Structure as dict
   │
   ├─▶ Truncate large fields
   │
   ▼
5. Return TextContent to MCP client
```

---

## 4. Security Design

### 4.1 Threat Model

| ID | Threat | Likelihood | Impact | Risk | Mitigation |
|----|--------|------------|--------|------|------------|
| T1 | Credential leakage via logs | Medium | Critical | **HIGH** | SecretStr, log filtering |
| T2 | Credential leakage via errors | Medium | Critical | **HIGH** | Generic error messages |
| T3 | Credential leakage via memory dump | Low | Critical | **MEDIUM** | Accept risk (OS-level) |
| T4 | Token file permission exposure | Medium | Critical | **HIGH** | Enforce 600 permissions |
| T5 | Resource exhaustion (DoS) | Medium | Medium | **MEDIUM** | Length limits, timeouts, rate limiting |
| T6 | GraphQL injection | Low | High | **MEDIUM** | pycti parameterized queries only |
| T7 | Information disclosure via errors | Medium | Medium | **MEDIUM** | Safe error handling |
| T8 | ReDoS via malformed input | Medium | Medium | **MEDIUM** | Length-first validation, simple patterns |
| T9 | Log injection | Low | Low | **LOW** | Structured logging, sanitization |
| T10 | SSRF via OpenCTI URL | Low | High | **MEDIUM** | URL validation, localhost default |
| T11 | Response size exhaustion | Medium | Medium | **MEDIUM** | Response size limits, truncation |
| T12 | Timing attacks | Low | Low | **LOW** | Accept risk (low value) |
| T13 | Dependency vulnerabilities | Medium | High | **MEDIUM** | Pin versions, audit deps |
| T14 | Enrichment API abuse | Medium | Medium | **MEDIUM** | Rate limiting, confirmation |
| T15 | Query complexity attacks | Low | Medium | **LOW** | Limit relationship depth |

### 4.2 Credential Management

#### 4.2.1 Credential Sources (precedence order)

1. `OPENCTI_TOKEN` environment variable (highest)
2. `~/.config/opencti-mcp/token` file
3. `.env` file in working directory (lowest)

#### 4.2.2 Token File Security

```python
def _load_token_file(path: Path) -> Optional[str]:
    """Load token from file with permission check.

    Security: Refuse to load token if file permissions are too open.
    """
    if not path.exists():
        return None

    # Check file permissions (POSIX only)
    if hasattr(os, 'stat'):
        mode = path.stat().st_mode
        # Reject if group or other can read (not 600 or 400)
        if mode & 0o077:
            logger.warning(
                "Token file has insecure permissions",
                extra={"path": str(path), "mode": oct(mode)}
            )
            raise ConfigurationError(
                f"Token file {path} has insecure permissions. "
                f"Run: chmod 600 {path}"
            )

    return path.read_text().strip()
```

#### 4.2.3 SecretStr Protection

```python
from pydantic import SecretStr

@dataclass
class Config:
    opencti_url: str
    opencti_token: SecretStr  # Pydantic's SecretStr

    def __repr__(self) -> str:
        # Never include token in repr
        return f"Config(opencti_url={self.opencti_url}, token=***)"

    def __str__(self) -> str:
        return self.__repr__()

    # Prevent accidental serialization
    def __getstate__(self):
        raise TypeError("Config should not be pickled (contains secrets)")
```

#### 4.2.4 Token Exposure Vectors (and mitigations)

| Vector | Risk | Mitigation |
|--------|------|------------|
| Logging | High | SecretStr, never log config directly |
| Error messages | High | Generic errors to clients |
| Debug output | Medium | `__repr__` masks token |
| Serialization | Medium | Block pickling |
| Memory dump | Low | Accept risk (OS-level protection) |
| /proc/environ | Low | Accept risk (document in README) |
| .env in repo | High | Add to .gitignore template |

### 4.3 Input Validation

#### 4.3.1 Length Limits

```python
# Security constants - prevent resource exhaustion
MAX_QUERY_LENGTH = 1000      # Search query
MAX_IOC_LENGTH = 2048        # IOC value (URLs can be long)
MAX_HASH_LENGTH = 128        # Hash with prefix
MAX_LIMIT = 100              # Max results per query
MAX_DAYS = 365               # Max days for temporal queries
MAX_RESPONSE_SIZE = 1_000_000  # 1MB response limit
```

#### 4.3.2 Validation Order (CRITICAL)

```
1. Check length FIRST ──────────────► Prevents ReDoS
2. Strip/normalize SECOND ──────────► Clean input
3. Validate format THIRD ───────────► Simple patterns only
4. Type-specific checks FOURTH ─────► Hash length, IP octets
```

#### 4.3.3 ReDoS Prevention

```python
# BAD - vulnerable to ReDoS
DOMAIN_PATTERN = r'^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'

# GOOD - simple, non-backtracking
def _is_domain(value: str) -> bool:
    """Check if value looks like a domain.

    Uses simple checks instead of complex regex to avoid ReDoS.
    """
    if len(value) > 253:  # Max domain length
        return False
    if not '.' in value:
        return False
    if value.startswith('.') or value.endswith('.'):
        return False
    # Additional simple checks...
    return True
```

#### 4.3.4 IOC Validation

```python
def validate_ioc(ioc: str) -> tuple[bool, str]:
    """Validate IOC format.

    Security: Length check BEFORE any regex/parsing.

    Returns:
        (is_valid, detected_type)
    """
    # 1. Length check FIRST
    if len(ioc) > MAX_IOC_LENGTH:
        raise ValidationError(f"IOC exceeds {MAX_IOC_LENGTH} characters")

    # 2. Strip and normalize
    ioc = ioc.strip()
    if not ioc:
        raise ValidationError("IOC cannot be empty")

    # 3. Simple pattern checks (no complex regex)
    if _is_ipv4(ioc):
        return True, "ipv4"
    if _is_hash(ioc):
        return True, "hash"
    if ioc.startswith(('http://', 'https://')):
        return True, "url"
    if _is_domain(ioc):
        return True, "domain"

    return True, "unknown"  # Allow unknown types
```

### 4.4 Network Security

#### 4.4.1 OpenCTI URL Validation

```python
def validate_opencti_url(url: str) -> str:
    """Validate and normalize OpenCTI URL.

    Security: Prevent SSRF by restricting URL schemes and hosts.
    """
    parsed = urlparse(url)

    # Only allow http/https
    if parsed.scheme not in ('http', 'https'):
        raise ConfigurationError(
            f"Invalid URL scheme: {parsed.scheme}. Use http or https."
        )

    # Warn if not localhost/private and using HTTP
    if parsed.scheme == 'http':
        host = parsed.hostname or ''
        private_hosts = ('localhost', '127.0.0.1', '::1')
        private_ranges = ('10.', '172.16.', '172.17.', '192.168.')

        is_private = (
            host in private_hosts or
            any(host.startswith(r) for r in private_ranges)
        )

        if not is_private:
            logger.warning(
                "Using HTTP for non-local OpenCTI instance",
                extra={"url": url, "warning": "credentials sent in plaintext"}
            )

    return url.rstrip('/')
```

#### 4.4.2 TLS Configuration

```python
# For remote OpenCTI instances, enforce TLS verification
def _create_session(self, url: str) -> requests.Session:
    session = requests.Session()

    if url.startswith('https://'):
        # Verify TLS certificates
        session.verify = True
        # Could add certificate pinning for high-security deployments
    else:
        # Local development only
        session.verify = False

    return session
```

### 4.5 Error Handling Security

#### 4.5.1 Error Classification

| Error Type | Safe to Return? | Example |
|------------|-----------------|---------|
| ValidationError | YES | "Query exceeds 1000 characters" |
| ConfigurationError | PARTIAL | "OpenCTI not configured" (not details) |
| ConnectionError | PARTIAL | "OpenCTI unavailable" (not network details) |
| QueryError | NO | Generic "Query failed" only |
| Internal errors | NO | Generic "Internal error" only |

#### 4.5.2 Safe Error Responses

```python
async def call_tool(self, name: str, arguments: dict) -> list[TextContent]:
    try:
        result = await self._dispatch_tool(name, arguments)
        return [TextContent(type="text", text=json.dumps(result))]

    except ValidationError as e:
        # Validation errors are safe - they describe input problems
        logger.warning("Validation failed", extra={
            "tool": name,
            "error": str(e),
            "arguments": _sanitize_for_log(arguments)
        })
        return [TextContent(type="text", text=json.dumps({
            "error": "validation_error",
            "message": str(e)
        }))]

    except ConfigurationError as e:
        # Config errors - return safe portion only
        logger.error("Configuration error", extra={"error": str(e)})
        return [TextContent(type="text", text=json.dumps({
            "error": "configuration_error",
            "message": "OpenCTI is not properly configured"
        }))]

    except Exception as e:
        # NEVER leak internal details
        logger.exception("Internal error", extra={
            "tool": name,
            "error_type": type(e).__name__
            # NOT including str(e) which may have sensitive info
        })
        return [TextContent(type="text", text=json.dumps({
            "error": "internal_error",
            "message": "An unexpected error occurred. Check server logs."
        }))]
```

### 4.6 Log Security

#### 4.6.1 Log Injection Prevention

```python
def _sanitize_for_log(value: Any) -> Any:
    """Sanitize value for safe logging.

    Prevents log injection by escaping newlines and control characters.
    """
    if isinstance(value, str):
        # Remove/escape control characters
        sanitized = value.encode('unicode_escape').decode('ascii')
        # Truncate long values
        if len(sanitized) > 500:
            sanitized = sanitized[:500] + "...[truncated]"
        return sanitized
    elif isinstance(value, dict):
        return {k: _sanitize_for_log(v) for k, v in value.items()}
    elif isinstance(value, list):
        return [_sanitize_for_log(v) for v in value[:10]]  # Limit list size
    else:
        return value
```

#### 4.6.2 Sensitive Field Filtering

```python
SENSITIVE_FIELDS = {'token', 'password', 'secret', 'key', 'auth', 'credential'}

def _filter_sensitive(data: dict) -> dict:
    """Filter sensitive fields from data before logging."""
    result = {}
    for key, value in data.items():
        if any(s in key.lower() for s in SENSITIVE_FIELDS):
            result[key] = "***REDACTED***"
        elif isinstance(value, dict):
            result[key] = _filter_sensitive(value)
        else:
            result[key] = value
    return result
```

### 4.7 Rate Limiting

#### 4.7.1 Query Rate Limiting

```python
from collections import deque
from time import time

class RateLimiter:
    """Simple rate limiter for API calls.

    Prevents abuse and protects OpenCTI from overload.
    """

    def __init__(self, max_calls: int = 60, window_seconds: int = 60):
        self.max_calls = max_calls
        self.window = window_seconds
        self.calls: deque = deque()

    def check(self) -> bool:
        """Check if call is allowed. Returns False if rate limited."""
        now = time()

        # Remove old calls outside window
        while self.calls and self.calls[0] < now - self.window:
            self.calls.popleft()

        if len(self.calls) >= self.max_calls:
            return False

        self.calls.append(now)
        return True

    def wait_time(self) -> float:
        """Return seconds to wait before next call allowed."""
        if len(self.calls) < self.max_calls:
            return 0.0
        oldest = self.calls[0]
        return max(0.0, oldest + self.window - time())
```

#### 4.7.2 Enrichment Rate Limiting (Stricter)

```python
# Enrichment uses external API quota - much stricter limits
ENRICHMENT_RATE_LIMIT = RateLimiter(max_calls=10, window_seconds=3600)  # 10/hour
```

### 4.8 Response Security

#### 4.8.1 Response Size Limits

```python
def _truncate_response(result: dict, max_size: int = MAX_RESPONSE_SIZE) -> dict:
    """Truncate response if it exceeds size limit.

    Security: Prevents memory exhaustion from large OpenCTI responses.
    """
    serialized = json.dumps(result)

    if len(serialized) <= max_size:
        return result

    # Truncate large fields
    result = _truncate_large_fields(result)

    # If still too large, drop items from lists
    result = _reduce_list_sizes(result)

    # Add truncation notice
    result['_truncated'] = True
    result['_original_size'] = len(serialized)

    return result
```

#### 4.8.2 Field Truncation

```python
MAX_DESCRIPTION_LENGTH = 500
MAX_PATTERN_LENGTH = 200

def _truncate_large_fields(data: dict) -> dict:
    """Truncate known large fields."""
    if 'description' in data and len(data.get('description', '')) > MAX_DESCRIPTION_LENGTH:
        data['description'] = data['description'][:MAX_DESCRIPTION_LENGTH] + '...'

    if 'pattern' in data and len(data.get('pattern', '')) > MAX_PATTERN_LENGTH:
        data['pattern'] = data['pattern'][:MAX_PATTERN_LENGTH] + '...'

    return data
```

### 4.9 Dependency Security

#### 4.9.1 Pinned Dependencies

```toml
# pyproject.toml - pin major.minor versions
[project]
dependencies = [
    "mcp>=1.0.0,<2.0.0",
    "pycti>=6.0.0,<7.0.0",
    "pydantic>=2.0.0,<3.0.0",
]
```

#### 4.9.2 Dependency Audit

```bash
# Add to CI/CD pipeline
pip install pip-audit
pip-audit --require-hashes -r requirements.txt
```

### 4.10 Defense in Depth Summary

```
Layer 1: Input Validation (server.py)
    ├── Length limits
    ├── Format validation
    └── Type checking

Layer 2: Input Validation (client.py) ← Defense in depth
    ├── Re-validate lengths
    ├── Re-validate formats
    └── Sanitize values

Layer 3: Query Execution
    ├── Parameterized queries via pycti
    ├── Timeouts on all calls
    └── Rate limiting

Layer 4: Response Processing
    ├── Size limits
    ├── Field truncation
    └── Sensitive field filtering

Layer 5: Error Handling
    ├── Safe error messages
    ├── Internal logging only
    └── No stack traces to clients
```

### 4.11 Security Testing Requirements

```python
# tests/test_security.py - REQUIRED tests

class TestCredentialSafety:
    def test_token_not_in_repr(self): ...
    def test_token_not_in_str(self): ...
    def test_token_not_in_error(self): ...
    def test_token_not_logged(self): ...
    def test_config_not_picklable(self): ...
    def test_token_file_permissions_enforced(self): ...

class TestInputValidation:
    def test_length_checked_before_regex(self): ...
    def test_max_query_length_enforced(self): ...
    def test_max_ioc_length_enforced(self): ...
    def test_malformed_ioc_no_crash(self): ...
    def test_unicode_handling(self): ...
    def test_null_bytes_rejected(self): ...

class TestErrorLeakage:
    def test_no_stack_trace_in_response(self): ...
    def test_no_file_paths_in_response(self): ...
    def test_no_internal_errors_exposed(self): ...
    def test_no_token_in_errors(self): ...

class TestResponseSafety:
    def test_response_size_limited(self): ...
    def test_large_fields_truncated(self): ...
    def test_list_sizes_capped(self): ...

class TestRateLimiting:
    def test_query_rate_limit_enforced(self): ...
    def test_enrichment_rate_limit_enforced(self): ...
    def test_rate_limit_returns_error(self): ...

class TestNetworkSecurity:
    def test_only_http_https_allowed(self): ...
    def test_http_warning_for_remote(self): ...
```

---

## 5. API Design (MCP Tools)

### 5.1 Tool Overview

| Tool | Priority | Description |
|------|----------|-------------|
| `search_threat_intel` | P0 | Unified search across all entity types |
| `lookup_ioc` | P0 | Full context for a specific IOC |
| `search_threat_actor` | P0 | Search APT groups and intrusion sets |
| `search_malware` | P0 | Search malware families |
| `search_attack_pattern` | P0 | Search MITRE ATT&CK techniques |
| `search_vulnerability` | P0 | Search CVEs |
| `get_recent_indicators` | P1 | Recent IOCs from last N days |
| `search_reports` | P1 | Search threat intel reports |
| `get_health` | P1 | Check OpenCTI connectivity |
| `list_connectors` | P2 | List enrichment connectors |
| `enrich_observable` | P2 | Trigger enrichment |

### 5.2 Tool Specifications

#### 5.2.1 search_threat_intel

**Purpose:** Unified search across all entity types

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "query": {
      "type": "string",
      "description": "Search term (IOC, threat actor name, malware, etc.)",
      "maxLength": 1000
    },
    "limit": {
      "type": "integer",
      "description": "Max results per entity type (default: 5, max: 20)",
      "default": 5,
      "minimum": 1,
      "maximum": 20
    }
  },
  "required": ["query"]
}
```

**Response Format:**
```json
{
  "query": "APT29",
  "indicators": [...],
  "threat_actors": [...],
  "malware": [...],
  "attack_patterns": [...],
  "vulnerabilities": [...],
  "reports": [...]
}
```

#### 5.2.2 lookup_ioc

**Purpose:** Full context for a specific IOC with relationships

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "ioc": {
      "type": "string",
      "description": "IOC value (IP, hash, domain, URL)",
      "maxLength": 2048
    },
    "include_relationships": {
      "type": "boolean",
      "description": "Include related entities (default: true)",
      "default": true
    }
  },
  "required": ["ioc"]
}
```

**Response Format:**
```json
{
  "found": true,
  "ioc": "192.168.1.1",
  "ioc_type": "ipv4",
  "indicators": [
    {
      "name": "Malicious IP",
      "pattern": "[ipv4-addr:value = '192.168.1.1']",
      "confidence": 85,
      "created": "2025-01-15T10:00:00Z"
    }
  ],
  "related_threat_actors": ["APT29", "Cozy Bear"],
  "related_malware": ["SUNBURST"],
  "mitre_techniques": ["T1071.001"],
  "source": "opencti"
}
```

#### 5.2.3 search_threat_actor

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "query": {
      "type": "string",
      "description": "Threat actor name or alias",
      "maxLength": 500
    },
    "limit": {
      "type": "integer",
      "default": 10,
      "maximum": 50
    }
  },
  "required": ["query"]
}
```

**Response Format:**
```json
{
  "results": [
    {
      "name": "APT29",
      "aliases": ["Cozy Bear", "The Dukes", "Midnight Blizzard"],
      "description": "Russian SVR-attributed threat actor...",
      "sophistication": "expert",
      "resource_level": "government",
      "primary_motivation": "espionage",
      "country": "Russia"
    }
  ],
  "total": 1
}
```

#### 5.2.4 search_malware

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "query": {
      "type": "string",
      "description": "Malware name or alias",
      "maxLength": 500
    },
    "limit": {
      "type": "integer",
      "default": 10,
      "maximum": 50
    }
  },
  "required": ["query"]
}
```

#### 5.2.5 search_attack_pattern

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "query": {
      "type": "string",
      "description": "MITRE technique ID (T1003) or name",
      "maxLength": 500
    },
    "limit": {
      "type": "integer",
      "default": 10,
      "maximum": 50
    }
  },
  "required": ["query"]
}
```

#### 5.2.6 search_vulnerability

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "query": {
      "type": "string",
      "description": "CVE ID or keyword",
      "maxLength": 500
    },
    "limit": {
      "type": "integer",
      "default": 10,
      "maximum": 50
    }
  },
  "required": ["query"]
}
```

#### 5.2.7 get_recent_indicators

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "days": {
      "type": "integer",
      "description": "Number of days to look back (default: 7, max: 90)",
      "default": 7,
      "minimum": 1,
      "maximum": 90
    },
    "limit": {
      "type": "integer",
      "default": 20,
      "maximum": 100
    }
  }
}
```

#### 5.2.8 get_health

**Purpose:** Check OpenCTI connectivity

**Input Schema:**
```json
{
  "type": "object",
  "properties": {}
}
```

**Response Format:**
```json
{
  "status": "healthy",
  "opencti_available": true,
  "opencti_url": "http://localhost:8080",
  "connector_count": 17
}
```

### 5.3 Response Conventions

**All responses include:**
- Clear structure (not just raw text)
- Type information where relevant
- Confidence levels when available
- Source attribution ("opencti")

**Truncation:**
- Descriptions truncated to 500 chars
- Pattern fields truncated to 200 chars
- Lists capped at requested limit

---

## 6. Error Handling

### 6.1 Error Categories

| Category | Example | Client Message | Action |
|----------|---------|----------------|--------|
| ValidationError | Query too long | "Query exceeds 1000 characters" | Return immediately |
| ConfigurationError | Missing token | "OpenCTI not configured" | Return immediately |
| ConnectionError | Network timeout | "OpenCTI unavailable" | Retry once, then fail |
| QueryError | Invalid filter | "Query failed" | Return immediately |
| InternalError | Unexpected | "Internal server error" | Log, return generic |

### 6.2 Error Response Format

```json
{
  "error": "error_type",
  "message": "Human-readable description",
  "details": {}  // Optional, only for safe details
}
```

### 6.3 Retry Strategy

**Transient failures (retry once):**
- Connection timeout
- Connection reset
- 502/503/504 errors

**Permanent failures (no retry):**
- 401 Unauthorized
- 400 Bad Request
- Validation errors

```python
async def _execute_with_retry(self, func, *args, **kwargs):
    """Execute with single retry for transient failures."""
    try:
        return await asyncio.to_thread(func, *args, **kwargs)
    except (ConnectionError, TimeoutError) as e:
        logger.warning("Transient failure, retrying", extra={"error": str(e)})
        await asyncio.sleep(1)
        try:
            return await asyncio.to_thread(func, *args, **kwargs)
        except Exception as e:
            logger.error("Retry failed", extra={"error": str(e)})
            raise
```

---

## 7. Testing Strategy

### 7.1 Test Categories

| Category | Coverage Target | Purpose |
|----------|-----------------|---------|
| Unit Tests | 90% | Individual functions/methods |
| Integration Tests | Key workflows | End-to-end with mock OpenCTI |
| Security Tests | All attack vectors | Input validation, error leakage |
| Stress Tests | Resource limits | Memory/CPU under load |

### 7.2 Test Structure

```
tests/
├── conftest.py              # Shared fixtures
├── test_server.py           # MCP tool handlers
├── test_client.py           # OpenCTI client methods
├── test_validation.py       # Input validation
├── test_config.py           # Configuration loading
├── test_errors.py           # Error handling
├── test_integration.py      # End-to-end workflows
└── test_security.py         # Security-focused tests
```

### 7.3 Key Test Cases

#### Security Tests (test_security.py)

```python
class TestCredentialSafety:
    """Ensure credentials never leak."""

    def test_token_not_in_repr(self):
        """Config repr doesn't include token."""
        config = Config(opencti_url="http://localhost", opencti_token="secret")
        assert "secret" not in repr(config)
        assert "secret" not in str(config)

    def test_token_not_in_error_messages(self):
        """Errors don't include token."""
        # ... test various error scenarios

    def test_token_not_logged(self):
        """Logging doesn't capture token."""
        # ... capture logs and verify

class TestInputValidation:
    """Input validation security tests."""

    @pytest.mark.parametrize("length", [1001, 5000, 10000])
    def test_query_length_limit(self, length):
        """Reject queries exceeding max length."""
        # ...

    @pytest.mark.parametrize("ioc", MALFORMED_IOCS)
    def test_malformed_ioc_handling(self, ioc):
        """Handle malformed IOCs gracefully."""
        # ...

class TestErrorLeakage:
    """Ensure internal details don't leak."""

    def test_no_stack_trace_in_response(self):
        """Responses don't include stack traces."""
        # ...

    def test_no_file_paths_in_response(self):
        """Responses don't include internal paths."""
        # ...
```

#### Validation Tests (test_validation.py)

```python
class TestIOCValidation:
    """IOC format validation tests."""

    # IPv4
    VALID_IPV4 = ["192.168.1.1", "10.0.0.1", "8.8.8.8"]
    INVALID_IPV4 = ["256.1.1.1", "1.2.3", "not.an.ip"]

    # Hashes
    VALID_MD5 = ["d41d8cd98f00b204e9800998ecf8427e"]
    VALID_SHA256 = ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
    INVALID_HASHES = ["xyz123", "tooshort", "g" * 64]

    @pytest.mark.parametrize("ip", VALID_IPV4)
    def test_valid_ipv4(self, ip):
        # ...
```

### 7.4 Mock Strategy

```python
@pytest.fixture
def mock_opencti_client():
    """Mock OpenCTI client for testing."""
    client = Mock(spec=OpenCTIClient)
    client.is_available.return_value = True
    client.search_indicators.return_value = [
        {"name": "Test IOC", "pattern": "[ipv4-addr:value = '1.2.3.4']"}
    ]
    return client

@pytest.fixture
def server(mock_opencti_client):
    """Server with mocked client."""
    config = Config(
        opencti_url="http://test",
        opencti_token=SecretStr("test-token")
    )
    server = OpenCTIMCPServer(config)
    server.client = mock_opencti_client
    return server
```

---

## 8. Implementation Plan

### 8.1 Phases

```
Phase 1: Core Infrastructure (2-3 hours)
├── config.py         - Configuration management
├── errors.py         - Exception hierarchy
├── validation.py     - Input validation
└── logging.py        - Structured logging

Phase 2: Client Implementation (2-3 hours)
├── client.py         - OpenCTI API client
├── test_client.py    - Client tests
└── test_validation.py - Validation tests

Phase 3: Server Implementation (2-3 hours)
├── server.py         - MCP server
├── __main__.py       - Entry point
└── test_server.py    - Server tests

Phase 4: Testing & Polish (1-2 hours)
├── test_integration.py - E2E tests
├── test_security.py    - Security tests
├── README.md           - Documentation
└── pyproject.toml      - Packaging
```

### 8.2 File Creation Order

1. `src/opencti_mcp/__init__.py`
2. `src/opencti_mcp/errors.py`
3. `src/opencti_mcp/validation.py`
4. `src/opencti_mcp/config.py`
5. `src/opencti_mcp/logging.py`
6. `src/opencti_mcp/client.py`
7. `src/opencti_mcp/server.py`
8. `src/opencti_mcp/__main__.py`
9. `tests/conftest.py`
10. `tests/test_*.py`
11. `pyproject.toml`
12. `README.md`

### 8.3 Dependencies

```toml
[project]
dependencies = [
    "mcp>=1.0.0",
    "pycti>=6.0.0",
    "pydantic>=2.0.0",      # For SecretStr and validation
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0",
    "pytest-asyncio>=0.21",
    "pytest-cov>=4.0",
    "mypy>=1.0",
]
```

---

## 9. Risks and Mitigations

### 9.1 Security Risks

| Risk | Likelihood | Impact | Risk Level | Mitigation | Verification |
|------|------------|--------|------------|------------|--------------|
| Token leakage in logs | Medium | Critical | **HIGH** | SecretStr, log filtering | test_security.py |
| Token leakage in errors | Medium | Critical | **HIGH** | Generic error messages | test_security.py |
| Token file permissions | Medium | Critical | **HIGH** | Enforce chmod 600 | test_security.py |
| ReDoS via input | Medium | Medium | **MEDIUM** | Length-first validation | test_validation.py |
| Log injection | Low | Medium | **LOW** | Sanitize log inputs | test_security.py |
| SSRF via URL config | Low | High | **MEDIUM** | URL validation | test_config.py |
| Response memory exhaustion | Medium | Medium | **MEDIUM** | Size limits, truncation | test_client.py |
| Enrichment API abuse | Medium | Medium | **MEDIUM** | Rate limiting (10/hour) | test_security.py |
| Dependency vulnerabilities | Medium | High | **MEDIUM** | Pin versions, pip-audit | CI pipeline |

### 9.2 Operational Risks

| Risk | Likelihood | Impact | Risk Level | Mitigation | Verification |
|------|------------|--------|------------|------------|--------------|
| OpenCTI API changes | Low | Medium | **LOW** | Pin pycti version | Integration tests |
| OpenCTI unavailable | Medium | Low | **LOW** | Graceful degradation | test_client.py |
| pycti sync blocking | High | Low | **LOW** | asyncio.to_thread() | test_server.py |
| Large result sets | Medium | Medium | **MEDIUM** | Result limits, pagination | test_client.py |
| Query timeout | Medium | Low | **LOW** | Configurable timeouts | test_client.py |

### 9.3 Security Checklist (Pre-Release)

Before releasing, verify:

- [ ] **Credentials**
  - [ ] Token never appears in any log file
  - [ ] Token never appears in any error message
  - [ ] Token file requires 600 permissions
  - [ ] Config object cannot be pickled
  - [ ] `.env` added to `.gitignore`

- [ ] **Input Validation**
  - [ ] Length checked before regex on all inputs
  - [ ] All MAX_* constants enforced
  - [ ] Null bytes rejected
  - [ ] Unicode normalized/handled
  - [ ] No complex regex patterns

- [ ] **Error Handling**
  - [ ] No stack traces to clients
  - [ ] No file paths to clients
  - [ ] No internal state to clients
  - [ ] All exceptions caught and wrapped

- [ ] **Network**
  - [ ] Only http/https schemes accepted
  - [ ] Warning logged for HTTP to remote hosts
  - [ ] Connection timeouts configured

- [ ] **Rate Limiting**
  - [ ] Query rate limit enforced
  - [ ] Enrichment rate limit enforced (stricter)

- [ ] **Responses**
  - [ ] Max response size enforced
  - [ ] Large fields truncated
  - [ ] List sizes capped

- [ ] **Dependencies**
  - [ ] Versions pinned in pyproject.toml
  - [ ] `pip-audit` passes
  - [ ] No known vulnerabilities

- [ ] **Testing**
  - [ ] All test_security.py tests pass
  - [ ] Coverage > 80%
  - [ ] Security tests cannot be skipped

---

## Appendices

### A. Comparison with forensic-triage-mcp

| Aspect | forensic-triage-mcp | opencti-mcp (proposed) |
|--------|---------------------|------------------------|
| Input validation | MAX_* constants, manual checks | Centralized validation.py |
| Credential handling | Module-level token loading | Pydantic SecretStr, Config class |
| Error handling | Generic exception catching | Typed exception hierarchy |
| Logging | Basic logging | Structured JSON logging |
| Testing | 2000+ tests | Similar target with security focus |
| Async handling | asyncio.to_thread in handlers | Centralized async wrapper |

### B. Entity Type Mapping

| CLI --type | OpenCTI Entity | pycti Method |
|------------|----------------|--------------|
| indicator | Indicator | client.indicator.list() |
| threat_actor | IntrusionSet + ThreatActorGroup | client.intrusion_set.list() |
| malware | Malware | client.malware.list() |
| attack_pattern | AttackPattern | client.attack_pattern.list() |
| report | Report | client.report.list() |
| vulnerability | Vulnerability | client.vulnerability.list() |

### C. OpenCTI GraphQL Notes

**pycti handles GraphQL internally.** We use high-level methods:
```python
# Search with filters
client.indicator.list(
    search="query",
    first=10,
    orderBy="created",
    orderMode="desc"
)

# Filter by date
client.indicator.list(
    filters={
        "mode": "and",
        "filters": [
            {"key": "created", "values": [since_date], "operator": "gte"}
        ],
        "filterGroups": []
    }
)
```

---

## Approval Checklist

Before implementation, confirm:

- [ ] Tool set is complete for IR workstation needs
- [ ] Security controls are adequate
- [ ] Error handling approach is acceptable
- [ ] Testing strategy is sufficient
- [ ] Implementation order makes sense

---

**Document Status:** Ready for review
**Next Step:** Await approval to proceed with implementation
