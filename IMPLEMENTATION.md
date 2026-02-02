# OpenCTI MCP Implementation

Technical architecture and implementation details for the OpenCTI MCP Server.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              MCP Client                                      │
│                        (Claude Code, Inspector)                              │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ MCP Protocol (JSON-RPC over stdio)
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            OpenCTIMCPServer                                  │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                          server.py                                   │    │
│  │  • list_tools() → 30+ tool definitions                              │    │
│  │  • call_tool() → dispatch to handlers                               │    │
│  │  • Error handling → safe messages                                   │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                    │                                         │
│                                    │ async dispatch                          │
│                                    ▼                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                          client.py                                   │    │
│  │  • Search methods (20+)                                             │    │
│  │  • Write methods (4)                                                │    │
│  │  • Formatting methods (15+)                                         │    │
│  │  • Rate limiting (thread-safe)                                      │    │
│  │  • Circuit breaker                                                  │    │
│  │  • Retry with exponential backoff                                   │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                    │                                         │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐           │
│  │  config.py │  │validation.py│ │ adaptive.py│  │  errors.py │           │
│  │ SecretStr  │  │ IOC detect  │  │ Latency    │  │ Safe msgs  │           │
│  │ Token load │  │ Length-first│  │ P50/95/99  │  │ Hierarchy  │           │
│  │ URL valid  │  │ Truncation  │  │ Circuit    │  │            │           │
│  └────────────┘  └────────────┘  └────────────┘  └────────────┘           │
│  ┌────────────┐  ┌────────────────────────────┐                           │
│  │  cache.py  │  │      feature_flags.py      │                           │
│  │ TTL cache  │  │ FF_RESPONSE_CACHING etc.   │                           │
│  │ LRU evict  │  │ Environment-based toggles  │                           │
│  └────────────┘  └────────────────────────────┘                           │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ pycti (GraphQL)
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                               OpenCTI                                        │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐          │
│  │   GraphQL API    │  │    Connectors    │  │    ElasticSearch │          │
│  │   (STIX 2.1)     │  │ (VT, Shodan...)  │  │    (storage)     │          │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘          │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Data Flow

### Query Flow

```
1. MCP Client sends tool call
   ↓
2. server.py receives call_tool(name, arguments)
   ↓
3. Input validation (length, type, format)
   ↓
4. Rate limit check (thread-safe)
   ↓
5. Circuit breaker check
   ↓
6. asyncio.to_thread() → client method
   ↓
7. client.py executes pycti query with retry
   ↓
8. Format response (truncate, sanitize)
   ↓
9. Return JSON via MCP
```

### Write Flow (when enabled)

```
1. Check read_only mode → reject if true
   ↓
2. Use enrichment rate limiter (stricter)
   ↓
3. Log operation (audit trail)
   ↓
4. Execute via pycti create method
   ↓
5. Return result with created entity ID
```

## Module Details

### server.py (~1460 LOC)

**Responsibilities:**
- MCP server initialization
- Tool registration (30+ tools)
- Request dispatch
- Error handling and sanitization

**Key Classes:**
```python
class OpenCTIMCPServer:
    WRITE_TOOLS = frozenset({"create_indicator", "create_note", ...})

    def __init__(self, config: Config):
        self.client = OpenCTIClient(config)
        self.server = Server("opencti-mcp")
        self._register_tools()

    async def _dispatch_tool(self, name: str, arguments: dict) -> dict:
        # Route to appropriate handler
```

**Tool Categories:**
1. Search tools (18) - Query OpenCTI entities
2. Entity tools (5) - Get by ID, relationships
3. Write tools (4) - Create entities (conditional)
4. System tools (3) - Health, connectors, metrics

### client.py (~2780 LOC)

**Responsibilities:**
- OpenCTI API wrapper
- Connection management
- Rate limiting
- Circuit breaker
- Retry logic
- Response caching
- Graceful degradation
- Startup validation
- Response formatting

**Key Classes:**
```python
class CircuitBreaker:
    CLOSED = "closed"    # Normal operation
    OPEN = "open"        # Failing fast
    HALF_OPEN = "half_open"  # Testing recovery

class RateLimiter:
    def check_and_record(self) -> bool:
        # Thread-safe sliding window

class OpenCTIClient:
    def __init__(self, config: Config):
        self._query_limiter = RateLimiter(60, 60)      # 60/min
        self._enrichment_limiter = RateLimiter(10, 3600)  # 10/hour
        self._circuit_breaker = CircuitBreaker(5, 60)
```

**Search Method Pattern:**
```python
def search_entity(self, query, limit=10, offset=0,
                  labels=None, confidence_min=None,
                  created_after=None, created_before=None):
    # 1. Validate inputs
    # 2. Check rate limit
    # 3. Build filters
    # 4. Execute with retry
    # 5. Apply offset/limit
    # 6. Format results
```

### config.py (~390 LOC)

**Responsibilities:**
- Secure configuration loading
- Token management
- URL validation
- Permission checks

**Key Classes:**
```python
class SecretStr:
    """Never exposes value in repr/str/logs"""
    def get_secret_value(self) -> str

@dataclass(frozen=True)
class Config:
    opencti_url: str
    opencti_token: SecretStr
    read_only: bool = True
    timeout_seconds: int = 30
    # ... more settings
```

**Token Loading Precedence:**
1. `OPENCTI_TOKEN` env var
2. `~/.config/opencti-mcp/token`
3. `~/.config/rag/opencti_token` (legacy)
4. `.env` file

### validation.py (~1079 LOC)

**Responsibilities:**
- Input validation
- IOC type detection
- Observable/note type validation
- Date filter validation
- Pattern type validation
- Response truncation
- Hash normalization

**Key Functions:**
```python
def validate_length(value, max_length, field_name):
    """Length-first validation (ReDoS prevention)"""

def validate_ioc(value) -> tuple[bool, str]:
    """Detect IOC type: ipv4, ipv6, hash, domain, url, cve, mitre"""

def validate_observable_types(values) -> list[str] | None:
    """Validate against known STIX SCO types"""

def validate_note_types(values) -> list[str] | None:
    """Validate note types with ASCII-only enforcement"""

def validate_date_filter(value, field_name) -> str | None:
    """ISO8601 date validation with range checks"""

def validate_pattern_type(value) -> str:
    """Validate pattern type against allow-list"""

def truncate_response(data, max_size=50000):
    """Safely truncate large responses"""
```

### adaptive.py (~520 LOC)

**Responsibilities:**
- Latency tracking
- Success rate monitoring
- Dynamic recommendations
- Background probing

**Key Classes:**
```python
@dataclass
class LatencyStats:
    p50: float
    p95: float
    p99: float
    sample_count: int

class AdaptiveMetrics:
    def record_request(self, start_time, success, error_type=None):
        """Record request outcome and latency"""

    def get_adaptive_config(self) -> AdaptiveConfig:
        """Get recommended settings based on observed conditions"""
```

### cache.py (~224 LOC)

**Responsibilities:**
- TTL-based response caching
- LRU eviction when cache full
- Thread-safe operations
- Cache statistics tracking

**Key Classes:**
```python
class TTLCache:
    def __init__(self, ttl_seconds: int, max_size: int = 1000, name: str = ""):
        """Thread-safe TTL cache with LRU eviction."""

    def get(self, key: str) -> tuple[bool, Any]:
        """Get value if present and not expired."""

    def set(self, key: str, value: Any) -> None:
        """Set value with TTL, evicting LRU if full."""

    def get_stats(self) -> dict[str, int]:
        """Return hits, misses, evictions, size."""
```

### feature_flags.py (~119 LOC)

**Responsibilities:**
- Environment-based feature toggles
- Singleton pattern for global access
- Boolean parsing from env vars

**Key Classes:**
```python
@dataclass(frozen=True)
class FeatureFlags:
    response_caching: bool = False      # Cache search results
    graceful_degradation: bool = True   # Return cached on failure
    startup_validation: bool = True     # Test connectivity on start
    version_checking: bool = True       # Check OpenCTI version
    negative_caching: bool = True       # Cache "not found" results
    request_correlation: bool = True    # Add request IDs to logs
    adaptive_timeouts: bool = False     # Dynamic timeout adjustment

    @classmethod
    def load(cls) -> "FeatureFlags":
        """Load from FF_* environment variables."""
```

### errors.py (~110 LOC)

**Error Hierarchy:**
```
OpenCTIMCPError (base)
├── ConfigurationError  # Token missing, bad URL
├── ConnectionError     # Can't reach OpenCTI
├── ValidationError     # Bad input
├── QueryError          # GraphQL errors
└── RateLimitError      # Rate limit exceeded
```

All errors have `safe_message` property that never leaks internals.

## Security Implementation

### Credential Protection

```python
class SecretStr:
    def __repr__(self): return "SecretStr('***')"
    def __str__(self): return "***"
    # Never appears in logs
```

### Token File Security

```python
def _load_token_file(path: Path) -> Optional[str]:
    mode = path.stat().st_mode
    if mode & (stat.S_IRGRP | stat.S_IROTH | ...):
        raise ConfigurationError("Insecure permissions")
```

### Rate Limiting

```python
class RateLimiter:
    def check_and_record(self) -> bool:
        with self._lock:  # Thread-safe
            now = time()
            self._cleanup_unlocked(now)
            if len(self.calls) < self.max_calls:
                self.calls.append(now)
                return True
            return False
```

### Input Validation

```python
def validate_length(value: str, max_length: int, field_name: str):
    """Check length BEFORE regex to prevent ReDoS"""
    if len(value) > max_length:
        raise ValidationError(f"{field_name} exceeds {max_length}")
```

### Configurable Allow-Lists

```python
# Observable types accept standard STIX SCO types + custom extensions
def validate_observable_types(values, extra_types=None):
    allowed = VALID_OBSERVABLE_TYPES
    if extra_types:
        allowed = VALID_OBSERVABLE_TYPES | extra_types
    # Validate against merged set

# Pattern types accept standard + custom extensions
def validate_pattern_type(value, extra_types=None):
    allowed = VALID_PATTERN_TYPES
    if extra_types:
        allowed = VALID_PATTERN_TYPES | frozenset(t.lower() for t in extra_types)
    # Validate against merged set
```

Configure via environment:
```bash
OPENCTI_EXTRA_OBSERVABLE_TYPES=Custom-IOC,Internal-Host  # Case-sensitive
OPENCTI_EXTRA_PATTERN_TYPES=osquery,kql                  # Case-insensitive
```

### Circuit Breaker

```python
def _execute_with_retry(self, func, *args, **kwargs):
    if not self._circuit_breaker.allow_request():
        raise ConnectionError("Circuit breaker open")

    for attempt in range(self.config.max_retries + 1):
        try:
            result = func(*args, **kwargs)
            self._circuit_breaker.record_success()
            return result
        except Exception as e:
            if self._is_transient_error(e):
                delay = self._calculate_backoff(attempt)
                time.sleep(delay)
            else:
                self._circuit_breaker.record_failure()
                raise
```

## OpenCTI Entity Coverage

### STIX Domain Objects (SDOs)

| Entity Type | Search Tool | pycti Method |
|-------------|-------------|--------------|
| Attack-Pattern | `search_attack_pattern` | `attack_pattern.list()` |
| Campaign | `search_campaign` | `campaign.list()` |
| Course-of-Action | `search_course_of_action` | `course_of_action.list()` |
| Grouping | `search_grouping` | `grouping.list()` |
| Identity (Org) | `search_organization` | `identity.list(types=["Organization"])` |
| Identity (Sector) | `search_sector` | `identity.list(types=["Sector"])` |
| Incident | `search_incident` | `incident.list()` |
| Indicator | `search_*` + filters | `indicator.list()` |
| Infrastructure | `search_infrastructure` | `infrastructure.list()` |
| Intrusion-Set | `search_threat_actor` | `intrusion_set.list()` |
| Location | `search_location` | `location.list()` |
| Malware | `search_malware` | `malware.list()` |
| Note | `search_note` | `note.list()` |
| Report | `search_reports` | `report.list()` |
| Threat-Actor | `search_threat_actor` | `threat_actor_group.list()` |
| Tool | `search_tool` | `tool.list()` |
| Vulnerability | `search_vulnerability` | `vulnerability.list()` |

### STIX Cyber Observables (SCOs)

| Observable Type | Access Via |
|-----------------|------------|
| IPv4-Addr | `search_observable`, `lookup_ioc` |
| IPv6-Addr | `search_observable`, `lookup_ioc` |
| Domain-Name | `search_observable`, `lookup_ioc` |
| URL | `search_observable`, `lookup_ioc` |
| StixFile | `search_observable`, `lookup_hash` |
| Email-Addr | `search_observable` |

### STIX Relationships (SROs)

| Relationship | Access Via |
|--------------|------------|
| indicates | `get_relationships` |
| uses | `get_relationships` |
| targets | `get_relationships` |
| attributed-to | `get_relationships` |
| related-to | `get_relationships` |
| Sighting | `search_sighting`, `create_sighting` |

## Filter Implementation

### OpenCTI Filter Format

```python
def _build_filters(self, labels, confidence_min, created_after, created_before):
    filters = []

    if labels:
        filters.append({
            "key": "objectLabel",
            "values": labels[:10],
            "operator": "eq",
            "mode": "or"
        })

    if confidence_min is not None:
        filters.append({
            "key": "confidence",
            "values": [str(confidence_min)],
            "operator": "gte"
        })

    if created_after:
        filters.append({
            "key": "created",
            "values": [created_after],
            "operator": "gte"
        })

    return {"mode": "and", "filters": filters, "filterGroups": []}
```

### Pagination

```python
# Offset-based pagination (fetch extra, then slice)
results = client.entity.list(
    search=query,
    first=limit + offset,  # Fetch extra
    orderBy="created",
    orderMode="desc"
)
results = results[offset:offset + limit]  # Apply offset
```

## Test Coverage

### Test Categories

| Category | Tests | Coverage |
|----------|-------|----------|
| Validation | 95+ | IOC detection, length, truncation, observable/note/date/pattern types |
| New Validations | 71 | Observable types, note types, date filters, pattern types, edge cases |
| Deep Security | 64 | Timing attacks, memory exhaustion, Unicode normalization, protocol injection, state manipulation, boundary stress, concurrent safety, error leakage, config security, fuzzing |
| Comprehensive Security | 102 | Date filter injection, label validation, note/relationship type validation, STIX pattern validation, UUID validation, IOC edge cases, rate limiter/circuit breaker edge cases, truncation, config security, log sanitization, pattern types, hash normalization, OpenCTI data types, Unicode encoding, empty/null inputs, boundary values, error message leakage |
| Security | 56 | Credentials, rate limiting, injection, homoglyphs |
| Client | 35+ | Queries, formatting, errors |
| Server | 30+ | Tool dispatch, error handling |
| Config | 25+ | Token loading, URL validation, env parsing |
| Adaptive | 15+ | Metrics, circuit breaker |
| Logging | 15+ | Context, sanitization, thread-safety |

**Total: 1530 tests**

### Running Tests

```bash
# All tests
pytest

# Specific module
pytest tests/test_security.py

# With coverage
pytest --cov=opencti_mcp --cov-report=html
```

## Performance Considerations

### Query Optimization

- Results limited to prevent memory issues
- Descriptions truncated to 500 chars
- Patterns truncated to 200 chars
- Labels limited to 10 per entity

### Connection Pooling

- Single pycti client per OpenCTIClient instance
- Thread-safe with locks for concurrent access
- Health check cached for 30 seconds

### Adaptive Tuning

- Latency tracked per request
- Recommendations based on P95 latency
- Circuit breaker prevents cascade failures

## Changelog

### 2026-02-02: Feature Flags, Startup Validation, and Response Caching

**Features Implemented:**

| Feature | Description |
|---------|-------------|
| **Feature Flags** | Environment-based feature toggles (FF_ prefix) for gradual rollout |
| **Startup Validation** | Tests API connectivity and token validity on server start |
| **Version Checking** | Warns about incompatible OpenCTI versions (supports 5.x-6.x) |
| **Response Caching** | TTL-based caching for search results (opt-in via FF_RESPONSE_CACHING) |
| **Graceful Degradation** | Returns cached results when circuit breaker is open |
| **Negative Caching** | Caches "not found" results to reduce API calls |
| **Null Byte Detection** | Rejects null bytes in inputs (path truncation prevention) |

**New Files:**
- `src/opencti_mcp/cache.py` - Thread-safe TTL cache with LRU eviction
- `src/opencti_mcp/feature_flags.py` - Feature flag management
- `tests/test_new_features.py` - 20 unit tests for new features
- `tests/test_live_new_features.py` - 12 live integration tests

**New MCP Tools:**
- `force_reconnect` - Reset caches and circuit breaker
- `get_cache_stats` - View response cache statistics

**New Client Methods:**
- `validate_startup()` - Validate configuration and connectivity
- `get_server_info()` - Get server version and status
- `get_last_response_metadata()` - Check if response was from cache/degraded
- `get_cache_stats()` - Get cache hit/miss statistics
- `clear_all_caches()` - Clear all response caches
- `force_reconnect()` - Reset all caches and circuit breaker

**New Environment Variables:**
| Variable | Default | Description |
|----------|---------|-------------|
| `FF_STARTUP_VALIDATION` | `true` | Test API connectivity on startup |
| `FF_VERSION_CHECKING` | `true` | Check OpenCTI version compatibility |
| `FF_RESPONSE_CACHING` | `false` | Cache search results |
| `FF_GRACEFUL_DEGRADATION` | `true` | Return cached results on failure |
| `FF_NEGATIVE_CACHING` | `true` | Cache "not found" results |
| `FF_REQUEST_CORRELATION` | `true` | Add request IDs to logs |
| `FF_ADAPTIVE_TIMEOUTS` | `false` | Dynamically adjust timeouts |

**Test Suite:** 1438 → 1470 tests (32 new feature tests)

---

### 2026-02-02: Configurable Allow-Lists for Custom OpenCTI Instances

**Feature:** Added configurable allow-lists for observable types and pattern types to support customized OpenCTI instances.

**New Environment Variables:**
- `OPENCTI_EXTRA_OBSERVABLE_TYPES` - Comma-separated list of custom observable types (case-sensitive)
- `OPENCTI_EXTRA_PATTERN_TYPES` - Comma-separated list of custom pattern types (case-insensitive)

**Changes:**
| File | Change |
|------|--------|
| `config.py` | Added `_parse_set_env()` helper, `extra_observable_types` and `extra_pattern_types` fields |
| `validation.py` | Updated `validate_observable_types()` and `validate_pattern_type()` to accept `extra_types` parameter |
| `server.py` | Pass config's extra types to validation functions |

**New Tests:** 33 tests in `test_configurable_allowlists.py` covering:
- Environment variable parsing
- Config loading with extra types
- Observable type validation with extras
- Pattern type validation with extras
- Integration and security tests

**Total Tests:** 555 (was 522)

---

### 2026-02-02: Deep Security Assessment Remediation

**Findings Addressed:**

| Severity | Finding | Fix |
|----------|---------|-----|
| MEDIUM-001 | Observable types not validated against known STIX SCO types | Added `validate_observable_types()` with strict allow-list |
| MEDIUM-002 | Note types allow arbitrary strings without validation | Added `validate_note_types()` with ASCII-only character validation |
| MEDIUM-003 | Date filters vulnerable to invalid format injection | Added `validate_date_filter()` with ISO8601 format and range validation |
| LOW-001 | Pattern type defaults silently to "stix" on invalid input | Added `validate_pattern_type()` that raises on invalid types |
| LOW-003 | Rate limiter uses wall clock time (vulnerable to clock adjustments) | Changed `RateLimiter` and `CircuitBreaker` to use `monotonic()` |

**New Validation Functions (validation.py):**
- `VALID_OBSERVABLE_TYPES` - frozenset of 30 valid STIX SCO types
- `validate_observable_types()` - validates list against known types, max 10 items
- `VALID_NOTE_TYPES` - frozenset of 6 valid note types
- `validate_note_types()` - validates with ASCII-only character enforcement, max 5 items
- `_ISO_DATE_PATTERN` - regex for ISO8601 date/datetime parsing
- `validate_date_filter()` - validates format, year (1970-2100), month, day, hour, minute, second
- `VALID_PATTERN_TYPES` - frozenset of 6 valid pattern types
- `validate_pattern_type()` - validates or raises (no silent defaults)

**Updated Handlers (server.py):**
- `search_observable` - validates observable_types and date filters
- `create_note` - validates note_types
- `create_indicator` - uses strict pattern_type validation
- `search_threat_intel` - validates date filters

**Monotonic Time Fix (client.py):**
- Imported `from time import time, monotonic`
- `RateLimiter`: all time comparisons use `monotonic()` instead of `time()`
- `CircuitBreaker`: `_last_failure_time` uses `monotonic()` instead of `time()`
- Prevents attackers from manipulating system clock to bypass rate limits

**New Test Files:**
- `tests/test_new_validations.py` (71 tests) - comprehensive tests for all new validation functions
- `tests/test_deep_security.py` (64 tests) - advanced security scenario tests

**Deep Security Test Categories:**
- Timing attack prevention (constant-time validation behavior)
- Memory exhaustion prevention (nested dicts, wide dicts, long lists, large strings)
- Unicode normalization attacks (combining chars, fullwidth, mathematical alphanumeric)
- Protocol injection (GraphQL, JSON, HTTP header, log injection)
- State manipulation (rate limiter window, circuit breaker transitions)
- Boundary condition stress (max lengths, edge values)
- Concurrent access safety simulation
- Error message information leakage prevention
- Config security (SecretStr behavior)
- Fuzzing-style tests (27 parametrized input patterns)

**Test Suite:** 285 → 420 tests (135 new security tests)

### 2026-02-02: Comprehensive Security Review & Test Design

**Code Review Findings:**

| Finding | Severity | Status | Description |
|---------|----------|--------|-------------|
| Date filters not validated in all handlers | LOW | Documented | `search_threat_actor`, `search_malware`, etc. pass dates directly without `validate_date_filter()`. However, pycti handles escaping and OpenCTI validates format server-side. |
| Labels not validated in all search handlers | LOW | Documented | Search handlers pass labels directly. Write operations validate labels. pycti escapes values. |
| Note type validation accepts any ASCII | INFO | By Design | Allows custom note types for flexibility. Character set restriction prevents injection. |
| Relationship type validation accepts any ASCII | INFO | By Design | Allows custom types for extensibility. Character set restriction prevents injection. |
| Calendar date validation doesn't check leap years | INFO | Documented | Feb 30 passes validation. OpenCTI rejects invalid dates. Defense in depth is maintained. |
| Health check uses wall clock for cache | INFO | Documented | Uses `time()` for 30s cache TTL. Not security-critical as rate limiter/circuit breaker use monotonic time. |

**New Test Coverage (102 tests in test_comprehensive_security.py):**

1. **Date Filter Validation Tests** - Injection attempts, invalid calendar dates, format preservation
2. **Label Validation Tests** - Malicious labels, character set, length limits, empty handling
3. **Note Type Validation Tests** - Normalization, character restrictions, accept behavior
4. **Relationship Type Validation Tests** - Character restrictions, length limits
5. **STIX Pattern Validation Tests** - Valid patterns, bracket validation, null bytes, length
6. **Observable Type Validation Tests** - All valid types, case sensitivity, max items
7. **UUID Validation Tests** - Valid formats, length, format, injection attempts
8. **IOC Validation Edge Cases** - IPv4, IPv6, CIDR, domain, CVE, MITRE ID boundaries
9. **Rate Limiter/Circuit Breaker Tests** - Exact limits, wait time, zero max, thresholds
10. **Truncation Edge Cases** - Deep nesting, wide dicts, mixed structures, metadata
11. **Config Security Tests** - Secret hiding, comparison, pickle prevention, URL validation
12. **Log Sanitization Tests** - Control chars, sensitive fields, truncation
13. **Pattern Type Validation Tests** - All types, normalization, invalid handling
14. **Hash Normalization Tests** - Prefix removal, case normalization, whitespace
15. **Concurrent Access Tests** - Thread safety simulation, state consistency
16. **OpenCTI Data Types Tests** - TLP labels, confidence boundaries, pattern types
17. **Unicode/Encoding Tests** - Homoglyphs, special Unicode, fullwidth, mathematical
18. **Empty/Null Input Tests** - Consistent handling across all validators
19. **Boundary Value Tests** - Query length, IOC length, date years, UUID lists
20. **Error Message Leakage Tests** - No sensitive info in error messages

**Test Suite:** 420 → 522 tests (102 comprehensive security tests added)

### 2026-02-02: Functionality Correctness Audit

**Handler/Schema Alignment Fixes (server.py):**
- `search_tool` handler now passes offset/labels/dates to client
- `search_infrastructure` handler now passes offset/labels/dates to client
- Updated `search_attack_pattern` schema to expose offset/labels/date filters
- Updated `search_vulnerability` schema to expose offset/labels/date filters
- Updated `search_tool` schema to expose offset/labels/date filters
- Updated `search_infrastructure` schema to expose offset/labels/date filters

**Config Robustness Fix (config.py):**
- Added `_parse_int_env()` and `_parse_float_env()` helper functions
- Environment variables with invalid values now log warning and use defaults
- Previously: `OPENCTI_TIMEOUT=abc` would crash with ValueError
- Now: Uses default (30) and logs warning

**New Tests (9 tests in test_security.py):**
- Environment variable parsing edge cases
- Invalid value handling verification
- Default value fallback tests

**Test Suite:** All 285 tests passing

### 2026-02-02: External Security Audit Fixes

**IDN Homograph Attack Prevention (validation.py):**
- Replaced `c.isalnum()` with explicit ASCII character sets in domain validation
- Replaced `tld.isalpha()` with ASCII-only alphabet validation
- Replaced `c.isalnum()` with ASCII-only validation in relationship type validation
- Added ASCII character set constants: `_ASCII_ALPHA`, `_ASCII_ALNUM`, `_ASCII_DIGITS`
- Prevents homoglyph attacks using Cyrillic, Greek, or other Unicode lookalikes

**Thread-Safety Fix (logging.py):**
- Added `threading.Lock()` to `RequestContextFilter` class
- Protected `_context` dict access in `set_request_id()`, `clear_request_id()`, and `filter()`
- Prevents race conditions when used with `asyncio.to_thread()`

**New Security Tests (7 additional tests):**
- `test_homoglyph_in_domain_rejected` - Cyrillic 'а' in domain
- `test_greek_letters_in_domain_rejected` - Greek 'ο' in domain
- `test_cyrillic_tld_rejected` - Cyrillic characters in TLD
- `test_homoglyph_in_relationship_type_rejected` - Homoglyphs in relationship types
- `test_unicode_digits_in_relationship_rejected` - Fullwidth digits
- `test_ascii_domain_accepted` - Valid ASCII domains including Punycode IDN
- `test_ascii_relationship_types_accepted` - Valid ASCII types

**Test Suite:** 276 → 285 tests passing (after adding 9 env var tests)

### 2026-02-02: High-Threat Security Hardening

**Security Hardening for Public Deployment:**
- Added UUID validation for all entity/connector IDs - prevents injection via malformed IDs
- Added STIX pattern validation - prevents pattern injection attacks
- Added label format validation - restricts to safe character set
- Added relationship type validation - prevents injection via type names
- Added comprehensive security test suite (49 new tests)

**New Validation Functions (validation.py):**
- `validate_uuid()` - Strict UUID format validation
- `validate_uuid_list()` - Batch UUID validation with limits
- `validate_label()` / `validate_labels()` - Safe character validation
- `validate_relationship_types()` - Type name validation
- `validate_stix_pattern()` - Basic STIX pattern syntax validation

**Updated Handlers (server.py):**
- `get_entity` - Now validates entity_id as UUID
- `get_relationships` - Validates entity_id and relationship_types
- `create_indicator` - Validates STIX pattern and labels
- `create_note` - Validates all entity_ids as UUIDs
- `create_sighting` - Validates indicator_id and sighted_by_id
- `trigger_enrichment` - Validates entity_id and connector_id

### 2026-02-02: Code Review Fixes

**Critical Bug Fix:**
- Fixed missing `ValidationError` import in `client.py` - would cause `NameError` when validation fails in `create_note()`

**Functionality Fixes:**
- Fixed `search_threat_intel` to pass filter parameters (labels, confidence_min, created_after, created_before) to `unified_search()`
- Updated `unified_search()` to accept and propagate filter parameters to all sub-searches

**Code Quality:**
- Moved inline imports (`import random`, `import time as time_module`) to module level in `client.py`
- All 269 tests passing
