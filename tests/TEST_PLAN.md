# OpenCTI MCP - Comprehensive Test Plan

## Purpose

This test plan ensures the opencti-mcp works reliably with **any** OpenCTI instance a user might have: local Docker, remote self-hosted, Filigran SaaS, AWS/Azure Marketplace, Kubernetes, or behind reverse proxies. The plan covers unit tests (mockable), integration simulation tests (mock network conditions), and live smoke tests (optional, against real instances).

---

## Deployment Matrix

Every scenario below must be considered across these deployment types:

| ID | Deployment | Typical URL | Latency | SSL | Token Source | Notes |
|----|-----------|-------------|---------|-----|-------------|-------|
| D1 | Local Docker Compose | `http://localhost:8080` | <10ms | No | Env var | Most common dev setup |
| D2 | Local Docker (custom port) | `http://localhost:4000` | <10ms | No | Env var | Non-default port |
| D3 | Remote self-hosted (LAN) | `https://opencti.internal:8080` | 1-50ms | Self-signed | Token file | Corporate network |
| D4 | Remote self-hosted (WAN) | `https://opencti.example.com` | 50-200ms | CA-signed | Env var | Internet-facing |
| D5 | Filigran SaaS | `https://tenant.opencti.io` | 100-500ms | CA-signed | Env var | Managed, higher latency |
| D6 | AWS Marketplace | `https://opencti.vpc.amazonaws.com` | 20-100ms | ACM cert | Env var | VPC networking |
| D7 | Azure Marketplace | `https://opencti.azurewebsites.net` | 20-100ms | Azure cert | Env var | Azure networking |
| D8 | Behind reverse proxy | `https://threat-intel.corp.com/opencti` | Variable | Proxy cert | Token file | Path prefix, proxy headers |
| D9 | Kubernetes (internal) | `http://opencti-platform.ns.svc:8080` | <5ms | Optional | K8s secret | Service mesh possible |
| D10 | Air-gapped / isolated | `https://10.0.0.50:8080` | <10ms | Self-signed | Token file | No internet, IP-only |

---

## Test Categories

### 1. Connection Establishment

Tests that the client can connect under all URL/auth variations.

| # | Test | Variables | Mock/Live | Priority |
|---|------|-----------|-----------|----------|
| C1 | Connect with http://localhost:8080 (default) | D1 | Mock | P0 |
| C2 | Connect with https:// URL | D4, D5 | Mock | P0 |
| C3 | Connect with custom port | D2 | Mock | P0 |
| C4 | Connect with IP address (no hostname) | D10 | Mock | P1 |
| C5 | Connect with IPv6 address | `http://[::1]:8080` | Mock | P2 |
| C6 | Connect with URL path prefix | D8 `https://host/opencti` | Mock | P1 |
| C7 | Connect with trailing slash in URL | `http://localhost:8080/` | Mock | P0 |
| C8 | Connect with multiple trailing slashes | `http://localhost:8080///` | Mock | P1 |
| C9 | Token from env var (OPENCTI_TOKEN) | All | Mock | P0 |
| C10 | Token from file (~/.config/opencti-mcp/token) | D3, D10 | Mock | P0 |
| C11 | Token from .env file | D1 | Mock | P1 |
| C12 | Token with leading/trailing whitespace | All | Mock | P0 |
| C13 | Token with newline (from file read) | D3 | Mock | P0 |
| C14 | UUID-format token (OpenCTI default) | All | Mock | P0 |
| C15 | Long API key token (SaaS/EE format) | D5, D6, D7 | Mock | P1 |
| C16 | Token file with wrong permissions (644) | D3 | Mock | P0 |
| C17 | Token file with correct permissions (600) | D3 | Mock | P0 |
| C18 | Reject empty token | All | Mock | P0 |
| C19 | Reject whitespace-only token | All | Mock | P0 |
| C20 | Connect reuses cached client | All | Mock | P0 |
| C21 | Thread-safe concurrent connect calls | All | Mock | P1 |

### 2. SSL/TLS Handling

| # | Test | Variables | Mock/Live | Priority |
|---|------|-----------|-----------|----------|
| S1 | ssl_verify=true with valid CA cert | D4, D5 | Mock | P0 |
| S2 | ssl_verify=true with self-signed cert → error | D3, D10 | Mock | P0 |
| S3 | ssl_verify=false bypasses cert validation | D3, D10 | Mock | P0 |
| S4 | ssl_verify=false logs security warning | D3 | Mock | P1 |
| S5 | OPENCTI_SSL_VERIFY env var parsing (true/false/1/0/yes/no) | All | Mock | P0 |
| S6 | SSL error is classified as transient (retryable) | D4 | Mock | P1 |
| S7 | SSL error message doesn't leak cert details | All | Mock | P1 |
| S8 | HTTP URL for remote host logs security warning | D4 | Mock | P0 |
| S9 | HTTP URL for localhost does NOT warn | D1 | Mock | P0 |
| S10 | HTTP URL for private IP (10.x, 172.16.x, 192.168.x) does NOT warn | D9 | Mock | P1 |

### 3. Timeout and Latency Handling

Critical for cloud/remote instances where latency is 100-500ms.

| # | Test | Variables | Mock/Live | Priority |
|---|------|-----------|-----------|----------|
| T1 | Default timeout is 60s | All | Mock | P0 |
| T2 | OPENCTI_TIMEOUT env var overrides default | All | Mock | P0 |
| T3 | Timeout range validation (1-300s) | All | Mock | P0 |
| T4 | Request completes within timeout (fast instance) | D1 | Mock | P0 |
| T5 | Request times out on slow instance → ConnectionError | D5 | Mock | P0 |
| T6 | Timeout error triggers retry (transient) | D5 | Mock | P0 |
| T7 | Adaptive timeout increases for consistently slow instance | D5, D7 | Mock | P0 |
| T8 | Adaptive timeout decreases for fast instance | D1 | Mock | P1 |
| T9 | Adaptive timeout never goes below 10s floor | All | Mock | P0 |
| T10 | Adaptive timeout never exceeds 300s ceiling | All | Mock | P0 |
| T11 | Adaptive timeout requires 10+ samples before adjusting | All | Mock | P0 |
| T12 | Adaptive timeout requires >25% change to adjust | All | Mock | P0 |
| T13 | Adapted timeout updates pycti client in-place | All | Mock | P0 |
| T14 | Effective timeout shown in get_network_status | All | Mock | P0 |
| T15 | Simulate cloud latency: 200ms avg, 500ms P95 | D5 | Mock | P1 |
| T16 | Simulate intermittent latency spikes (bimodal: 50ms / 2000ms) | D4 | Mock | P1 |
| T17 | connect() uses effective_timeout, not config.timeout_seconds | All | Mock | P0 |

### 4. Retry and Backoff

| # | Test | Variables | Mock/Live | Priority |
|---|------|-----------|-----------|----------|
| R1 | Retry on ConnectionError (max_retries times) | All | Mock | P0 |
| R2 | Retry on TimeoutError | D5 | Mock | P0 |
| R3 | Retry on HTTP 429 (rate limited) | D5, D6 | Mock | P0 |
| R4 | Retry on HTTP 500 (server error) | All | Mock | P0 |
| R5 | Retry on HTTP 502 (bad gateway / reverse proxy) | D8 | Mock | P0 |
| R6 | Retry on HTTP 503 (service unavailable / during deploy) | D5, D9 | Mock | P0 |
| R7 | Retry on HTTP 504 (gateway timeout / cloud LB) | D5, D6, D7 | Mock | P0 |
| R8 | NO retry on HTTP 401 (auth failure) | All | Mock | P0 |
| R9 | NO retry on HTTP 403 (forbidden) | All | Mock | P0 |
| R10 | NO retry on HTTP 404 (not found) | All | Mock | P1 |
| R11 | NO retry on ValidationError | All | Mock | P0 |
| R12 | Exponential backoff: delay doubles each attempt | All | Mock | P0 |
| R13 | Backoff has jitter (10-20%) | All | Mock | P1 |
| R14 | Backoff capped at retry_max_delay (30s default) | All | Mock | P0 |
| R15 | All retries exhausted → raise last exception | All | Mock | P0 |
| R16 | Retry on SSLError (transient cert issue) | D5 | Mock | P1 |
| R17 | Retry on ProxyError | D8 | Mock | P1 |
| R18 | Successful retry records success in circuit breaker | All | Mock | P0 |
| R19 | Failed retry records failure in circuit breaker | All | Mock | P0 |
| R20 | _maybe_adapt_timeout called after successful retry | All | Mock | P0 |

### 5. Circuit Breaker

| # | Test | Variables | Mock/Live | Priority |
|---|------|-----------|-----------|----------|
| CB1 | Circuit starts CLOSED | All | Mock | P0 |
| CB2 | CLOSED → OPEN after threshold failures (default 5) | All | Mock | P0 |
| CB3 | OPEN → fail fast without calling server | All | Mock | P0 |
| CB4 | OPEN → HALF_OPEN after recovery_timeout (default 60s) | All | Mock | P0 |
| CB5 | HALF_OPEN → CLOSED on success (probe succeeds) | All | Mock | P0 |
| CB6 | HALF_OPEN → OPEN on failure (probe fails) | All | Mock | P0 |
| CB7 | Manual reset returns to CLOSED | All | Mock | P0 |
| CB8 | force_reconnect resets circuit breaker | All | Mock | P0 |
| CB9 | Circuit breaker uses monotonic time (immune to clock changes) | All | Mock | P1 |
| CB10 | Concurrent access to circuit breaker is thread-safe | All | Mock | P1 |
| CB11 | OPENCTI_CIRCUIT_THRESHOLD env var override | All | Mock | P0 |
| CB12 | OPENCTI_CIRCUIT_TIMEOUT env var override | All | Mock | P0 |

### 6. Graceful Degradation

Critical for production — when the server goes down, stale data is better than no data.

| # | Test | Variables | Mock/Live | Priority |
|---|------|-----------|-----------|----------|
| GD1 | Circuit open + cache hit → return stale data with degraded flag | All | Mock | P0 |
| GD2 | Circuit open + cache miss → raise ConnectionError | All | Mock | P0 |
| GD3 | Degraded response includes degraded=True indicator | All | Mock | P0 |
| GD4 | FF_GRACEFUL_DEGRADATION=false → no fallback, raise immediately | All | Mock | P0 |
| GD5 | Stale cache used regardless of TTL expiry during degradation | All | Mock | P0 |
| GD6 | Negative cache entries NOT returned during degradation | All | Mock | P1 |
| GD7 | Recovery from degraded state when server comes back | All | Mock | P1 |

### 7. Caching

| # | Test | Variables | Mock/Live | Priority |
|---|------|-----------|-----------|----------|
| CA1 | FF_RESPONSE_CACHING=true enables caching | All | Mock | P0 |
| CA2 | FF_RESPONSE_CACHING=false disables caching | All | Mock | P0 |
| CA3 | Cache respects TTL (60s for search, 300s for entity) | All | Mock | P0 |
| CA4 | Cache evicts LRU when full (500 search, 1000 entity) | All | Mock | P1 |
| CA5 | FF_NEGATIVE_CACHING=true caches "not found" | All | Mock | P0 |
| CA6 | FF_NEGATIVE_CACHING=false skips "not found" caching | All | Mock | P0 |
| CA7 | Negative cache has shorter TTL (30s for search, 60s for entity) | All | Mock | P1 |
| CA8 | get_cache_stats returns accurate metrics | All | Mock | P0 |
| CA9 | Cache thread-safe under concurrent access | All | Mock | P1 |

### 8. Authentication Failure Scenarios

| # | Test | Variables | Mock/Live | Priority |
|---|------|-----------|-----------|----------|
| A1 | Invalid token → clear error message (not "internal error") | All | Mock | P0 |
| A2 | Expired token → clear error message | D5, D6, D7 | Mock | P1 |
| A3 | Revoked token → clear error message | D5 | Mock | P1 |
| A4 | Token with insufficient permissions → specific error | All | Mock | P1 |
| A5 | Auth error is NOT retried (non-transient) | All | Mock | P0 |
| A6 | Auth error doesn't leak token in error message | All | Mock | P0 |
| A7 | Auth error doesn't trip circuit breaker | All | Mock | P1 |
| A8 | Token never appears in logs (SecretStr protection) | All | Mock | P0 |
| A9 | Token never appears in repr/str | All | Mock | P0 |
| A10 | Config cannot be pickled (prevents token serialization) | All | Mock | P0 |

### 9. Network Condition Simulation

Simulate real-world network conditions users will encounter.

| # | Test | Variables | Mock/Live | Priority |
|---|------|-----------|-----------|----------|
| N1 | Simulate packet loss (random failures, 10% rate) | D4, D5 | Mock | P1 |
| N2 | Simulate high latency (500ms constant) | D5 | Mock | P1 |
| N3 | Simulate jittery latency (10ms-2000ms random) | D5, D7 | Mock | P1 |
| N4 | Simulate DNS resolution failure | D4, D5 | Mock | P1 |
| N5 | Simulate connection refused (server down) | All | Mock | P0 |
| N6 | Simulate connection reset (server crash mid-request) | All | Mock | P1 |
| N7 | Simulate slow response (data trickles in) | D5 | Mock | P2 |
| N8 | Simulate server returning garbage/non-JSON | All | Mock | P1 |
| N9 | Simulate reverse proxy returning HTML error page | D8 | Mock | P1 |
| N10 | Simulate HTTP 301/302 redirect | D8 | Mock | P1 |
| N11 | Server goes down mid-session, comes back later | All | Mock | P1 |
| N12 | Simulate rate limiting from cloud provider (HTTP 429 with Retry-After) | D5, D6 | Mock | P1 |

### 10. Proxy Support

| # | Test | Variables | Mock/Live | Priority |
|---|------|-----------|-----------|----------|
| P1 | HTTP_PROXY env var is respected by pycti/requests | D8 | Mock | P1 |
| P2 | HTTPS_PROXY env var is respected | D8 | Mock | P1 |
| P3 | NO_PROXY env var excludes specific hosts | D8 | Mock | P2 |
| P4 | ProxyError classified as transient (retryable) | D8 | Mock | P0 |
| P5 | Proxy auth failure gives clear error | D8 | Mock | P2 |

### 11. URL Edge Cases

| # | Test | Variables | Mock/Live | Priority |
|---|------|-----------|-----------|----------|
| U1 | URL with path prefix: `https://host/opencti/graphql` | D8 | Mock | P1 |
| U2 | URL normalization: trailing slashes stripped | All | Mock | P0 |
| U3 | URL with port in path: `https://host:443` | D5 | Mock | P1 |
| U4 | URL scheme must be http or https (SSRF prevention) | All | Mock | P0 |
| U5 | file:// URL rejected | All | Mock | P0 |
| U6 | ftp:// URL rejected | All | Mock | P0 |
| U7 | URL with username:password@ rejected or warned | All | Mock | P1 |
| U8 | Very long URL handled gracefully | All | Mock | P2 |
| U9 | Unicode in hostname handled (IDN) | D4 | Mock | P2 |
| U10 | Kubernetes service URL: `http://svc.ns.svc.cluster.local:8080` | D9 | Mock | P1 |

### 12. OpenCTI Version Compatibility

| # | Test | Variables | Mock/Live | Priority |
|---|------|-----------|-----------|----------|
| V1 | Works with OpenCTI 5.x API | D1, D4 | Live | P1 |
| V2 | Works with OpenCTI 6.x API | D1, D5 | Live | P0 |
| V3 | Startup validation reports version info | All | Mock | P0 |
| V4 | Version mismatch produces warning, not hard failure | All | Mock | P1 |
| V5 | Missing or changed GraphQL fields handled gracefully | All | Mock | P1 |
| V6 | pycti version compatibility check at import time | All | Mock | P1 |

### 13. Rate Limiting

| # | Test | Variables | Mock/Live | Priority |
|---|------|-----------|-----------|----------|
| RL1 | Query rate limit enforced (60/min default) | All | Mock | P0 |
| RL2 | Enrichment rate limit enforced (10/hour default) | All | Mock | P0 |
| RL3 | Rate limit error includes wait time | All | Mock | P0 |
| RL4 | Rate limit sliding window correctly expires old entries | All | Mock | P0 |
| RL5 | Rate limit thread-safe under concurrent tool calls | All | Mock | P1 |
| RL6 | Server-side rate limit (HTTP 429) triggers client retry | D5 | Mock | P0 |

### 14. Input Validation (All 34 Tools)

| # | Test | Variables | Mock/Live | Priority |
|---|------|-----------|-----------|----------|
| IV1 | Empty query rejected | All | Mock | P0 |
| IV2 | Query exceeding MAX_QUERY_LENGTH (1000) rejected | All | Mock | P0 |
| IV3 | Null bytes in query rejected | All | Mock | P0 |
| IV4 | SQL injection in query sanitized | All | Mock | P0 |
| IV5 | GraphQL injection in query sanitized | All | Mock | P0 |
| IV6 | Unicode normalization in queries | All | Mock | P1 |
| IV7 | IOC validation: IPv4, IPv6, domain, hash, URL, CVE, MITRE | All | Mock | P0 |
| IV8 | Hash normalization (uppercase → lowercase) | All | Mock | P0 |
| IV9 | Limit validation (1-20 for search, 1-100 for indicators) | All | Mock | P0 |
| IV10 | Offset validation (0-500) | All | Mock | P0 |
| IV11 | Date filter validation (ISO format) | All | Mock | P0 |
| IV12 | UUID validation for entity_id | All | Mock | P0 |
| IV13 | STIX pattern validation for create_indicator | All | Mock | P1 |
| IV14 | Read-only mode blocks write operations | All | Mock | P0 |
| IV15 | Length check happens BEFORE regex (ReDoS prevention) | All | Mock | P0 |

### 15. Response Handling

| # | Test | Variables | Mock/Live | Priority |
|---|------|-----------|-----------|----------|
| RH1 | Normal response formatted as TextContent JSON | All | Mock | P0 |
| RH2 | Large response truncated at MAX_RESPONSE_SIZE (1MB) | All | Mock | P0 |
| RH3 | Empty results return valid empty JSON | All | Mock | P0 |
| RH4 | Description fields truncated to prevent overflow | All | Mock | P0 |
| RH5 | STIX pattern fields truncated | All | Mock | P1 |
| RH6 | Response doesn't include sensitive fields | All | Mock | P0 |
| RH7 | Error response uses sanitized safe_message | All | Mock | P0 |
| RH8 | Error response never includes stack traces | All | Mock | P0 |

### 16. Startup and Lifecycle

| # | Test | Variables | Mock/Live | Priority |
|---|------|-----------|-----------|----------|
| LC1 | Startup with valid config succeeds | All | Mock | P0 |
| LC2 | Startup with missing token fails with clear message | All | Mock | P0 |
| LC3 | Startup validation connects and reports version | All | Mock | P0 |
| LC4 | Startup validation failure is warning, not fatal | All | Mock | P0 |
| LC5 | FF_STARTUP_VALIDATION=false skips validation | All | Mock | P0 |
| LC6 | Server runs on stdio transport | All | Mock | P0 |
| LC7 | KeyboardInterrupt shuts down cleanly | All | Mock | P1 |
| LC8 | Unhandled exception logged and exits with code 1 | All | Mock | P1 |
| LC9 | Background adaptive probing starts and stops cleanly | All | Mock | P1 |
| LC10 | force_reconnect works mid-session | All | Mock | P0 |

### 17. Logging and Observability

| # | Test | Variables | Mock/Live | Priority |
|---|------|-----------|-----------|----------|
| LO1 | JSON log format produces valid JSON | All | Mock | P0 |
| LO2 | Text log format for development | All | Mock | P0 |
| LO3 | Token never appears in logs | All | Mock | P0 |
| LO4 | Sensitive fields redacted in logs | All | Mock | P0 |
| LO5 | Control characters escaped in logs | All | Mock | P1 |
| LO6 | Long values truncated in logs | All | Mock | P1 |
| LO7 | Structured log includes timestamp, level, service | All | Mock | P0 |
| LO8 | Warning+ logs include file location | All | Mock | P0 |
| LO9 | get_network_status returns all diagnostic info | All | Mock | P0 |

---

## Live Smoke Test Protocol

For users/contributors who have access to an OpenCTI instance. Run with:

```bash
OPENCTI_URL=https://your-instance OPENCTI_TOKEN=your-token pytest tests/test_live_smoke.py -v
```

### Smoke Tests (require live instance)

| # | Test | What it Validates |
|---|------|-------------------|
| LS1 | Connect and get version | Basic connectivity, auth, GraphQL endpoint |
| LS2 | Search threat actors (limit=1) | Query pipeline, response parsing |
| LS3 | Search malware (limit=1) | Different entity type |
| LS4 | Get recent indicators (days=1) | Date filtering, indicator parsing |
| LS5 | Lookup known IOC (8.8.8.8) | IOC pipeline, observable resolution |
| LS6 | Get network status | Adaptive metrics, latency measurement |
| LS7 | Force reconnect then query | Reconnection recovery |
| LS8 | Get cache stats | Cache system health |
| LS9 | Search with filters (confidence_min, created_after) | Filter pipeline |
| LS10 | Get entity by ID (if ID known) | Direct entity fetch |

### Live Environment Matrix

Document which deployments have been validated:

| Deployment | Version | Last Tested | Result | Notes |
|-----------|---------|-------------|--------|-------|
| Local Docker | 6.x | | | |
| Filigran SaaS | | | | |
| AWS Marketplace | | | | |
| Azure Marketplace | | | | |
| Self-hosted (LAN) | | | | |
| Behind nginx proxy | | | | |

---

## Implementation Priorities

### Phase 1 — Core Reliability (P0, ~60 tests)
All P0 tests. These are non-negotiable — any failure here means the MCP is broken for that deployment type. Focus on:
- Connection with all URL/token formats
- Timeout defaults and adaptive behavior
- Retry for transient errors, no retry for auth errors
- Circuit breaker state machine
- Input validation on all tools
- Error message safety (no token/stack leakage)

### Phase 2 — Production Resilience (P1, ~50 tests)
P1 tests that cover real-world production scenarios:
- SSL/TLS edge cases
- Network condition simulation
- Graceful degradation
- Concurrent access safety
- Cloud-specific latency patterns
- Proxy support verification

### Phase 3 — Edge Cases (P2, ~15 tests)
P2 tests for rare but possible scenarios:
- IPv6, IDN hostnames
- Proxy auth
- Slow-drip responses
- Very long URLs

### Phase 4 — Live Validation
Run smoke tests against each deployment type in the matrix. Record results. This is the final proof that the mock-based tests correctly model real behavior.

---

## Test Infrastructure Needed

### Mock Framework
- `unittest.mock` for pycti client mocking
- `time.monotonic` patching for circuit breaker timing
- `threading.Event` for concurrent access tests
- Custom fixtures for network condition simulation (latency injection, error injection)

### Network Simulation Fixtures

```python
@pytest.fixture
def slow_client(mock_config):
    """Simulate a cloud instance with 200ms avg latency."""
    # Inject 200ms delay into every pycti call

@pytest.fixture
def flaky_client(mock_config):
    """Simulate 10% packet loss with random failures."""
    # Randomly fail 1 in 10 calls with ConnectionError

@pytest.fixture
def degraded_client(mock_config):
    """Simulate server that's up but responding with 502s."""
    # Return HTTP 502 for first N calls, then succeed
```

### Live Test Environment
- `OPENCTI_TEST_URL` and `OPENCTI_TEST_TOKEN` env vars
- `@pytest.mark.live` marker to skip without credentials
- Separate `conftest.py` for live fixtures

---

## Coverage Gaps to Close (Current → Target)

| Area | Current | Target | Gap |
|------|---------|--------|-----|
| Connection URL variants | 3 tests | 21 tests | Path prefixes, IPv6, K8s URLs |
| SSL/TLS scenarios | 2 tests | 10 tests | Self-signed, cert errors, warnings |
| Timeout adaptive loop | 11 tests | 17 tests | Cloud latency simulation |
| Retry classification | 8 tests | 20 tests | All HTTP codes, proxy errors |
| Auth failure handling | 5 tests | 10 tests | Expired/revoked tokens, error clarity |
| Network simulation | 0 tests | 12 tests | Entirely new category |
| Proxy support | 0 tests | 5 tests | Entirely new category |
| Live smoke tests | 12 tests (broken) | 10 tests (working) | Fix existing, add env matrix |
| Graceful degradation | 4 tests | 7 tests | Recovery, negative cache exclusion |

**Total new tests needed: ~80-100**
**Total test count target: ~1,650+**
