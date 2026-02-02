# OpenCTI MCP Design Review

**Date:** 2026-02-02
**Reviewer:** Third-party design review
**Sources:** [OpenCTI Documentation](https://docs.opencti.io/latest/), [pycti API](https://www.mickaelwalter.fr/opencti-use-the-api/), [GraphQL API](https://docs.opencti.io/latest/reference/api/)

---

## Executive Summary

The OpenCTI MCP server provides **read-only search access** to approximately **30%** of OpenCTI's entity types and **0%** of write operations. While security controls are well-implemented, significant functionality gaps exist that limit usefulness for incident response workflows.

| Category | Score | Notes |
|----------|-------|-------|
| Security | ★★★★☆ | Strong input validation, credential protection, rate limiting |
| Feature Coverage | ★★☆☆☆ | Missing major entity types and all write operations |
| Production Readiness | ★★★★☆ | Good resilience patterns (circuit breaker, retries, adaptive) |
| API Design | ★★★☆☆ | Consistent but limited; no advanced filtering |

---

## 1. Missing Entity Types (HIGH PRIORITY)

### OpenCTI Entity Categories vs. MCP Coverage

| Category | OpenCTI Entities | MCP Coverage |
|----------|------------------|--------------|
| **Threats** | Campaigns, Threat Actors, Intrusion Sets | ⚠️ Partial (no Campaigns) |
| **Arsenal** | Malware, Tools, Vulnerabilities | ⚠️ Partial (no Tools) |
| **Techniques** | Attack Patterns, Courses of Action | ⚠️ Partial (no CoA) |
| **Observations** | Indicators, Observables, Artifacts | ⚠️ Partial (no Artifacts) |
| **Events** | Incidents, Sightings | ❌ None |
| **Cases** | Incident Response, RFI, RFT | ❌ None |
| **Analysis** | Reports, Groupings, Malware Analyses | ⚠️ Partial (only Reports) |
| **Entities** | Sectors, Organizations, Systems, Individuals | ❌ None |
| **Locations** | Countries, Regions, Cities | ❌ None |
| **Infrastructure** | Infrastructure objects | ❌ None |

### Critical Missing for IR Workflows

1. **Campaigns** - Essential for tracking ongoing threat activity
2. **Incidents** - Case management integration
3. **Sightings** - Detection event correlation
4. **Infrastructure** - C2 servers, hosting providers
5. **Tools** - Legitimate tools used maliciously (PsExec, Mimikatz as tool vs. malware)
6. **Organizations** - Victim identification, vendor tracking
7. **Observables** - Raw SCOs separate from indicators

---

## 2. Missing Operations (HIGH PRIORITY)

### Read Operations

| Operation | Status | Impact |
|-----------|--------|--------|
| Search by ID | ❌ Missing | Cannot get specific entity |
| Get relationships | ⚠️ Partial | Only from IOC context |
| Advanced filters | ❌ Missing | No label/confidence/date filters |
| Pagination | ❌ Missing | Max 100 results hard limit |
| Export STIX | ❌ Missing | No interoperability |
| Get entity history | ❌ Missing | No audit trail |

### Write Operations (All Missing)

| Operation | Use Case |
|-----------|----------|
| `create_indicator` | Add IOC from investigation |
| `create_observable` | Add technical artifact |
| `create_sighting` | Record detection event |
| `create_note` | Add analyst annotation |
| `create_opinion` | Add analyst assessment |
| `add_relationship` | Link entities together |
| `add_label` | Tag with custom labels |
| `trigger_enrichment` | Request VT/Shodan enrichment |
| `promote_to_indicator` | Observable → Indicator |

### Impact Assessment

Without write operations, the MCP is **query-only**. Analysts cannot:
- Document findings back to OpenCTI
- Create IOCs from investigation
- Add notes to threat intel
- Trigger enrichment workflows
- Link evidence to threat actors

---

## 3. Security Assessment

### Strengths ✓

| Control | Implementation |
|---------|----------------|
| Credential Protection | SecretStr, no logging, pickle-blocked |
| Input Validation | Length-first (ReDoS prevention), type validation |
| Rate Limiting | Thread-safe, separate query/enrichment limits |
| Error Handling | Safe messages, no stack trace exposure |
| Connection Security | SSL verification, timeout enforcement |
| Token File Security | 600 permissions enforced |

### Gaps to Address

| Issue | Risk | Recommendation |
|-------|------|----------------|
| No audit logging | LOW | Add query audit log for compliance |
| No RBAC awareness | LOW | Document token permission inheritance |
| URL in health response | LOW | Consider removing from response |
| Write ops if added | HIGH | Need confirmation prompts, role checks |

### Security Considerations for Write Operations

If write operations are added:

1. **Confirmation Required** - Destructive operations need explicit confirmation
2. **Role Validation** - Check token has write permissions before attempting
3. **Input Sanitization** - STIX pattern validation for indicators
4. **Rate Limiting** - Stricter limits for writes
5. **Audit Trail** - Log all write operations with correlation IDs

---

## 4. API Design Issues

### Current Tools

```
search_threat_intel    - Unified search (good)
lookup_ioc             - IOC context (good)
search_threat_actor    - Threat actors (good)
search_malware         - Malware (good)
search_attack_pattern  - MITRE techniques (good)
search_vulnerability   - CVEs (good)
get_recent_indicators  - Recent IOCs (good)
search_reports         - Reports (good)
get_health             - Health check (good)
list_connectors        - Enrichment connectors (good)
get_network_status     - Adaptive metrics (good)
```

### Missing Tool Patterns

```
# Entity-specific tools needed:
search_campaign        - Campaign search
search_incident        - Incident/case search
search_tool            - Tool search (LOLBins, etc.)
search_infrastructure  - C2/hosting search
search_organization    - Organization search
search_observable      - Observable search (vs indicators)
search_sighting        - Sighting search

# Advanced search needed:
get_entity             - Get by ID
get_relationships      - Get entity relationships
search_by_label        - Filter by labels
search_by_date_range   - Temporal filtering

# Write tools needed (with safety):
create_indicator       - Create IOC
create_note            - Add note to entity
create_sighting        - Record detection
trigger_enrichment     - Request enrichment
```

### Filter Support

Current: Only `search` term supported
Needed:
- `labels` - Filter by TLP, custom labels
- `confidence` - Minimum confidence threshold
- `created_after` / `created_before` - Date range
- `source` - Filter by data source
- `relationship_type` - Filter by relationship

---

## 5. Functional Gaps

### Hash Lookup Not Exposed

`lookup_hash()` exists in client but no MCP tool exposes it.

### Enrichment Not Triggerable

`_enrichment_limiter` exists but no `trigger_enrichment` tool.

### Relationship Data Limited

Current relationship output:
```json
{
  "related_threat_actors": ["APT29"],
  "related_malware": ["SUNBURST"]
}
```

Missing:
- Relationship type (indicates, uses, targets)
- Confidence level
- First/last seen dates
- Source attribution

### No STIX Bundle Support

Cannot export or understand STIX 2.1 bundles, limiting interoperability.

---

## 6. Production Concerns

### Version Compatibility

pycti version must match OpenCTI version. No version check or warning exists.

**Recommendation:** Add version compatibility check on connect.

### Connection Pooling

Single connection per client instance. High concurrency may cause issues.

**Recommendation:** Consider connection pool for high-load scenarios.

### Background Probing

`start_adaptive_probing()` exists but not auto-started or exposed via tool.

**Recommendation:** Add configuration option for auto-start.

---

## 7. Recommended Improvements

### Phase 1: Complete Read Coverage (Priority: HIGH)

1. Add missing entity search tools:
   - `search_campaign`
   - `search_tool`
   - `search_infrastructure`
   - `search_incident`
   - `search_observable`
   - `search_sighting`

2. Add get-by-ID tool:
   - `get_entity(id, type)`

3. Add relationship tools:
   - `get_relationships(entity_id, direction, types)`

4. Expose hash lookup:
   - `lookup_hash`

### Phase 2: Advanced Filtering (Priority: MEDIUM)

1. Add filter support to all search tools:
   ```json
   {
     "query": "APT29",
     "filters": {
       "labels": ["tlp:amber"],
       "confidence_min": 70,
       "created_after": "2024-01-01"
     }
   }
   ```

2. Add pagination support:
   ```json
   {
     "query": "...",
     "limit": 50,
     "offset": 100
   }
   ```

### Phase 3: Write Operations (Priority: HIGH for IR)

1. Safe write tools with confirmation:
   - `create_indicator` - Create IOC with pattern
   - `create_note` - Add note to existing entity
   - `create_sighting` - Record detection event

2. Enrichment triggering:
   - `trigger_enrichment(entity_id, connector_id)`

3. Relationship creation:
   - `add_relationship(from_id, to_id, type)`

### Phase 4: Operational Features (Priority: LOW)

1. STIX export:
   - `export_stix(entity_ids)`

2. Version compatibility:
   - Check pycti vs OpenCTI version on connect

3. Audit logging:
   - Log all tool calls with correlation IDs

---

## 8. Security Recommendations for Writes

If implementing write operations:

```python
# 1. Add write permission check
async def _check_write_permission(self) -> bool:
    """Verify token has write permissions."""
    # Query user capabilities from OpenCTI
    pass

# 2. Add confirmation for creates
class CreateIndicatorArgs(BaseModel):
    pattern: str
    name: str
    confidence: int = 50
    confirm: bool = False  # Require explicit confirmation

# 3. Add stricter rate limits
WRITE_RATE_LIMIT = 10  # per minute vs 60 for reads

# 4. Add audit logging
def log_write_operation(tool: str, entity_id: str, user: str):
    logger.info("AUDIT", extra={
        "action": "create",
        "tool": tool,
        "entity_id": entity_id,
        "correlation_id": get_correlation_id()
    })
```

---

## 9. Summary of Action Items

| Priority | Item | Effort |
|----------|------|--------|
| HIGH | Add `search_campaign` tool | Low |
| HIGH | Add `search_tool` tool | Low |
| HIGH | Add `get_entity` by ID tool | Low |
| HIGH | Expose `lookup_hash` as tool | Low |
| HIGH | Add `create_indicator` tool | Medium |
| HIGH | Add `create_note` tool | Medium |
| MEDIUM | Add filter support to searches | Medium |
| MEDIUM | Add pagination support | Medium |
| MEDIUM | Add `trigger_enrichment` tool | Low |
| MEDIUM | Add `get_relationships` tool | Medium |
| LOW | Add STIX export | High |
| LOW | Add version compatibility check | Low |
| LOW | Add audit logging | Medium |

---

## 10. Conclusion

The OpenCTI MCP provides a **solid foundation** with good security controls and production resilience patterns. However, it currently exposes only a fraction of OpenCTI's capabilities:

- **~30%** of entity types searchable
- **0%** of write operations
- **No** advanced filtering
- **No** relationship exploration beyond IOC context

For effective incident response integration, the MCP needs:
1. Complete entity type coverage
2. Write operations for documentation
3. Relationship exploration tools
4. Advanced filtering capabilities

The security architecture is sound and can be extended to safely support write operations with appropriate controls.
