# T-G5a: audit-routing investigation findings (code-only)

## Test under investigation

`tests/integration/test_m4d_multi_tenant.py::test_per_tenant_audit_routing`
(skip-marked at commit 3e628e3, M5a carry-forward).

Failure mode reported in 3e628e3 commit body: "the tenant_b audit
event still doesn't land in tenant-b-audit-* ... event missing from
index entirely, not appearing in the cross-tenant index either".

## Code paths inspected

- `src/wazuh_mcp/observability/audit.py` - `MultiSinkAuditEmitter.emit`
  + `start`/`stop`
- `src/wazuh_mcp/observability/sinks/wazuh_indexer.py` - `WazuhIndexerSink._drain_loop`,
  `_send_with_retry`, `_ensure_template`
- `src/wazuh_mcp/observability/sinks/base.py` - `QueuedSink.submit`
  + `_drain_loop` lifecycle
- `src/wazuh_mcp/wazuh/indexer.py` - `IndexerClient.bulk` + `put_index_template`
- `src/wazuh_mcp/wazuh/indexer_pool.py` - `IndexerClientPool.acquire`
- `src/wazuh_mcp/server.py` - `_build_per_tenant_sinks` (line 143-159)
  + `build_http_app` audit_emitter wiring (line 442-449)
- `src/wazuh_mcp/transport/http.py` - lifespan that calls
  `audit_emitter.start()` (line 180-188)
- `tests/integration/conftest.py` - `mcp_http_server_audit_sinks` fixture
- `tests/integration/test_m4d_multi_tenant.py` - the test body

## Hypotheses evaluated

### H1: QueuedSink flush not draining within 5s window

**Evidence**:
- `WazuhIndexerSink._drain_loop` (wazuh_indexer.py:90-110) uses
  `flush_ms=200` (200ms batch deadline) and `batch=1` per the fixture
  config. With batch=1 the inner accumulator loop exits as soon as one
  event arrives - the drain hits `_send_with_retry` immediately.
- `_send_with_retry` retry budget: `max_attempts=5`,
  `backoff_base=0.1s`, doubling. Worst-case time before final drop:
  0.1 + 0.2 + 0.4 + 0.8 + 1.6 = 3.1s. Comfortably inside the 5s test
  sleep.
- `audit_emitter.start()` is called in the ASGI lifespan
  (transport/http.py:182), so the drain task is alive before any
  request hits the server.
- `MultiSinkAuditEmitter.emit` (audit.py:150-153) is synchronous and
  routes to the per-tenant sink immediately.

**Verdict**: Unlikely. Timing budget is generous; drain task lifecycle
is correct.

### H2: Admin auth missing tenant-b indexer write permission

**Evidence**:
- Both `local` and `tenant_b` use `admin/admin` in the fixture's
  secrets.yaml (conftest.py:336-345) and point at the same indexer
  (`https://localhost:9200`).
- Wazuh-indexer's `admin` user is mapped to `all_access` role by
  default - allows bulk to any non-system index.
- `tenant-b-audit-*` is not a system index and not specially
  protected.

**Verdict**: Highly unlikely. Same admin creds work for `local` and
the `raw_indexer_client` query side; if `admin` could not write
`tenant-b-audit-*` it could not search it either.

### H3: Index template install bug + silent retry exhaustion

**Evidence**:
- `_INDEX_TEMPLATE_BODY` (wazuh_indexer.py:23-46) hardcodes
  `"index_patterns": ["wazuh-mcp-audit-*"]`. The fixture configures
  `index_prefix: tenant-b-audit` and `index_prefix: local-audit` -
  **neither matches the template's `index_patterns`**.
- The template name varies (`{prefix}-template`) so PUTs for both
  tenants succeed on the indexer side. But the template never applies
  to the actual write target (`tenant-b-audit-YYYY.MM.DD`).
- Without a matching template, OpenSearch dynamic-maps the index. The
  `tenant` field becomes `text` + `.keyword` multi-field. The test's
  `{"match": {"tenant": "tenant_b"}}` query against a `text` field
  with the standard analyzer should still match (underscore is treated
  as alphanumeric by Lucene's standard tokenizer, so "tenant_b" tokens
  to ["tenant_b"]).
- `_send_with_retry` catches a broad `Exception` (wazuh_indexer.py:123)
  - includes both template install failures AND bulk write failures.
  After 5 attempts, both events drop via `_safe_record_drop` with
  reason "delivery_failed". **There is no log surface here** beyond
  the metric counter; an operator (or test harness) querying the
  index sees nothing.
- The `bulk()` call (wazuh/indexer.py:56-70) does NOT pass
  `?refresh=wait_for` - so even on a successful write, the doc is
  not searchable until OpenSearch's next refresh (default 1s). This
  alone is fine inside the test's 5s window.

**Verdict**: **Most likely root cause family.** The template
mismatch isn't fatal on its own (dynamic mapping covers it), but the
combination of (a) silent drop on retry exhaustion + (b) no
visibility into bulk-response errors via logs + (c) a hardcoded
template pattern that suggests the original author intended a
different index naming scheme that bypassed the per-tenant prefix
entirely points at a wiring inconsistency. The most defensible fix
addresses both the template pattern bug AND the diagnostic gap.

### H4: Index name mismatch

**Evidence**:
- Test queries `index="tenant-b-audit-*"` (test_m4d:126) and
  `index="local-audit-*"` (test_m4d:133).
- Fixture sets `index_prefix: tenant-b-audit` and
  `index_prefix: local-audit` (conftest.py:329, 314).
- `_today_index` returns `f"{self._prefix}-{YYYY.MM.DD}"`
  (wazuh_indexer.py:79-80) -> `tenant-b-audit-2026.05.01`.

**Verdict**: Names match exactly. Not the root cause.

## Most likely root cause

**H3** - silent retry exhaustion in `WazuhIndexerSink._send_with_retry`
masks the actual upstream error. The hardcoded
`index_patterns: ["wazuh-mcp-audit-*"]` template pattern (orthogonal
bug) is a strong signal that this code path has not been exercised
end-to-end since the per-tenant `index_prefix` config knob was added.
The 3e628e3 commit's "event missing from index entirely" symptom is
exactly what silent retry exhaustion looks like from the test side.

## Recommended T-G5b fix

Three changes, smallest first:

1. **Make template `index_patterns` match the configured prefix**
   (`src/wazuh_mcp/observability/sinks/wazuh_indexer.py:23-46`).
   Move the body construction inside `_ensure_template` so it can
   close over `self._prefix`:

   ```python
   async def _ensure_template(self) -> None:
       if self._template_installed: return
       client = await self._pool.acquire(self._tenant_id)
       body = {
           "index_patterns": [f"{self._prefix}-*"],
           "template": {
               "settings": {"number_of_shards": 1, "number_of_replicas": 0},
               "mappings": {"dynamic": False, "properties": {...}},
           },
       }
       await client.put_index_template(name=f"{self._prefix}-template", body=body)
       self._template_installed = True
   ```

2. **Add `?refresh=wait_for` to bulk in test/integration mode** (or,
   safer, add a log line at WARNING level inside `_send_with_retry`'s
   final-drop branch so a test failure has a tail to grep). The
   minimal version: log the upstream exception in the
   `_safe_record_drop(event, "delivery_failed")` branch. Currently
   only the metric increments; a single `_logger.warning(...)` makes
   the silent failure debuggable.

3. **Optional**: for the test, replace `await asyncio.sleep(5.0)` with
   an explicit `await raw_indexer_client.indices.refresh(index="tenant-b-audit-*")`
   call before the search. This removes the timing dependency entirely
   and is the OpenSearch-idiomatic pattern for write-then-search test
   loops.

The first change is the load-bearing fix (template now actually
applies). The second is the diagnostic fix that prevents the next
silent-failure regression. The third is a test-side robustness
improvement.

## Validation gap

T-G5b fix requires a docker stack to validate end-to-end (Wazuh
indexer + manager + Keycloak). Deferred to next session. Carry-
forward note: see this file's "Most likely root cause" section for
the spike conclusion. Order of operations on resumption:

1. Bring up `docker/integration-compose.yml`.
2. Apply fix #2 first (logging) so the test's first re-run surfaces
   the actual failure cause - confirms or refutes H3.
3. Apply fix #1.
4. Re-run `pytest tests/integration/test_m4d_multi_tenant.py::test_per_tenant_audit_routing -xvs`.
5. If still failing, apply fix #3 (refresh-on-search) and re-run.
6. Un-skip the test.
