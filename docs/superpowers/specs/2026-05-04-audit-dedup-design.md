# v1.2 — Audit-emitter cross-replica dedup

**Status:** approved (brainstorm 2026-05-04)
**Milestone:** v1.2
**Predecessor:** v1.1.0 (HEAD `c15cb5c`)
**Scope:** audit-emitter dedup. Helm chart `replicaCount` default unchanged.

## Goal

Close the second half of the v1.0 HA caveat. Today, every audit event hits OpenSearch with an auto-generated UUID `_id`, so a partial-success bulk retry creates duplicate documents for the same conceptual event. Multi-replica deployments compound the problem: the same JSON-RPC request seen by two replicas (rare but possible under session resumption / pod failover) produces two indexed documents that operators querying `local-audit-*` see as duplicates.

After this milestone, every event carries a deterministic `event_id` (per-emit UUID, persisted across QueuedSink retries) used as the OpenSearch `_id`, plus a queryable `request_id` correlation field for cross-replica deduplication at query time.

## Non-goals (v1.2)

- Bumping the Helm chart's `replicaCount` default. The v1.0 docs eagerly promised this; review at brainstorm time concluded the two-flag opt-in (`redis.enabled=true` + `replicaCount: 2+`) is the more correct posture. Operators who want HA continue to set both explicitly.
- Backfilling `event_id` / `request_id` on pre-v1.2 audit events. Old documents stay queryable as-is; aggregations by `request_id` only work for v1.2+ events.
- Stdio-transport `request_id` plumbing. The contextvar mechanism is in place; the stdio handler doesn't currently surface a JSON-RPC id, so stdio events ship with `request_id: null`. Plumbing the stdio path is a v1.3+ follow-up if demand surfaces.
- An `audit_dropped_total{reason="dedup"}` metric. OpenSearch silently overwrites on `_id` collision; observing dedup events from the client side requires a second round-trip we won't pay for.
- Backwards-compat shim for the `_id` change. Shape is identical (UUID4); only the *source* (server-generated → client-generated) shifts. No consumer should care.
- Promoting `request_id` into the `_id` derivation. Currently a queryable correlation field. Promotion to `_id` would force request-id propagation at every emit() call site (RBAC denial paths, resource handlers); deferred until cross-replica overlap is observed in production.

## Decisions locked during brainstorm

| # | Decision | Rationale |
|---|---|---|
| 1 | **Solve both retry-induced duplicates AND cross-replica overlap with the same fix.** | Per-event UUID anchored as `_id` solves the high-frequency retry case cleanly. Adding `request_id` as a queryable field gives operators a query-time dedup primitive for the cross-replica scenario without forcing the plumbing rabbit hole. Same change closes both. |
| 2 | **Per-event UUID for `_id` + queryable `request_id` field.** | Pure content-hash collides on legitimate distinct same-shape calls within the truncation window. UUIDs cannot collide. Retries reuse the queued event's `event_id` → idempotent. The `request_id` field is set from a contextvar populated at the FastMCP request boundary; null when no request scope is active. |
| 3 | **Helm chart `replicaCount: 1` default stays.** | The v1.0 doc promise was wrong: bumping replicaCount blindly multiplies the rate budget across replicas unless `redis.enabled=true` is also set, but `redis.enabled=true` requires an operator-provided Secret that can't be defaulted. Documented two-flag opt-in is the most-correct UX. |

## Architecture

Two changes to the existing emitter, one config-level change in the indexer sink, one new contextvars module, one transport-layer hook.

```
src/wazuh_mcp/observability/
├── audit.py                       (modified — emit() generates UUID, reads contextvar)
├── audit_context.py               (new — contextvars: request_id setter/getter)
└── sinks/
    └── wazuh_indexer.py           (modified — bulk body sets _id; template adds field mappings)

src/wazuh_mcp/transport/
└── http.py                        (modified — set request_id contextvar at MCP request boundary)
```

## Component responsibilities

### `audit_context.py` (new)

Single `ContextVar[str | None]` plus three functions:

```python
from __future__ import annotations
import contextvars

_audit_request_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "audit_request_id", default=None
)


def set_request_id(request_id: str | None) -> contextvars.Token[str | None]:
    return _audit_request_id.set(request_id)


def reset_request_id(token: contextvars.Token[str | None]) -> None:
    _audit_request_id.reset(token)


def get_request_id() -> str | None:
    return _audit_request_id.get()
```

~25 LOC, pure module, no other dependencies.

### `audit.py:emit()` (modified)

Two new lines populate the additive fields:

```python
event["event_id"] = str(uuid.uuid4())
event["request_id"] = get_request_id()
```

`event_id` is generated once per `emit()` call. The event then enters the queue carrying both fields; QueuedSink retries see the same `event_id` on every attempt.

### `wazuh_indexer.py:_build_bulk_body()` (modified)

```python
def _build_bulk_body(self, events: list[dict[str, Any]]) -> str:
    index = self._today_index()
    lines: list[str] = []
    for ev in events:
        action: dict[str, Any] = {"index": {"_index": index}}
        if "event_id" in ev:
            action["index"]["_id"] = ev["event_id"]
        lines.append(json.dumps(action))
        lines.append(json.dumps(ev))
    return "\n".join(lines) + "\n"
```

The `if "event_id" in ev` guard keeps backwards compatibility: events injected without it (tests, downstream consumers) fall back to the v1.1 auto-UUID behavior.

### `wazuh_indexer.py:_ensure_template()` (modified)

Add to `mappings.properties`:

```python
"event_id":   {"type": "keyword"},
"request_id": {"type": "keyword"},
```

Template name `{prefix}-template` unchanged. `put_index_template` is idempotent (PUT semantics); re-installing on v1.2 startup overlays the new mapping onto future writes.

### `transport/http.py` (modified)

At the FastMCP HTTP request boundary, extract the JSON-RPC `id` and set the contextvar; reset on request exit. Exact integration point is a plan-phase decision (T-C) — FastMCP's request lifecycle isn't fully obvious from the existing code. Worst-case fallback documented below in the risk register.

## OpenSearch dedup semantics

When a document with the same `_id` is bulk-indexed twice:

- Default `op_type=index` → upsert (overwrites existing doc with identical content; no error). Net effect: one doc survives.
- For our use case, the second write has identical content — the QueuedSink retry posts the same `event` dict on every attempt. Overwrite is safe; no data loss.

If a future consumer wants strict reject-on-collision behavior (debugging dedup events, etc.), they can switch to `op_type=create` in a follow-up. v1.2 ships `op_type=index` (the default) for safety.

## Event shape

```json
{
  "timestamp":     "2026-05-04T12:34:56.789012+00:00",
  "tool":          "alerts.search_alerts",
  "user":          "alice",
  "tenant":        "default",
  "rbac_role":     "analyst",
  "arg_hash":      "<sha256>",
  "outcome":       "ok",
  "result_count":  42,
  "duration_ms":   123,
  "error_code":    null,
  "error_reason":  null,
  "event_id":      "<uuid4>",
  "request_id":    "<jsonrpc-id>"
}
```

`event_id` is per-emit, mirrors `_id` in OpenSearch.
`request_id` is `null` for stdio transport (until plumbed) and for any emit that occurs outside an active FastMCP request context.

## Why contextvars

Threading `request_id` as an explicit kwarg through `emit()` would touch RBAC denial paths (`rbac/resolver.py`, 4 sites), resource handlers (`resources/agent_config.py`, 3 sites), and the `@instrumented_tool` decorator (1 site that fans out to all tool bodies). Every intermediate handler signature would need to thread the parameter through.

Contextvars keep the data flow invisible at call sites — exactly what they're for. `request_id` is request-scoped state that needs to reach `emit()` from the request boundary; that's the textbook contextvars use case.

`asyncio.create_task()` copies the current context by default, so spawned tasks see the parent's request_id. Tested directly in unit tests.

## Backwards compatibility

- Existing audit consumers parsing `local-audit-*` indices keep working — `event_id` and `request_id` are additive.
- The `_id` shape changes from auto-generated UUID to caller-supplied UUID — same shape, no operator-visible change.
- Old documents without the new fields stay queryable.
- New aggregations by `request_id` work for v1.2+ events only.

## Index template upgrade behavior

- v1.2 startup re-installs the template with the new mapping (idempotent PUT).
- Future writes (next daily index rollover) reflect the new mapping automatically.
- Existing daily indices were written under `dynamic: false` with the v1.1 mapping — the new fields are silently ignored on writes to those indices until they roll. Reads still see the field values (because we always send them in the doc body), but they won't be indexed for `keyword` lookups.
- Operators who want immediate field-indexed visibility on the current day's index can manually `_rollover` the index alias. Documented in v1.2 release notes.

## Helm chart edits

None to chart structure. Documentation only:

- `docs/deploy/helm.md` HA caveat collapses to: "All v1.0 HA blockers resolved as of v1.2. Multi-replica is supported with `redis.enabled=true` AND `replicaCount: 2+` set together. Default `replicaCount: 1` and `redis.enabled: false` reflect the conservative single-replica posture."
- README features-matrix multi-replica HA row updated to "Multi-replica HA — opt-in via redis.enabled=true + replicaCount > 1, audit dedup completed in v1.2."

## Documentation

- **`docs/deploy/helm.md`** — HA caveat collapsed (above).
- **`docs/deploy/observability.md`** — new section on audit dedup: describe `event_id` as the OpenSearch primary key, `request_id` as the cross-replica correlation field, the manual rollover note, and example queries (e.g. `GET local-audit-*/_search { "query": { "term": { "request_id": "abc123" } } }`).
- **`README.md`** — features-matrix update (above).
- **`docs/api-reference.md`** — no changes (audit emitter API unchanged at the call-site level).

## Migration

None required for existing operators. v1.1 → v1.2 upgrade:

1. New deployments / pod restarts re-install the index template (idempotent).
2. Today's daily index continues to accept writes; new fields are sent in the doc body but not field-indexed until rollover.
3. Tomorrow's daily index reflects the new mapping automatically.
4. Operators who want today's index to reflect the new mapping immediately run a one-shot `_rollover`. Documented in release notes; not required for correctness.

## Testing

### Unit (`tests/unit/test_audit_dedup.py`, new)

- `MultiSinkAuditEmitter.emit()` populates `event_id` (UUIDv4) on every event.
- `event_id` is unique per call: 1000 emits → 1000 distinct ids.
- `set_request_id("abc")` in scope → subsequent `emit()` carries `request_id == "abc"`.
- `reset_request_id(token)` removes the value cleanly; next `emit()` carries `request_id is None`.
- Concurrent contextvars: two `asyncio.create_task()` calls each set their own request_id; both `emit()` calls see their own context's value (no leakage).
- `WazuhIndexerSink._build_bulk_body()` writes `_id` line matching `event["event_id"]`.
- Defensive: an event without `event_id` produces a v1.1-shape bulk action (auto-UUID).
- Index template body now includes `event_id` and `request_id` keyword mappings.
- ~12 tests total.

### Integration (`tests/integration/test_audit_dedup_real.py`, new, `@pytest.mark.integration`)

- Emit 50 events with the same forced `event_id`. After `_refresh`, exactly 1 doc in the index.
- Emit 50 events with distinct `event_id`. 50 docs.
- Force partial-bulk-failure: mock the indexer to return `errors: true` for the second half of a 20-event batch on first attempt, succeed on retry. After retry, 20 docs total (not 30).
- End-to-end: drive an MCP HTTP request through the real server; assert the resulting audit event's `request_id` matches the JSON-RPC id sent.
- 4 tests total.

### Regression

`tests/integration/test_m4a_audit_indexer_sink.py` and `test_per_tenant_audit_routing.py` keep passing — changes are additive, no contract change for existing event consumers.

## Acceptance criteria

1. `tests/unit/test_audit_dedup.py` exists and passes (~12 tests).
2. `tests/integration/test_audit_dedup_real.py` exists and passes (4 tests) against a real Wazuh indexer in CI.
3. `tests/integration/test_m4a_audit_indexer_sink.py` continues to pass — proves backwards compatibility.
4. Manual smoke: forcing the same `event_id` twice produces exactly one doc in the audit index.
5. End-to-end: an MCP HTTP request's JSON-RPC id appears as the `request_id` field on its corresponding audit event.
6. `docs/deploy/helm.md` HA caveat updated; no remaining "deferred to v1.2" language anywhere in tracked docs.
7. `README.md` features-matrix entry updated.
8. `docs/deploy/observability.md` documents the new fields, dedup semantics, manual rollover note, and example queries.

## Risk register

| Risk | Severity | Mitigation |
|---|---|---|
| FastMCP request boundary doesn't cleanly expose JSON-RPC `id` to a middleware-style hook | Medium | Plan-time exploration of FastMCP's request lifecycle (T-C). Fallback: extract at `@instrumented_tool` decorator entry instead — same effect, marginally later in the lifecycle. RBAC denial paths run *before* `@instrumented_tool` so they'd ship with `request_id: null` under the fallback; documented as known minor limitation if we land on the fallback. |
| Index template re-install fails on v1.2 startup against existing template | Low | `put_index_template` is idempotent (PUT semantics); template name unchanged. Tested in T-B2. |
| Contextvars not propagated across `asyncio.create_task()` boundaries | Low | `asyncio.create_task` copies the current context by default. Direct unit test in T-A1 (`test_contextvar_propagates_across_tasks`). |
| Operators with hand-rolled `dynamic: false` consumer indices reject the new fields | Low | The chart-installed template explicitly maps both fields. Hand-rolled consumers may need to update their own mapping; release notes call this out as a known compatibility note. |
| OpenSearch `op_type=index` upserts with identical content; future debugging may want strict-reject behavior | Low | Documented; `op_type=create` is a one-line change in a future release if observability of dedup collisions becomes a desired metric. |

## Open implementation choices (deferred to plan phase)

- **FastMCP integration hook precise location.** Middleware vs Starlette-level wrapper vs `@instrumented_tool` entry. T-C plan-phase exploration picks one.
- **JSON-RPC `id` extraction details.** The id can be a string, integer, or null per JSON-RPC 2.0. The contextvar accepts `str | None`; the extractor coerces non-string ids to strings.
- **Whether to set `op_type=create` for stricter dedup.** Default `op_type=index` (upsert) is correct for v1.2's at-least-once-with-idempotent-retry semantics; if a future debugging need arises we flip via single-line change.

## Estimate

| Phase | Tasks | Effort |
|---|---|---|
| T-A: Audit emitter + contextvars | 3 plans | small-medium |
| T-B: Indexer sink (bulk body + template) | 2 plans | small |
| T-C: Transport hook (FastMCP integration) | 2 plans | medium (codebase exploration) |
| T-D: Tests (unit + integration) | 2 plans | medium |
| T-E: Docs + release notes | 1 plan | small |

Total: ~10 plans across 5 phases. Methodology: brainstorm → spec → plan → subagent exec → retro. Full review on T-C (the only novel-shape integration). Tier-A spot-check elsewhere.
