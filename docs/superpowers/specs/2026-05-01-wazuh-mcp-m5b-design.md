# wazuh-mcp M5b — v1.0.0 Ship-Gate Design

**Goal:** Ship `v1.0.0`. M5b is the publicly-credible 1.0 release: matrix-tested compat across the supported Wazuh versions, production-baseline Kubernetes deploy story, end-to-end coverage of every secret-store driver, group-target active-response capability, topic-organized operator docs, and full closure of every M5a-deferred item.

**Spec date:** 2026-05-01

**Predecessor:** `v0.8.0-m5a` (commit `7c1f9c0`, shipped 2026-05-01). Quality gates landed; eval harness Phases 1-2 + cross-tenant leak suite + security CI + destructive isolation in place. Three M5a items deferred to M5b (T6 baseline, hand-minted phantom token, audit-routing investigation) — picked up here.

**Successor:** v1.1 (group-target AR allowlist tuning, External Secrets Operator integration, HA-grade Helm chart, external Redis rate-limiter when SDK supports multi-instance MCP).

**Tag:** `v1.0.0` on ship.

**Estimated scope:** ~31 tasks across 6 phases. ~17-18 dispatches expected (~0.55/task — controller-inline Phases 5+6 hold the average down).

---

## 0. Scope

**M5b delivers seven workstreams:**

1. **Group-target `run_active_response`** — new write tool with `agent_group_allowlist` tenant-config field; the only novel security primitive in the milestone.
2. **Wazuh version matrix** — nightly integration runs against {Wazuh-LTS, Wazuh-latest}; PR-time stays single-pin for fast feedback.
3. **Multi-manager integration workflow** — separate weekly workflow validating per-tenant federation against two physically distinct Wazuh clusters.
4. **Vault driver integration** — real Vault container in integration-compose; replaces `hvac.Client` mock-only coverage.
5. **Helm chart** — production-baseline (single-replica with documented HA caveat), bring-your-own-Secret pattern, optional NetworkPolicy/ServiceMonitor/Ingress.
6. **Docs restructure** — topic-organized files under `docs/deploy/`; per-milestone files archived. New `docs/deploy/helm.md` and `docs/api-reference.md`.
7. **M5a-deferred + cleanup batch** — `WazuhError.scope` field, integration-log secret-scan workflow, T6 maintainer eval baseline, hand-minted phantom token, `test_per_tenant_audit_routing` investigation+fix.

**Explicit non-goals (carried to v1.1):**

- **External (Redis) rate-limiter.** `RateLimiter` Protocol stays in place; multi-instance deploy is documented as "single-replica in v1.0.0; multi-replica deferred to v1.1 when external rate-limiter ships."
- **HA-grade Helm chart.** No PodDisruptionBudget, no HorizontalPodAutoscaler, no pod anti-affinity, no External Secrets Operator integration. v1.0.0 ships single-replica with the rate-limiter caveat documented.
- **Formal toolset SDK wiring.** Gated on `mcp` SDK shipping the feature.
- **MCP elicitation activation.** Gated on SDK.
- **Group-target AR tuning beyond v1.0.0 surface.** v1.0.0 ships the wire support + per-tenant `agent_group_allowlist` enforcement. Per-group-rate-limit, per-group-audit-fan-out, and dynamic-group introspection are v1.1.

**Phasing strategy** (single-milestone choice; 31 tasks demands disciplined phasing):

- **Phase 1 — Tier-A novel primitive:** group-target AR. Lands first; downstream fixtures may consume it.
- **Phase 2 — Test infrastructure (Tier-B mostly, batched):** Wazuh matrix workflow, multi-manager workflow, Vault container fixture, audit-routing investigation+fix, hand-minted phantom token, integration-log secret-scan workflow.
- **Phase 3 — `WazuhError.scope` refactor (Tier-A spot-check):** cross-cutting field addition; plan-time grep all error-raising sites and metrics consumers.
- **Phase 4 — Helm chart (Tier-B):** production-baseline chart; smoke-tested via kind in CI. Independent of Phases 2-3.
- **Phase 5 — Docs restructure (controller-inline):** topic-organized files; authored after all code lands so docs match shipped state.
- **Phase 6 — Ship (controller-inline):** T6 eval baseline, version bump, retro, tag, push.

Phase 1 must precede Phase 5. Phases 2 ⊥ 3 ⊥ 4 (independent). Phase 6 gated on all prior phases.

---

## 1. Group-target `run_active_response` (Phase 1, Tier-A novel primitive)

### 1.1 Why a new tool name (not an overload)

Two routes were considered:

- **Overload `agent_ids: list[str]` to also accept `"group:<name>"` literal.** Rejected: surfaces a sentinel-string in a typed list; awkward Pydantic validation; muddles the audit-shape distinction (caller intent ambiguous from the audit event).
- **New tool `write.run_active_response_on_group` with its own Args model.** Chosen: clean type contract, distinct audit shape, distinct allowlist primitive (`agent_group_allowlist` vs existing `active_response_allowlist`), distinct telemetry counter, no risk of regression in existing `agent_ids` callers.

### 1.2 Tenant-config additions

```python
# src/wazuh_mcp/tenancy/config.py — new field on TenantConfig
agent_group_allowlist: list[str] = Field(default_factory=list)
```

Validator decisions:

- `default_factory=list` — empty list legal, deny-all semantics (mirrors `active_response_allowlist` precedent).
- Per-entry: non-empty string, `Field(min_length=1)` not enforced as collection-min; `field_validator` rejects empty strings element-wise.
- Max 50 entries (mirrors `_AR_AGENTS_MAX`); validator raises ValueError on overflow.
- `extra="forbid"` already in place on `TenantConfig` — unknown YAML fields fail at parse.

### 1.3 Args model + handler

```python
# src/wazuh_mcp/tools/writes_args.py — new model
class RunActiveResponseOnGroupArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    group_name: str = Field(min_length=1, max_length=128)
    command_name: str = Field(min_length=1, max_length=128)
    custom_args: dict[str, Any] | None = None
    confirm: Literal[True]
```

Handler (in `_register_everything`):

```python
async def _run_ar_on_group_inner(args: RunActiveResponseOnGroupArgs, *, session: Session, ...) -> WriteResult:
    _check_write_allowed(session, "write.run_active_response_on_group")
    ar_group_allowlist = ar_group_allowlist_policy(session)
    if args.group_name not in ar_group_allowlist:
        raise WazuhError(
            "forbidden",
            f"group {args.group_name!r} not in active_response group allowlist",
            scope="ar_group_allowlist",
        )
    # ServerApiClient call, build WriteResult, return
```

### 1.4 ServerApiClient wire

```python
# src/wazuh_mcp/wazuh/server_api.py — new method on ServerApiClient
async def run_active_response_on_group(
    self, *, group_name: str, command: str, custom_args: dict[str, Any] | None, run_as: str
) -> dict:
    params = {"agents_list": f"group:{group_name}", "run_as": run_as}
    body = {"command": command}
    if custom_args:
        body["arguments"] = custom_args
    return await self._put("/active-response", params=params, json=body)
```

`group:<name>` is documented Wazuh `agents_list=` syntax for the `/active-response` endpoint. Plan-time matrix CI catches drift if 4.12 changes the prefix.

### 1.5 Resolver

New session-keyed resolver in `src/wazuh_mcp/rbac/resolver.py`:

```python
def make_ar_group_allowlist_policy(
    registry: TenantRegistry, audit_emitter: MultiSinkAuditEmitter
) -> Callable[[Session], list[str]]:
    def _resolve(session: Session) -> list[str]:
        try:
            tenant = registry.get(session.tenant_id)
        except KeyError:
            audit_emitter.emit(
                session=session,
                tool=_RESOLVE_SENTINEL,
                outcome="error",
                error_code="forbidden",
                error_reason=_REASON,
            )
            return []  # fail-closed
        return list(tenant.agent_group_allowlist)
    return _resolve
```

Wired into `build_app` and `build_http_app` alongside the existing three resolvers. `_register_everything` gains an `ar_group_allowlist_policy` kwarg.

### 1.6 Tests

- `tests/unit/test_ar_group_allowlist.py` (new file, 2 tests): resolver fan-out across tenants; audit emit on unknown-tenant.
- `tests/unit/test_write_tools.py` additions (2 tests): allow-then-deny on `agent_group_allowlist=["test-group"]`; audit shape on deny includes `scope="ar_group_allowlist"`.
- `tests/unit/test_server_api_writes.py` (1 test): URL build asserts `agents_list=group%3Atest-group` (URL-encoded colon) or `agents_list=group:test-group` (raw); confirm at plan-time which httpx emits.
- `tests/integration/test_m5b_group_ar.py` (new file, 1 test, `@requires_manager`): create test-group via `POST /groups`, add agent 001 via `PUT /agents/001/group/test-group`, fire `write.run_active_response_on_group(group_name="test-group", command_name="restart-wazuh", confirm=True)`, assert `WriteResult.ok=True` and `failed_agents=[]`. Reuses existing `mcp_http_server_writes` fixture (port 8770, admin role).

### 1.7 Plan-time invariant grep

Every Phase 1 plan task body MUST embed:

```bash
grep -rn 'class TenantConfig\|extra="forbid"\|active_response_allowlist' src/wazuh_mcp/tenancy/
grep -rn 'WazuhError("forbidden"\|_check_write_allowed\|ar_allowlist_policy' src/wazuh_mcp/
grep -rn 'agents_list=\|run_active_response\|/active-response' src/wazuh_mcp/wazuh/ tests/
grep -rn 'make_ar_allowlist\|make_write_allowlist\|make_rbac_policy' src/wazuh_mcp/rbac/
grep -rn '_AR_AGENTS_MAX\|_WRITE_TOOL_NAMES' src/wazuh_mcp/
```

Resolved file:line list goes into the plan as a "verified call sites" section per the M5a invariant-waves lesson.

### 1.8 Tasks

- **T-A1** (Tier-A full review): tenant-config field + validator + resolver + 2 unit tests for resolver.
- **T-A2** (Tier-A full review): ServerApiClient method + Args model + handler + write registration in `_register_everything` + add `"write.run_active_response_on_group"` to `_WRITE_TOOL_NAMES` + 4 unit tests.
- **T-A3** (Tier-B): integration test (`test_m5b_group_ar.py`).
- **T-A4** (Tier-B): docs section in `docs/deploy/writes.md` (Phase 5).

---

## 2. Wazuh version matrix (Phase 2)

### 2.1 Version selection

Plan-time research target: identify Wazuh's LTS designation and latest minor as of plan-write date. Likely candidates as of 2026-05-01:

- LTS: `4.9.x` (current pin, validated production-grade across M2-M5a).
- Latest: `4.12.x` or `4.13.x` (verify against `wazuh/wazuh-manager` Docker Hub tags).

Plan-write step: `docker pull wazuh/wazuh-manager:4.12.0` (or whatever latest tag is) + run bootstrap against it locally to surface obvious wire-shape drift before CI matrix is enabled.

### 2.2 Workflow + compose changes

`docker/integration-compose.yml` — parameterize image tags via env var:

```yaml
services:
  wazuh-manager:
    image: wazuh/wazuh-manager:${WAZUH_VERSION:-4.9.x}
  wazuh-indexer:
    image: wazuh/wazuh-indexer:${WAZUH_VERSION:-4.9.x}
```

`.github/workflows/integration.yml` — gate matrix on event type:

```yaml
strategy:
  matrix:
    wazuh_version:
      - 4.9.x
      - 4.12.x  # (or whatever latest is at plan-write)
    exclude:
      # PR-time: only run latest LTS (existing behavior)
      - wazuh_version: ${{ github.event_name == 'pull_request' && '4.12.x' || 'never-match' }}
```

(Exact `exclude` syntax verified at plan-write — GH Actions matrix-exclude with conditional values has known limitations; fallback is two separate workflows or a `if:` on the test step.)

### 2.3 Tasks

- **T-B1** (Tier-B): compose parameterization + workflow matrix + verify both tags pull cleanly.
- **T-B2** (Tier-B, may be zero work): held in reserve for any wire-shape drift the latest version surfaces. If zero drift, this task is a no-op commit message saying "matrix CI green on first run."

---

## 3. Multi-manager integration workflow (Phase 2)

### 3.1 Architecture

Mirrors the M5a destructive-integration workflow precedent: separate compose file, separate workflow, weekly cron + manual dispatch, isolated runner.

### 3.2 Compose extension

`docker/multi-manager-compose.yml` — extends `integration-compose.yml`:

```yaml
services:
  wazuh-manager-2:
    image: wazuh/wazuh-manager:${WAZUH_VERSION:-4.9.x}
    ports: ["55001:55000"]
    # ...mirroring wazuh-manager service
  wazuh-indexer-2:
    image: wazuh/wazuh-indexer:${WAZUH_VERSION:-4.9.x}
    ports: ["9201:9200"]
    # ...mirroring wazuh-indexer service
```

Bootstrap sequence: existing `bootstrap.sh` adapted to bootstrap both clusters in parallel (or runs twice with different `WAZUH_HOST` env). Disk-watermark relax from M5a `48b213c` carries over.

### 3.3 Conftest fixture

```python
# tests/integration/conftest.py — new fixture
@pytest.fixture
def mcp_http_server_multi_manager(...):
    # tenants.yaml with two tenants:
    #   tenant_a → indexer_url: https://indexer-1:9200, server_api_url: https://manager-1:55000
    #   tenant_b → indexer_url: https://indexer-2:9201, server_api_url: https://manager-2:55001
    # Spawns server on a unique port (8780).
```

### 3.4 Tests

`tests/integration/test_multi_manager.py` (new file, 2 tests, `@pytest.mark.multi_manager`):

1. **`test_tenant_a_session_only_hits_manager_1`** — session for tenant_a calls `agents.list`. Assert response shape contains agents from manager-1's seeded fixture only (manager-2 has a distinguishably-different agent name). Cross-pollination check: query against manager-2 directly via `raw_indexer_client_2` confirms no tenant_a query traffic landed there.
2. **`test_tenant_b_session_only_hits_manager_2`** — symmetric.

### 3.5 Workflow

`.github/workflows/multi-manager-integration.yml` — weekly Sunday 06:13 UTC + `workflow_dispatch`. Filter `-m "integration and multi_manager"`. Identical structure to `destructive-integration.yml`.

### 3.6 Pytest marker registration

`pyproject.toml` `[tool.pytest.ini_options]`:

```toml
markers = [
    # ...existing
    "multi_manager: requires two distinct Wazuh clusters (multi-manager-integration.yml)",
]
```

`integration.yml` filter updated to `-m "integration and not destructive and not multi_manager"`.

### 3.7 Tasks

- **T-C1** (Tier-B): multi-manager-compose.yml + bootstrap adaptation + conftest fixture + 2 integration tests.
- **T-C2** (Tier-B): workflow + marker registration + main `integration.yml` filter update.
- **T-C3** (Tier-B, controller-inline candidate): docs section in `docs/deploy/multi-tenant.md` (Phase 5).

---

## 4. Vault driver integration (Phase 2)

### 4.1 Compose extension

`docker/integration-compose.yml` adds a `vault` service:

```yaml
services:
  vault:
    image: hashicorp/vault:1.18  # verify latest stable at plan-write
    cap_add: ["IPC_LOCK"]
    environment:
      VAULT_DEV_ROOT_TOKEN_ID: test-root-token
      VAULT_DEV_LISTEN_ADDRESS: 0.0.0.0:8200
    ports: ["8200:8200"]
    healthcheck:
      test: ["CMD", "vault", "status", "-address=http://127.0.0.1:8200"]
      interval: 5s
      retries: 12
```

The `vault` test fixture polls the Vault healthcheck via `httpx` (timeout ~10s) before yielding. The main integration suite does not block on Vault — non-Vault tests can run while the Vault container is still starting, since they don't reference the fixture.

### 4.2 Bootstrap helper

`tests/integration/_vault_bootstrap.py` — small async helper using `httpx`:

```python
async def write_secret(path: str, data: dict[str, str]) -> None:
    async with httpx.AsyncClient() as c:
        await c.post(
            f"http://localhost:8200/v1/secret/data/{path}",
            headers={"X-Vault-Token": "test-root-token"},
            json={"data": data},
        )
```

Fixture writes `secret/data/wazuh-mcp/oauth_client_secret` and `secret/data/wazuh-mcp/wazuh_api_password` in setup.

### 4.3 Tests

`tests/integration/test_vault_secret_store.py` (new file, 3 tests, `@pytest.mark.vault`):

1. **`test_get_existing_secret_round_trips_through_vault`** — write secret, read via `VaultSecretStore`, assert `SecretValue.expose() == expected`, assert `repr(secret_value)` redacts.
2. **`test_get_missing_secret_raises_keyerror`** — read non-existent path, assert `KeyError`.
3. **`test_token_renewal_refreshes_lease`** — write secret with short TTL, sleep past renewal threshold, read again, assert success (`hvac` auto-renews).

### 4.4 Pytest marker

`pyproject.toml` adds `"vault: requires Vault container in integration-compose.yml"`. Tests run in main nightly (vault container is small; ~30MB image, sub-second startup in dev mode).

### 4.5 Tasks

- **T-D1** (Tier-B): compose extension + `_vault_bootstrap.py` + fixture + 3 integration tests + marker registration.
- **T-D2** (Tier-B, controller-inline candidate): docs section in `docs/deploy/secrets.md` (Phase 5).

---

## 5. Helm chart — production-baseline (Phase 4)

### 5.1 Chart layout

```
charts/wazuh-mcp/
  Chart.yaml
  values.yaml
  values.schema.json
  README.md
  templates/
    _helpers.tpl
    deployment.yaml
    service.yaml
    configmap-tenants.yaml
    secret.yaml              # gated on .Values.secrets.create
    serviceaccount.yaml
    role.yaml
    rolebinding.yaml
    networkpolicy.yaml       # gated on .Values.networkPolicy.enabled
    servicemonitor.yaml      # gated on .Values.serviceMonitor.enabled
    ingress.yaml             # gated on .Values.ingress.enabled
    tests/
      test-connection.yaml   # helm-test pod
```

### 5.2 Chart.yaml

```yaml
apiVersion: v2
name: wazuh-mcp
description: Model Context Protocol server exposing Wazuh as tools for Claude
type: application
version: 0.1.0  # chart version (independent of app version)
appVersion: "1.0.0"
keywords: [mcp, wazuh, security, ai]
home: https://github.com/0xFl4g/wazuh-mcp
maintainers:
  - name: 0xFl4g
```

### 5.3 values.yaml structure

```yaml
image:
  repository: ghcr.io/0xfl4g/wazuh-mcp
  tag: ""  # defaults to .Chart.AppVersion
  pullPolicy: IfNotPresent

replicaCount: 1  # see HA caveat in docs/deploy/helm.md

resources:
  requests: {cpu: 100m, memory: 128Mi}
  limits: {cpu: 500m, memory: 512Mi}

tenants:
  # inlined into a ConfigMap
  yaml: |
    tenants:
      default:
        tenant_id: default
        indexer_url: https://wazuh-indexer:9200
        # ...

secrets:
  # bring-your-own (default false): operator creates the Secret out-of-band
  create: false
  existingSecret: ""  # name of existing Secret with keys: oauth-client-secret, wazuh-api-password, indexer-admin-password
  # OR if create: true, chart templates a stub Secret from these stringData:
  oauthClientSecret: ""
  wazuhApiPassword: ""
  indexerAdminPassword: ""

probes:
  readiness: {path: /health/ready, initialDelaySeconds: 5}
  liveness: {path: /health/live, initialDelaySeconds: 30}

service:
  type: ClusterIP
  port: 8080

networkPolicy:
  enabled: false
  ingressFromNamespaces: []  # e.g. ["claude-clients"]
  egressTo:
    wazuhManager: {host: "", port: 55000}
    wazuhIndexer: {host: "", port: 9200}
    oidcIssuer: {host: "", port: 443}

serviceMonitor:
  enabled: false
  namespace: ""  # defaults to release namespace
  interval: 30s

ingress:
  enabled: false
  className: nginx
  host: ""
  tls:
    enabled: false
    secretName: ""
```

### 5.4 Deployment template

Single-replica, readiness + liveness probes, secret env-var injection, configmap volume mount at `/config/tenants.yaml`. ServiceAccount referenced. No init containers.

### 5.5 Helm-test hook

`templates/tests/test-connection.yaml`:

```yaml
apiVersion: v1
kind: Pod
metadata:
  annotations:
    "helm.sh/hook": test
spec:
  restartPolicy: Never
  containers:
    - name: smoke
      image: curlimages/curl:8.10.1
      command: ["sh", "-c", "curl -fsS http://{{ include \"wazuh-mcp.fullname\" . }}:{{ .Values.service.port }}/health/ready"]
```

### 5.6 CI workflows

New `.github/workflows/helm-lint.yml` — runs on PR + main pushes touching `charts/**`:

1. `helm lint charts/wazuh-mcp`
2. `helm template charts/wazuh-mcp` (verifies templating with default values)
3. Spin up kind cluster, `helm install wazuh-mcp ./charts/wazuh-mcp --set secrets.create=true,secrets.oauthClientSecret=test,secrets.wazuhApiPassword=test,secrets.indexerAdminPassword=test`, then `helm test wazuh-mcp` (runs the smoke pod).

### 5.7 HA caveat (documented in `docs/deploy/helm.md`)

The in-process `InProcessRateLimiter` does NOT share state across replicas. With `replicaCount: 2+`, each replica enforces its own rate-limit budget. For multi-instance deployments, wait for v1.1 (external Redis-backed `RateLimiter` impl). Operator workaround for v1.0.0: run with `replicaCount: 1` (default), use Kubernetes-native readiness gating + restart-on-failure for resilience.

### 5.8 Tasks

- **T-E1** (Tier-B): Chart.yaml + values.yaml + values.schema.json + Deployment + Service + ConfigMap.
- **T-E2** (Tier-B): Secret template + ServiceAccount + Role + RoleBinding.
- **T-E3** (Tier-B): NetworkPolicy + ServiceMonitor + Ingress (all gated opt-ins).
- **T-E4** (Tier-B): helm-test pod + helm-lint workflow + kind smoke.
- **T-E5** (Tier-B, controller-inline candidate): `docs/deploy/helm.md` (Phase 5).

---

## 6. Docs restructure (Phase 5, controller-inline)

### 6.1 Target structure

```
docs/deploy/
  README.md                 # index + recommended reading order
  install.md                # stdio + HTTP + container install
  tenants.md                # TenantConfig schema reference
  secrets.md                # SecretStore drivers (yaml/aws-sm/vault/sqlite-age) + caching wrapper
  oauth.md                  # OAuth + IssuerIndex semantics; cross-link to oauth-setup/
  api-keys.md               # (existing, lightly polished)
  tools.md                  # 17 read tools + cluster.status — invocation reference
  writes.md                 # 8 write tools + run_as + allowlists + new group-target AR
  observability.md          # OTel + Prom + audit + rate-limit metrics + new WazuhError.scope
  multi-tenant.md           # per-tenant resolvers + rate-limit + audit fan-out + multi-manager fixture
  quality-gates.md          # eval harness + security CI + destructive isolation (m5a content lifted)
  helm.md                   # NEW — chart usage + HA caveat
  oauth-setup/{keycloak,okta,entra,auth0}.md  # unchanged
  _archive/
    README.md               # banner: "Per-milestone deploy notes preserved for git history; current docs are at ../"
    m2-http.md              # verbatim from current docs/deploy/m2-http.md
    m3-tools.md
    m4a-secrets.md
    m4a-observability.md
    m4a-audit.md
    m4b-writes.md
    m4c-multi-tenant.md
    m4d-multi-tenant-runtime.md
    m5a-quality-gates.md
docs/api-reference.md       # NEW — every tool/resource/prompt with args, returns, errors, audit shape
README.md                   # polished — install quickstart + link to docs/deploy/README.md
docs/security/threat-model.md  # touched only if WazuhError.scope or group-target adds threats
```

### 6.2 Content sourcing

Each new topic-organized file consolidates from one or more per-milestone files. For example, `secrets.md` merges:

- `m4a-secrets.md` — AWS SM, Vault, SQLite+age driver details, `CachingSecretStore` wrapper.
- New section: real Vault container fixture (T-D1) for testing in development.

`writes.md` merges:

- `m4b-writes.md` — 7 original write tools + two-layer allowlist + audit shape.
- `m4c-multi-tenant.md` write-tool sections — `write.restart_manager` + `cluster.status` + multi-agent AR + `write_allowlist=[]` delta.
- New section: `write.run_active_response_on_group` + `agent_group_allowlist` from T-A.

`observability.md` merges:

- `m4a-observability.md` — OTel + Prom + audit overview.
- `m4a-audit.md` — sink types + `MultiSinkAuditEmitter` lifecycle.
- New section: `WazuhError.scope` field + the new structured `scope` label on rate-limit metrics from T-G1.

### 6.3 Archive banner

`docs/deploy/_archive/README.md`:

```markdown
# Archived per-milestone deploy notes

These files preserve the deploy guide as it existed at each milestone tag (M2 through M5a). They are kept for git history and for users diffing v0.x.y → v1.0.0 deployments.

**For current deployment docs, read [../README.md](../README.md).**

Files in this directory may reference superseded surfaces. They are not maintained.
```

### 6.4 Tasks

- **T-F1** (controller-inline): `secrets.md` + `oauth.md` + `tools.md` from existing m3+m4a content. Plus archive of m3-tools.md, m4a-secrets.md.
- **T-F2** (controller-inline): `writes.md` + `multi-tenant.md` from m4b+m4c+m4d content + new group-target section. Archive of m4b-writes.md, m4c-multi-tenant.md, m4d-multi-tenant-runtime.md.
- **T-F3** (controller-inline): `observability.md` + `quality-gates.md` from m4a + m5a content + new `WazuhError.scope` content. Archive of m4a-observability.md, m4a-audit.md, m5a-quality-gates.md.
- **T-F4** (controller-inline): `install.md` + `tenants.md` + `helm.md` + `docs/deploy/README.md` index + `_archive/README.md` banner. Archive of m2-http.md.
- **T-F5** (controller-inline): `docs/api-reference.md` + top-level `README.md` polish.

---

## 7. Carry-over batch (Phase 2/3)

### 7.1 `WazuhError.scope` field (Phase 3, Tier-A spot-check)

Additive `scope: str | None = None` field on `WazuhError`. Updates raise sites:

- `rate_limit/limiter.py` — `scope="rate_limit:tenant"` and `scope="rate_limit:session"` (replaces metrics substring-match).
- `rbac/resolver.py` — `scope="rbac:tenant_not_registered"`.
- AR allowlist deny — `scope="ar_allowlist"`.
- Write allowlist deny — `scope="write_allowlist"`.
- New AR-group allowlist deny (from T-A) — `scope="ar_group_allowlist"`.

Metrics consumer in `observability/metrics.py` reads `error.scope` directly; substring-match removed. Operator dashboards may want refresh — documented in `docs/deploy/observability.md`.

Tests:

- `tests/unit/test_wazuh_error.py` (new file or extension): 3 tests — field roundtrip, default `None`, repr/str preserves scope.
- 5 updates to existing rate-limit/RBAC error tests asserting on `.scope`.

**Plan-time invariant grep** (M5a invariant-waves discipline):

```bash
grep -rn 'WazuhError(' src/ tests/
grep -rn '"rate_limit"\|rate_limited\|rate_limit:' src/wazuh_mcp/observability/ src/wazuh_mcp/rate_limit/
grep -rn '\.scope\b' src/wazuh_mcp/  # confirm no attribute-name collision
```

Tier-A spot-check: full grep + manual enumeration in plan body. Not full-review unless grep surfaces a structural concern.

**1 task: T-G1.**

### 7.2 Integration log secret-scan workflow (Phase 2, Tier-B)

Plan-time check: does `integration.yml` already upload integration-log artifacts? If not, add `actions/upload-artifact@v4` step uploading `tests/integration/logs/*` + container logs (`docker compose logs > integration-logs/compose.log`).

New `.github/workflows/integration-log-scan.yml` triggered by `workflow_run` on `integration.yml` completion:

```yaml
on:
  workflow_run:
    workflows: ["integration"]
    types: [completed]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: integration-logs
          run-id: ${{ github.event.workflow_run.id }}
          github-token: ${{ secrets.GITHUB_TOKEN }}
      - uses: gitleaks/gitleaks-action@v2
        with:
          config-path: .gitleaks.toml
        env:
          GITLEAKS_ENABLE_UPLOAD_ARTIFACT: false
```

Fails workflow on hit; SARIF uploaded to GH Security tab.

**2 tasks: T-G2a (artifact upload), T-G2b (scan workflow).**

### 7.3 T6 maintainer eval baseline (Phase 6, controller-inline, **environment-flagged**)

**Environment requirement (per M5a deferral lesson):** controller's Claude Code session MUST have wazuh-mcp connected as MCP server.

Steps:

1. Verify MCP server connection: invoke a wazuh-mcp tool to confirm.
2. Run `/eval-wazuh-mcp` slash command.
3. Commit `docs/eval-history/2026-05-XX-claude-opus-4.7-results.json` + raw transcript.
4. If pass-rate < 90%: triage failures per M5a spec §1 ladder. **Do NOT lower thresholds to make a flaky prompt pass — fix the prompt.**

**1 controller-inline task: T-G3.**

### 7.4 Hand-minted phantom token (Phase 2, Tier-A spot-check)

Per Q8 decision: Keycloak admin-API mint (option B). Custom JWKS endpoint deferred — not needed if Keycloak admin can mint arbitrary-claim tokens.

New `tests/integration/_keycloak_admin.py`:

```python
async def mint_token_with_claims(*, sub: str, tenant_id: str, **extra_claims: Any) -> str:
    # POST /realms/{realm}/protocol/openid-connect/token with admin-cli client
    # then use admin API to construct a token with arbitrary claims
    # OR: use Keycloak's "token-exchange" feature with claim-overrides
```

**Plan-write spike (resolves before plan commit):** confirm Keycloak 26 supports the necessary claim-injection via standard token-endpoint with admin-cli client. Two outcomes:

- **Path A (preferred):** Keycloak admin can issue tokens with arbitrary claims via the standard token endpoint (e.g., via a service-account mapper or `client_assertion`). Helper uses standard OAuth flow.
- **Path B (fallback):** Keycloak's standard endpoint can't inject arbitrary claims. Helper fetches the realm signing key via Keycloak admin REST (`GET /admin/realms/{realm}/keys`) and mints a JWT directly via `joserfc` (already a dependency).

Plan-write picks one path and pastes the resolved code shape into T-G4a's task body. Spec stays path-agnostic until then.

New fixture `keycloak_admin_minted_token` in `tests/integration/conftest.py`. Un-skip cross-tenant test 4 (`test_cross_tenant_phantom_token_rejected_at_resolution` in `test_m4d_multi_tenant.py`):

```python
async def test_cross_tenant_phantom_token_rejected_at_resolution(
    mcp_http_server_audit, keycloak_admin_minted_token
):
    # Mint a token claiming tenant_id="tenant_b" but signed by realm key
    # tenant_b's OAuth client_id was wazuh-mcp-client-tenant-b in M5a
    # Server should reject because the token's sub doesn't match tenant_b's mapper rules
    token = await keycloak_admin_minted_token(sub="phantom-user", tenant_id="tenant_b")
    async with _mcp_session(MCP_URL, token) as session:
        with pytest.raises(McpError) as exc_info:
            await session.call_tool("agents.list", {})
    assert "forbidden" in str(exc_info.value) or "unauthorized" in str(exc_info.value)
```

**Plan-time invariant grep** (M5a T7 lesson — invariant waves):

```bash
grep -rn 'IssuerIndex\|get_by_tenant_id\|_build_session\|_pick_wazuh_user' src/wazuh_mcp/
grep -rn 'iss_tenant_cfg\|tenant_cfg\b' src/wazuh_mcp/auth/
```

Confirm phantom-token rejection path doesn't surface another invariant wave (M5a's `_pick_wazuh_user` second-order break is the precedent).

**2 tasks: T-G4a (admin helper + fixture), T-G4b (un-skip + assertion + grep).**

### 7.5 `test_per_tenant_audit_routing` investigation+fix (Phase 2, tier depends on root cause)

Skip-marked at commit `3e628e3`. Investigation order:

1. **Hypothesis 1 (most likely): QueuedSink.flush() not draining on test teardown.** Instrument fixture: add `await audit_emitter.flush()` (if method exists; add if not) + assert flush completion. Test re-run.
2. **Hypothesis 2: admin auth missing tenant-b indexer write permission.** Verify by direct curl from inside the test container to `tenant-b-audit-*` index using the admin credentials. If 403, the indexer security config in fixture lacks tenant-b index pattern.
3. **Hypothesis 3: per-tenant index template not registered before first write.** Check `IndexerClient.put_index_template` call ordering in `MultiSinkAuditEmitter.start()`. If templates aren't applied before first emit, the first event lands in an auto-mapped index that doesn't match the test's expected name pattern.

Fix scoped after root cause known. Likely Tier-B (test infra fix). If root cause exposes a sink-lifecycle bug, escalate to Tier-A spot-check.

**1-2 tasks: T-G5a (spike + root cause), T-G5b (fix if needed).**

---

## 8. Cross-cutting

### 8.1 Review tier classification

| Track | Tasks | Tier-A full | Tier-A spot-check | Tier-B |
|---|---|---|---|---|
| T-A group-target AR | 4 | T-A1, T-A2 | — | T-A3, T-A4 |
| T-B Wazuh matrix | 2 | — | — | T-B1, T-B2 |
| T-C multi-manager | 3 | — | — | all |
| T-D vault driver | 2 | — | — | both |
| T-E helm chart | 5 | — | — | all |
| T-F docs | 5 | — | — | all (controller-inline) |
| T-G1 WazuhError.scope | 1 | — | T-G1 | — |
| T-G2 log-scan | 2 | — | — | both |
| T-G3 T6 baseline | 1 | — | — | controller-inline |
| T-G4 phantom token | 2 | — | T-G4a, T-G4b | — |
| T-G5 audit-routing | 1-2 | — | T-G5b (if sink-lifecycle) | T-G5a |

**Tier-A full:** 2 (T-A1, T-A2).
**Tier-A spot-check:** 4-5 (T-G1, T-G4a, T-G4b, possibly T-G5b).
**Tier-B:** 22-23.

Per memory: full review only when introducing a novel primitive. T-A is the only novel-primitive track. T-G1 spot-check because it's an additive field cross-cutting; full plan-time grep + manual enumeration suffice. T-G4 spot-check because it touches OAuth/IssuerIndex composition (M5a T7 lesson) but doesn't introduce new primitives.

### 8.2 Dispatch budget

Note on phasing arithmetic: each track's docs subtask (T-A4, T-C3, T-D2, T-E5) is authored in Phase 5 alongside T-F1-F5, not in its parent track's phase. So Phase 1 ships 3 code tasks (T-A1+T-A2+T-A3) and defers T-A4; Phase 4 ships 4 code tasks (T-E1+...+T-E4) and defers T-E5; etc. Phase 5 absorbs all 4 deferred docs subtasks plus T-F1-F5 = 9 tasks total.

| Phase | Tasks | Implementer | Reviewer | Fix-after | Total |
|---|---|---|---|---|---|
| 1 (group-target AR — code) | 3 | 2 (T-A1 alone, T-A2+T-A3 batched OR T-A2 alone + T-A3 batched with later) | 1 combined | 1 budgeted | 4 |
| 2 (test infra batch — code) | 11 | 8 (per-track batches) | 0 | 0 | 8 |
| 3 (WazuhError.scope) | 1 | 1 | 0 (spot-check) | 0 | 1 |
| 4 (helm chart — code) | 4 | 3 (T-E1+T-E2 batched) | 0 | 0 | 3 |
| 5 (docs restructure) | 9 | 0 (controller-inline) | 0 | 0 | 0 |
| 6 (ship) | 3 | 0 (controller-inline) | 0 | 0 | 0 |
| **Total** | **~31** | **~14** | **1** | **1** | **~16** |

~0.52 dispatches/task — lower than M4d (0.62) because controller-inline scope is large (Phases 5+6 = 12 tasks). Slip to ~20 if T-A or T-G4 needs more than one fix pass, or if T-G5 fix turns out tier-A and warrants reviewer.

### 8.3 Plan-time grep targets (consolidated)

Phase 1 — group-target AR: see §1.7.
Phase 3 — `WazuhError.scope`: see §7.1.
Phase 2 — phantom token: see §7.4.

Each plan task body MUST embed the relevant grep + the resolved file:line list as a "verified call sites" section. ~5 minutes of plan-time grep avoids ~30+ minutes of dispatch-time correction (M4c/M4d/M5a precedent).

### 8.4 Plan-time fixture validators

`agent_group_allowlist`: empty list legal (deny-all default; mirrors `active_response_allowlist`). `default_factory=list`. Tests assert empty-list → all calls rejected with `forbidden`.

### 8.5 Testing strategy

- **Unit:** ~10-15 new tests. Total unit count: 519 → ~535.
- **Integration:** ~7-9 new tests. Marker matrix: `integration` (default), `requires_manager`, `destructive`, new `multi_manager`, new `vault`.
- **Filter expressions:**
  - Main nightly: `-m "integration and not destructive and not multi_manager"`.
  - Weekly destructive: `-m "integration and destructive"`.
  - Weekly multi-manager: `-m "integration and multi_manager"`.
- **Helm:** `helm lint` + `helm template | kubectl apply --dry-run=server` on PR; `helm install + helm-test` against kind on nightly.
- **Eval:** T6 baseline run committed in Phase 6.

### 8.6 Migration & operator-visible deltas

- **`TenantConfig.agent_group_allowlist`** — new field, defaults `[]` (deny-all). Existing tenants unaffected unless opting in.
- **`WazuhError.scope`** — new optional field; existing handler code unaffected. Metrics label `scope` appears on rate-limit error counters where it didn't before — operator dashboards may want refresh.
- **`docs/deploy/` restructure** — old per-milestone files moved to `_archive/` with redirect banner. README + docs/deploy/README.md point at new structure.
- **Helm chart at `charts/wazuh-mcp/`** — new artifact. Documented as the recommended k8s deploy path.
- **Wazuh version matrix** — nightly tests on LTS + latest; PR-time stays single-pin.
- **Multi-manager workflow** — new weekly cron; doesn't affect main nightly runtime.
- **Vault container in integration-compose** — adds ~30MB image + sub-second startup; cheap.

### 8.7 Ship checklist (Phase 6, controller-inline)

1. Confirm 7-night nightly green streak on Wazuh matrix.
2. Run `/eval-wazuh-mcp` (T6 baseline) in MCP-server-connected session; commit `docs/eval-history/<date>-<model>-results.json` + raw.
3. Verify `helm lint` + kind smoke pass.
4. Verify all skip-markers removed (no `pytest.mark.skip` in `tests/integration/test_m4d_multi_tenant.py` or `test_per_tenant_audit_routing` — except documented intentional skips).
5. `uv run ruff format .` (alignment commit only if drift, per M4c/M4d/M5a precedent).
6. `pyproject.toml` 0.8.0 → 1.0.0.
7. Write retro `docs/superpowers/retros/<date>-m5b-retro.md`.
8. Stage specific files (NOT `git add -A` — `.DS_Store` discipline).
9. Commit ship.
10. Tag `v1.0.0`.
11. Push with `--tags`.

---

## 9. Open questions resolved during brainstorm

- **Single milestone vs. split (M5b/M5c)?** Single M5b. (Q1)
- **Helm chart scope?** Production-baseline (single-replica + HA caveat). (Q2)
- **Multi-manager fixture cost?** Separate weekly workflow. (Q3)
- **Wazuh version matrix?** Matrix nightly only (PR-time stays single-pin). (Q4)
- **Vault integration scope?** SecretStore round-trip only (no OAuth-via-Vault end-to-end). (Q5)
- **Group-target AR — v1.0.0 or v1.1?** v1.0.0; Tier-A novel primitive. (Q6)
- **Docs consolidation strategy?** Topic-organized restructure with archive of per-milestone files. (Q7)
- **Phantom token mint — Keycloak admin or custom JWKS?** Keycloak admin-API mint. (Q8)
- **Remaining batched scopings (WazuhError.scope, log-scan, T6 baseline, audit-routing)?** All approved as scoped in §7. (Q8)

---

## 10. Predecessor / successor handoffs

**From M5a:**
- T6 baseline carry-forward → §7.3 (Phase 6).
- Hand-minted phantom token → §7.4 (Phase 2).
- `test_per_tenant_audit_routing` skip-mark → §7.5 (Phase 2).
- `WazuhError.scope` carry-forward → §7.1 (Phase 3).
- Vault integration carry-forward → §4 (Phase 2).
- Wazuh LTS + latest matrix carry-forward → §2 (Phase 2).
- Multi-manager fixture carry-forward → §3 (Phase 2).
- Helm chart carry-forward → §5 (Phase 4).
- Docs completion carry-forward → §6 (Phase 5).
- Integration log secret-scan carry-forward → §7.2 (Phase 2).

**To v1.1:**
- External (Redis) `RateLimiter` impl when SDK supports multi-instance MCP.
- HA-grade Helm chart (PDB, HPA, anti-affinity, ESO integration).
- Group-target AR enhancements (per-group rate-limit, dynamic-group introspection).
- Formal toolset SDK wiring when SDK ships the feature.
- MCP elicitation activation when SDK ships the feature.

---

## 11. Plan-write deliverable

`docs/superpowers/plans/2026-05-01-wazuh-mcp-m5b-plan.md` — six-phase task breakdown with concrete code snippets, verified file:line grep results, expected commands and outputs. Plan author MUST execute the §1.7 / §7.1 / §7.4 grep commands at plan-write time and paste resolved results into each task body.
