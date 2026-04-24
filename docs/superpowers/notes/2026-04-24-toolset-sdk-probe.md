# MCP toolset SDK probe — M4b T1

Question: does the installed MCP Python SDK support formal toolset
client-enablement?

## SDK version probed

`mcp == 1.27.0` (pin from `uv.lock`; confirmed at runtime via
`importlib.metadata.version("mcp")`).

## Surface inspected

Installed site-packages under
`/Users/moody/VSCode/wazuh-mcp/.venv/lib/python3.12/site-packages/mcp/`.

- `mcp/types.py`:
  - `Tool` at `types.py:1315-1339` — fields: `name` (via `BaseMetadata`),
    `description`, `inputSchema`, `outputSchema`, `icons`, `annotations`,
    `meta` (aliased to `_meta`, `types.py:1331`), `execution`. No
    `toolset`, `group`, `enabled`, or client-enablement field. `meta` is
    free-form `dict[str, Any] | None`.
  - `ListToolsResult` at `types.py:1342-1345` — just `tools: list[Tool]`.
    No toolset grouping in the wire schema.
  - `ToolsCapability` at `types.py:455-460` — only `listChanged: bool |
    None`. No `toolsets`, `enable`, or discovery field.
  - `ServerCapabilities` at `types.py:506-523` — allows an
    `experimental: dict[str, dict[str, Any]]` bag but no first-class
    toolset capability.
- `mcp/server/fastmcp/server.py`:
  - `FastMCP.add_tool` at `server.py:397-433` — takes `meta: dict | None`
    and forwards to `ToolManager.add_tool`. No `toolset`, `group`, or
    `enabled` kwarg.
  - `FastMCP.remove_tool` at `server.py:435-444`, `FastMCP.tool` decorator
    at `server.py:446+` — neither exposes toolset-awareness.
  - `dir(FastMCP)` filtered on `toolset|enable|filter` returns `[]` (ran
    via `uv run python -c`). No matches.
- `mcp/server/fastmcp/tools/tool_manager.py`:
  - `add_tool` at `tool_manager.py:53-64` accepts `meta: dict[str, Any] |
    None` and stores it on `Tool.meta` (`base.py:39`, `base.py:90`). No
    toolset field.
  - `list_tools` at `tool_manager.py:41-43` returns the raw dict values
    with no filter arg.
- `mcp/server/lowlevel/server.py`:
  - `Server.list_tools` decorator at `lowlevel/server.py:434-490` —
    single-slot handler registration; no toolset dispatch.
  - `Server.call_tool` decorator at `lowlevel/server.py:492-589` — no
    toolset or client-enablement gate on dispatch.
- `mcp/server/experimental/`: task-support features only
  (`task_context.py`, `task_result_handler.py`,
  `session_features.py`). `grep -i toolset` across the module returns
  zero hits. No toolset-experimental API is shipping in 1.27.0.
- `mcp.types` filtered on `toolset|enable` returns `[]` (ran via
  `uv run python -c`).
- Full-tree grep:
  `grep -rn -i -E "toolset|enable_tool|disable_tool|tool_filter"` across
  `.venv/lib/python3.12/site-packages/mcp/` matches *only*
  `ToolListChangedNotification` plumbing (`types.py:1372`, `1378`) and
  `session.send_tool_list_changed` (`server/session.py:477`). Both are
  for *all-tool list_changed* broadcast, not per-client toolset
  enablement.

## Findings

**No native toolset support in `mcp==1.27.0`.** The SDK does not model
toolsets at any layer:

1. **Wire protocol.** The `Tool` schema has no `toolset`/`group`
   field; the `ListToolsResult` has no grouping. `ServerCapabilities`
   has no `toolsets` capability. Only a free-form `_meta`
   (`Tool.meta: dict | None`, `types.py:1331`) and
   `ServerCapabilities.experimental` (`types.py:509`) dict are
   available for out-of-band extensions.
2. **Server API.** `FastMCP.add_tool` accepts arbitrary `meta`, but
   neither `FastMCP` nor `ToolManager` nor the low-level `Server`
   expose any symbol named `toolset`, `enable_tool`, `tool_filter`, or
   similar. No `on_list_tools` hook. No per-client toolset state. The
   only client-visible enablement signal is the all-tools
   `notifications/tools/list_changed` broadcast
   (`types.py:1372-1378`).
3. **Client enablement.** There is no client-side RPC for enabling or
   disabling toolsets. A client cannot ask the server "activate the
   `writes` toolset for this session" — the SDK simply doesn't model
   the concept. The nearest analogues (GitHub MCP server's "toolset"
   feature flag pattern; Cursor-style "modes") are server-internal
   conventions, implemented by re-registering / filtering tools; they
   ride on `_meta` and `list_changed` rather than any formal SDK API.

The meta placeholder currently used by M3's `_register_everything`
(`src/wazuh_mcp/server.py`) — where write-tool registrations can carry
`meta={"toolset": "writes"}` — remains a **server-side annotation with
no MCP-level semantics**. It is visible to clients on `tools/list`
responses but the SDK does not interpret it, and no current MCP client
(Claude Desktop, Cursor, mcp-inspector) changes behavior based on it.

## Decision for M4b

**Keep the M3 placeholder.** Continue writing
`meta={"toolset": "writes"}` on write-tool registrations in
`_register_everything` as a forward-looking annotation. Do **not** wire
it into any server-side enable/disable logic for M4b — the two-layer
allowlist (toolset-level via `tenant.toolsets.writes.enabled` + per-tool
`tenant.write_allowlist`) remains the source of truth. The `_meta`
annotation is purely descriptive: useful for future inspection tools,
for a future client-enablement feature once the SDK or protocol
gains one, and for human-readable diagnostics during audits.

Revisit in **M4c** when we evaluate per-client UI treatments (e.g., a
Claude Desktop feature-flag gating writes behind an explicit "enable
writes" toggle). The expected path there is:

1. Upstream the SDK once the MCP spec adopts toolsets (no open PR yet
   as of 2026-04-24 on
   `github.com/modelcontextprotocol/modelcontextprotocol`), or
2. Use `ServerCapabilities.experimental["toolsets"] = {...}` + a
   bespoke request/notification pair wrapped by `list_changed`, which
   clients already know how to re-poll on.

Document this explicitly in the M4b retro so the next cycle can pick
it up without re-running the probe.

## Implementation sketch (if supported)

Not supported, so no wiring. For reference, the conditional sketch that
would have fit (had a `FastMCP.toolset(...)` API existed, hypothetically)
is:

```python
# Hypothetical: NOT valid against mcp==1.27.0.
writes = mcp_app.toolset("writes", description="Mutating Wazuh operations")
with writes.require_enablement():  # client must opt in
    @writes.tool(...)
    async def write_isolate_agent(...): ...
```

The actual M4b wiring stays at:

```python
mcp_app.add_tool(
    write_isolate_agent,
    name="write.isolate_agent",
    meta={"toolset": "writes"},  # placeholder; SDK ignores it today
)
```

with enforcement handled by the two-layer allowlist at
`_register_everything` (skip the `add_tool` call entirely when the
tenant config excludes a given write name).
