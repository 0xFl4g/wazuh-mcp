# FastMCP list_tools filter probe

Question: can `list_tools` be filtered per-Session by RBAC via an SDK hook,
or must we wrap the handler?

## SDK version probed

`mcp == 1.27.0` (pin from `uv.lock`; confirmed at runtime via
`importlib.metadata.version("mcp")`).

## Surface inspected

Installed site-packages under
`/Users/moody/VSCode/wazuh-mcp/.venv/lib/python3.12/site-packages/mcp/`:

- `mcp/server/fastmcp/server.py` (1349 lines) — `FastMCP` class.
- `mcp/server/fastmcp/tools/tool_manager.py` — `ToolManager`.
- `mcp/server/lowlevel/server.py` (824 lines) — low-level `Server`.

Specifically inspected:

- `FastMCP._setup_handlers` at `fastmcp/server.py:302-313` — registers the
  bound methods `FastMCP.list_tools` / `FastMCP.call_tool` / etc. on the
  underlying low-level server by calling its decorators as plain functions,
  e.g. `self._mcp_server.list_tools()(self.list_tools)`.
- `FastMCP.list_tools` at `fastmcp/server.py:315-330` — builds the response
  by calling `self._tool_manager.list_tools()` (no args, no session
  awareness) and mapping each `Tool` to an MCP `Tool`.
- `FastMCP.call_tool` at `fastmcp/server.py:343-346` — delegates to
  `self._tool_manager.call_tool(name, arguments, context=context, ...)`.
- `ToolManager.list_tools` at
  `fastmcp/tools/tool_manager.py:41-43` — returns `list(self._tools.values())`.
  No filter arg, no session arg, no hook.
- `Server.list_tools` decorator at `lowlevel/server.py:434-465` — registers
  a handler into `self.request_handlers[types.ListToolsRequest]`. The
  registered wrapper also refreshes `self._tool_cache` with every returned
  tool (`lowlevel/server.py:447-459`). That cache is read by
  `_get_cached_tool_definition` (`lowlevel/server.py:476-490`) during
  `call_tool` dispatch for input validation — **not** for authorization.
- `Server.call_tool` decorator at `lowlevel/server.py:492-589` — the call
  handler at line 521 pulls `req.params.name` and invokes `func(tool_name,
  arguments)` unconditionally; the tool-cache lookup only feeds JSON
  Schema validation. There is no authorization gate anywhere on this
  path.
- `FastMCP` attributes that mention "list", "filter", or "tool":
  `{add_tool, call_tool, list_prompts, list_resource_templates,
  list_resources, list_tools, remove_tool, tool}`. Nothing like
  `on_list_tools`, `tool_filter`, `middleware`, or a session-aware hook.
- Grepping `fastmcp/server.py` for `middleware|hook|filter` turns up only
  Starlette HTTP middleware (auth context, bearer auth) — none of which
  intercepts the MCP-level `tools/list` response.

## Findings

No native per-request `list_tools` filter hook exists in FastMCP 1.27.0.
`FastMCP.list_tools` is a plain bound method with no extension point.
`ToolManager.list_tools` is argument-free and session-agnostic. The
low-level `Server.list_tools` decorator only supports registering *one*
handler (overwrites `self.request_handlers[types.ListToolsRequest]`),
so calling it a second time from our code would replace FastMCP's handler
entirely — not chain.

Of the three options the plan laid out:

- **(a) Native filter hook — does not exist.** The FastMCP surface has no
  `on_list_tools`, `tool_filter`, or session-aware hook, and no
  middleware seam between the low-level dispatcher and the bound
  `list_tools` method. Starlette middleware sits at the HTTP layer, too
  early to see the MCP method name, and also doesn't apply to stdio.
- **(b) Drop to low-level Server — not cleanly available alongside
  `@mcp_app.tool(...)`.** Re-registering
  `@app._mcp_server.list_tools()(...)` after `_setup_handlers` ran would
  clobber FastMCP's own handler (`request_handlers[ListToolsRequest]` is
  a single slot). We would lose FastMCP's Tool→MCPTool conversion and
  its tool-cache refresh. Workable but invasive.
- **(c) Wrap FastMCP's bound method — the right fit.** FastMCP assigns
  handlers *by reference* inside `_setup_handlers`. That binding happens
  once at `FastMCP.__init__` time (line 304), so re-assigning
  `app.list_tools` after-the-fact does not rewire the low-level
  dispatcher. We instead install our own handler on the low-level server
  *after* `FastMCP.__init__` returns, delegating to FastMCP's original
  `list_tools` for the unfiltered list and then filtering. Overwriting
  the single-slot `request_handlers[types.ListToolsRequest]` is expected
  usage — it's how the low-level API is designed — and it remains
  backward compatible with stdio and HTTP because both transports
  dispatch through the same `Server._handle_request` at
  `lowlevel/server.py:729`.

## Decision for T25

**Option (c): wrap the handler by re-registering on the low-level server.**

In `build_app` / `build_http_app` (see `_register_everything` at
`src/wazuh_mcp/server.py:244-540`), after all `@mcp_app.tool(...)`
decorators have run, install a replacement `ListToolsRequest` handler on
`mcp_app._mcp_server` that:

1. Collects the full tool list from FastMCP's bound
   `mcp_app.list_tools()` (preserves the `Tool→MCPTool` mapping and the
   low-level tool-cache refresh semantics — because our replacement
   handler can just call FastMCP's `list_tools` coroutine internally).
2. Reads `current_session()` from `wazuh_mcp.auth.session_ctx`.
3. Resolves `effective_allowlist_for(tenant_override=...)` from the
   tenant config.
4. Returns only the tools passing
   `rbac.filter.is_allowed(session, tool.name, effective)`.

We must also guard `call_tool`: `Server.call_tool`'s dispatcher does not
consult any authorization, so a client that knows a tool name could
invoke a tool that was filtered out of `list_tools`. T25 should wrap
`mcp_app.call_tool` with the same `is_allowed` check and raise a
`ToolError` ("unknown tool" or explicit "forbidden" — to be decided,
matching whatever leaks the least information) when denied.

## Implementation sketch

```python
# after _register_everything(mcp_app, ...)
import mcp.types as _mt
from mcp.server.lowlevel.server import Server as _LL
from wazuh_mcp.auth.session_ctx import current_session
from wazuh_mcp.rbac.filter import is_allowed
from wazuh_mcp.rbac.policy import effective_allowlist_for

_fastmcp_list_tools = mcp_app.list_tools  # bound method from _setup_handlers

@mcp_app._mcp_server.list_tools()
async def _rbac_list_tools() -> list[_mt.Tool]:
    all_tools = await _fastmcp_list_tools()
    try:
        session = current_session()
    except LookupError:
        return all_tools  # stdio pre-session path; T25 decides policy
    effective = effective_allowlist_for(tenant_override=session.tenant.rbac_overrides)
    return [t for t in all_tools if is_allowed(session, t.name, effective)]

_fastmcp_call_tool = mcp_app.call_tool
async def _rbac_call_tool(name, arguments):
    session = current_session()
    effective = effective_allowlist_for(tenant_override=session.tenant.rbac_overrides)
    if not is_allowed(session, name, effective):
        raise ToolError(f"Unknown tool: {name}")
    return await _fastmcp_call_tool(name, arguments)
mcp_app._mcp_server.call_tool(validate_input=False)(_rbac_call_tool)
```

Both re-registrations overwrite the single-slot entries FastMCP installed
during `__init__`, which is the only supported extension pattern in the
low-level API. The existing `_tool_cache` refresh behavior inside
`Server.list_tools`'s wrapper still fires because we call through to
FastMCP's `list_tools`, which returns the full (unfiltered-at-cache-layer)
list — we filter the *response*, not the internal cache. That matters for
`call_tool`'s input-schema validation, which relies on the cache.

## Open concerns

- **Stdio pre-session path.** `build_app` sets the session contextvar
  once before `app.run_stdio_async()` (server.py:136-138), so
  `current_session()` will resolve for every in-loop `tools/list`. The
  initial listing during initialize handshake happens after that
  priming, so the filter is safe. But a `LookupError` branch is still
  prudent — T25 should decide whether the safe default on stdio-without-
  session is "allow all" (single-tenant, trusted) or "deny all" (strict).
  Recommend allow-all on stdio with an audit event, because the process
  is the trust boundary there.
- **HTTP session timing.** Sessions are set by HTTP middleware on each
  request. The filter reads `current_session()` which must be populated
  by auth middleware *before* the MCP request handler runs. Existing
  HTTP wiring in M3 already ensures this for `call_tool`; we just need
  to verify `tools/list` takes the same path. It does: the Starlette
  app mounts `StreamableHTTPSessionManager`, which calls into
  `Server._handle_request` for every MCP method, after auth middleware.
- **Tool-cache / `call_tool` input validation.** Because our wrapped
  `list_tools` still returns the full list to the low-level dispatcher's
  cache-refresh loop (we filter the response, not `_tool_cache`), the
  schema validator on `call_tool` keeps working normally. Verified
  against `lowlevel/server.py:447-459` and 476-490.
- **Leak via error wording.** The sketch returns "Unknown tool: {name}"
  for denied calls to avoid disclosing the presence of a tool the
  caller cannot see. T25 must pick this deliberately; document it in
  the audit event so operators can tell apart "doesn't exist" from
  "role denied".
- **Dynamically registered tools.** `mcp_app.add_tool(...)` after startup
  would be picked up by our wrapper on the next `tools/list` because we
  call through FastMCP's `list_tools` each time. No caching on our side
  required. (wazuh-mcp does not currently register tools post-startup,
  so this is a latent property, not a need.)
- **`FastMCP` private-attr access.** We reach into `mcp_app._mcp_server`
  and re-use the low-level decorators. That's a documented pattern in
  the SDK's own docstrings (`lowlevel/server.py:23-28` advertises
  `@server.list_tools()` as the public extension point), but T25 should
  add a comment + a smoke test pinning `mcp==1.27.x` behavior so a
  future SDK bump that renames `_mcp_server` fails loudly in CI.
- **Order vs. the existing handler.** FastMCP installs its handler in
  `_setup_handlers` during `__init__`. Our wrap runs *after*
  `_register_everything`. Because `request_handlers` is a single-slot
  dict, the last registration wins — we must register last. T25 should
  assert this by asserting the replaced handler identity (or adding a
  unit test that exercises the handler via
  `await mcp_app._mcp_server.request_handlers[ListToolsRequest](req)`).
