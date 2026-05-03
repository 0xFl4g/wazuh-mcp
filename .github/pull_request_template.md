<!--
Thanks for the PR. Keep this template short — fill what's relevant, drop what isn't.
Read CONTRIBUTING.md before opening: commit style, CI gates, code style.
-->

## Summary

<!-- One or two sentences. What does this PR do, and why? -->

## Type

<!-- Pick one or more. -->

- [ ] Bug fix
- [ ] New feature
- [ ] Refactor / cleanup (no functional change)
- [ ] Documentation
- [ ] CI / tooling
- [ ] Breaking change

## Test plan

<!--
What did you run to convince yourself this is correct?
Tick all that apply; add specifics where useful.
-->

- [ ] `uv run pytest tests/unit -q -m "not integration"` passes locally
- [ ] `uv run ruff check . && uv run ruff format --check . && uv run ty check src tests` clean
- [ ] Integration suite (`tests/integration/`) — run if you touched integration paths or the docker stack
- [ ] Helm chart (`helm lint charts/wazuh-mcp/`) — run if you touched `charts/`
- [ ] Manual smoke against a real Wazuh deployment — describe what

## Backwards compatibility

<!--
Does this change the wire format of any tool's args or result?
Does it change the shape of `server.yaml` / `tenants.yaml` / `secrets.yaml`?
Does it change the `/healthz` or `/metrics` contract?
If yes, describe the migration story (or call it explicitly out of scope).
-->

## Related issues / specs

<!-- Closes #N. Refs `docs/superpowers/specs/...` if applicable. -->
