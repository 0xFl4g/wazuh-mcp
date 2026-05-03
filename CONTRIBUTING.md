# Contributing to wazuh-mcp

## Quick start

```bash
git clone https://github.com/0xFl4g/wazuh-mcp.git
cd wazuh-mcp
uv sync
uv run pytest tests/unit -q -m "not integration"   # 591 PASS, 4 SKIP
```

## What to expect

- **`main` is the integration branch.** All PRs target `main`. Feature branches are short-lived.
- **Atomic commits, scope-prefixed messages.** Commit style: `scope(area): subject in imperative mood`. Examples: `feat(rate_limit): ...`, `fix(integration): ...`, `docs(v1.1): ...`. The body explains *why*.
- **No AI-attribution footers.** No `Co-Authored-By: Claude`, no "Generated with..." trailers. All commits land in the contributor's voice.
- **TDD-first for non-trivial changes.** Write the failing test, get it to fail for the right reason, implement, watch it pass, commit.
- **Small PRs.** A clean 200-line PR lands faster than a 2000-line one. If a feature is large, split into a series.

## CI gates

Every PR runs:

- **`ci`** — `ruff check`, `ruff format --check`, `ty check`, `pytest tests/unit`. Must pass.
- **`helm-lint`** — runs on chart edits. Must pass.
- **`security`** — `gitleaks`, `pip-audit`, `safety`. Must pass.
- **`integration`** — runs nightly + on workflow_dispatch. Touching integration code? Trigger it via `gh workflow run integration.yml` before requesting review.

## Code style

- Python 3.12. Type hints required on new code. `ruff` config in `pyproject.toml` is authoritative; selects `E/F/I/UP/B/SIM/RUF/N/ASYNC`.
- Pydantic models default to `model_config = ConfigDict(extra="forbid", frozen=True)` unless mutability is genuinely needed.
- Use `# ty: ignore` for type-checker suppressions, not `# type: ignore` (we use `ty`, not mypy).
- Avoid `# noqa: <CODE>` for codes not in the project's ruff selects — they trigger `RUF100 unused-noqa`. Use a plain explanatory comment instead.

## Tests

- Unit tests in `tests/unit/`. Async tests use `asyncio_mode = "auto"` (no explicit `@pytest.mark.asyncio` decorator needed but harmless).
- Integration tests in `tests/integration/`, marked `@pytest.mark.integration`. Spun up via `docker compose -f docker/integration-compose.yml up -d` + the bootstrap script.
- New write-tools (`write.*`) require a unit test for the allowlist contract AND an integration test that proves the wire shape.
- Cross-subsystem changes (touching tenancy, rate-limiter, audit) require plan-time invariant grep — see prior ship history for the M5a Keycloak claim-mapper / IssuerIndex precedent.

## Documentation

- Operator-facing changes update `docs/deploy/*.md`.
- New tools update `docs/api-reference.md`.
- Design docs go in `docs/superpowers/specs/YYYY-MM-DD-<topic>-design.md`. Implementation plans in `docs/superpowers/plans/`. These are intentionally public — they document how decisions were made.

## Reporting bugs

For non-security bugs: open a GitHub issue with the `bug` label.
For security issues: see [`SECURITY.md`](SECURITY.md). Do not open a public issue.

## Releasing

Maintainers only. Process:

1. Bump `version` in `pyproject.toml`; run `uv lock`.
2. Commit with `chore: bump version X -> Y`.
3. Tag: `git tag -a vX.Y.Z -m "release notes here"`.
4. Push `main` + the tag. The `release` workflow publishes to GHCR.
5. Create a GitHub Release page with formatted notes.
