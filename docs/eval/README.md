# wazuh-mcp eval harness

Maintainer-run quality gate. Drives Claude Code through a corpus of
security-ops prompts and asserts the model picks the right wazuh-mcp tool
for each.

## Prerequisites

1. Wazuh-mcp connected as an MCP server in your Claude Code session
   (typically via `~/.claude/settings.json`'s `mcpServers` block, with
   `WAZUH_MCP_CONFIG_DIR` pointing at a working config dir).
2. The current Claude Code model recorded somewhere you can paste in
   (Sonnet 4.6, Opus 4.7, etc.).

## Run

In a fresh Claude Code session with wazuh-mcp connected:

    /eval-wazuh-mcp

The slash command:
1. Verifies wazuh-mcp tools are visible.
2. Iterates the three corpus tiers, recording your tool selections to
   `docs/eval-history/<today>-<model>-results-raw.json` *without
   executing the tools*.
3. Invokes `tools/eval/score.py` to score the raw results against
   `tools/eval/thresholds.yaml`.
4. Prints a per-category accuracy summary.

## Three corpus tiers

- `corpus/selection_only.yaml` — 30 entries. Asserts tool name only.
- `corpus/with_args.yaml` — 10 entries. Asserts tool name + a subset of
  expected args (extra args from Claude are OK; missing required args
  fail).
- `corpus/multi_step.yaml` — 5 entries. Asserts a sequence of tool calls
  for multi-turn flows. Each step lists its own `stub_result` that the
  slash command replays as if Wazuh had returned it.

## Adding a prompt

Append a YAML entry under the appropriate tier. Pick a stable `id`
(snake_case, descriptive). Use realistic operator phrasing — not
contrived prompts engineered to be easy. Pick the smallest reasonable
`category`.

## Audit trail

Each run commits two files to `docs/eval-history/`:
- `<today>-<model>-results-raw.json` (Phase 1 output, what Claude
  decided)
- `<today>-<model>-results.json` (Phase 2 output, scored report)

Git history shows accuracy trends across releases. Use
`jq '.failures' docs/eval-history/<file>` to inspect specific
regressions.

## Forward path

A v1.x community contributor with a paid `ANTHROPIC_API_KEY` can wrap
the corpus + `score.py` in a CI workflow by adding
`tools/eval/run_via_api.py` that loops the corpus → calls
`anthropic.Anthropic` → writes raw-results → invokes `score.py`. The
corpus + thresholds + scoring don't change.
