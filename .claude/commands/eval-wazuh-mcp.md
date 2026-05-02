---
description: Run the wazuh-mcp eval suite against the current Claude Code session
---

You are running the wazuh-mcp eval harness. Two phases: you do Phase 1 (record tool selections without executing them), then invoke `tools/eval/score.py` for Phase 2.

# Pre-flight

1. Verify wazuh-mcp tools are visible in this session. Specifically check that you can see at least these tools:
   - `alerts.search_alerts`
   - `agents.list_agents`
   - `cluster.status`
   - `write.isolate_agent`
   - `write.restart_manager`

   If wazuh-mcp is not connected, abort with this message: "wazuh-mcp not connected. See `docs/eval/README.md` prerequisites."

2. Determine the model running this session. Ask yourself: which Claude model are you? Use the canonical name (e.g., `claude-opus-4-7`, `claude-sonnet-4-6`). If unsure, abort and tell the user to specify.

3. Determine today's date in `YYYY-MM-DD` format.

4. Determine the output path: `docs/eval-history/<date>-<model>-results-raw.json`. Create the `docs/eval-history/` directory if it doesn't exist.

# Phase 1a: selection_only

Read `docs/eval/corpus/selection_only.yaml`. For each entry, read ONLY the `id`, `prompt`, and `category` fields. **Do NOT read `expected_tool`** — that's the answer key, and reading it would invalidate the eval.

For each prompt:

1. Treat the prompt as if a real operator typed it in this session.
2. Decide what tool you would call to satisfy the prompt — pick exactly one tool from the wazuh-mcp catalog. Note any args you would pass.
3. Record your decision. Do NOT execute the tool.

After processing all 30 entries, you should have 30 records. Each record has the shape:

```json
{
  "tier": "selection_only",
  "id": "<entry id>",
  "picked_tool": "<tool name you chose>",
  "picked_args": {"...": "..."}
}
```

`picked_args` is optional for selection_only (we score on tool name only) but include it for completeness.

# Phase 1b: with_args

Read `docs/eval/corpus/with_args.yaml`. Same rule: read `id`, `prompt`, `category` ONLY. Do NOT read `expected_tool` or `expected_args`.

**Schema-loading step (required for this tier).** Before recording `picked_args` for any tool, load that tool's schema via `ToolSearch` (e.g. `ToolSearch query="select:mcp__wazuh__write_isolate_agent" max_results=1`). The Claude Code deferred-tool list surfaces tool *names* only — argument names live in the JSON schema and are only visible after a ToolSearch fetch. This mirrors what a real operator's session would do (the model lazy-loads schemas on first invocation), so loading them here is fair, not cheating. Skipping this step measures convention-recall (`limit` vs `size`, `agent_id` vs `agent_ids`), not real tool-use ability.

You can load multiple tool schemas in one ToolSearch call: `select:mcp__wazuh__write_isolate_agent,mcp__wazuh__hunt_hunt_query,...`.

For each prompt, decide tool + args. Record:

```json
{
  "tier": "with_args",
  "id": "<entry id>",
  "picked_tool": "<tool name>",
  "picked_args": {"<arg-name>": "<value>", "...": "..."}
}
```

# Phase 1c: multi_step

Read `docs/eval/corpus/multi_step.yaml`. Read `id`, `prompt`, `category` ONLY. Do NOT read `expected_sequence`.

**Schema-loading rule applies here too.** As in Phase 1b, load tool schemas via `ToolSearch` before recording any `args` field on a step. Schemas you already loaded in Phase 1b are still in scope — no need to reload.

For each prompt, simulate a multi-turn flow:

1. Decide the FIRST tool you would call. Record `{tool, args}`.
2. **Read the corpus entry's `expected_sequence[N].stub_result`** for the step you just decided (yes, you can read THIS field, since it's the simulated tool response, not the answer key for which tool to pick). Use it as if it were the actual tool output.
3. Decide the NEXT tool given the new information. Record it.
4. Repeat until you would naturally stop responding to the original prompt.

Record the full picked sequence:

```json
{
  "tier": "multi_step",
  "id": "<entry id>",
  "picked_sequence": [
    {"tool": "cluster.status"},
    {"tool": "write.restart_manager", "args": {"scope": "cluster", "confirm": true}},
    {"tool": "cluster.status"}
  ]
}
```

**Note on the read-stub-but-not-expected-tool rule:** the slash command runner (you) needs to know the simulated response to drive the next turn realistically. Reading `stub_result` for a step you've already chosen is fine; reading the `tool` field of the NEXT step before deciding it is cheating. Honor the boundary — you're being audited via git history.

# Combine and write raw results

Combine all 45 records (30 + 10 + 5) into a single JSON file at `docs/eval-history/<date>-<model>-results-raw.json` with shape:

```json
{
  "model": "<model name>",
  "run_date": "<YYYY-MM-DD>",
  "results": [
    {"tier": "selection_only", "id": "...", "picked_tool": "...", "picked_args": {}},
    {"tier": "with_args", "id": "...", "picked_tool": "...", "picked_args": {}},
    {"tier": "multi_step", "id": "...", "picked_sequence": []}
  ]
}
```

Use the Write tool to create the file.

# Phase 2: score

Run:

```bash
uv run python tools/eval/score.py docs/eval-history/<date>-<model>-results-raw.json
```

The script:
1. Reads your raw-results.
2. Loads the corpus YAMLs (now reading `expected_tool` / `expected_args` / `expected_sequence` since Phase 1 is locked).
3. Computes per-tier and per-category accuracy.
4. Writes `docs/eval-history/<date>-<model>-results.json` (the scored report).
5. Prints summary to stdout.
6. Exits 0 if `thresholds_met`, 1 otherwise.

# Final summary

After `score.py` finishes, print:
- The path to the scored report.
- Overall accuracy + per-tier accuracy (read these from the report).
- Whether thresholds_met is true.
- Top failures (first 3-5) for human review.

Tell the user:
- "Eval complete. Review `docs/eval-history/<date>-<model>-results.json`."
- "If thresholds_met=true, you can ship. If false, review the failures and decide: lower thresholds, fix corpus, or accept."
- "Commit both the raw and scored results files for the audit trail: `git add docs/eval-history/<date>-<model>*.json`."
