# wazuh-mcp eval scoring

Phase 2 of the eval harness — pure-Python, no API access.

## Usage

`uv run python tools/eval/score.py docs/eval-history/<today>-<model>-results-raw.json`

The `/eval-wazuh-mcp` slash command invokes this automatically. Run
manually only for re-scoring an old raw-results file.

## Output

Writes `<today>-<model>-results.json` alongside the raw input. Shape:

```json
{
  "model": "claude-opus-4-7",
  "run_date": "2026-04-28",
  "overall": {"accuracy": 0.91, "passed": 41, "failed": 4, "total": 45},
  "by_tier": { ... },
  "by_category": { ... },
  "failures": [{"id": "...", "tier": "...", "expected": "...", "picked": "..."}],
  "thresholds_met": true
}
```

## Exit code

0 if `thresholds_met` is true. 1 otherwise. The slash command surfaces
this so the maintainer knows whether the release-gate is met.

## Thresholds

`tools/eval/thresholds.yaml`. `default` applies to every model; `per_model`
overrides specific keys for specific models. Currently:

- default: selection_only >=0.85, with_args >=0.90, multi_step >=0.80, overall >=0.85
- claude-opus-4-7: overall >=0.90 (top-tier bar)

Adjust these only after T6 baseline calibration. Don't lower thresholds
to make a flaky prompt pass — fix the prompt instead.
