"""wazuh-mcp eval scoring (Phase 2 of the eval harness).

Pure-Python, no API access. Loads raw-results JSON + corpus YAMLs +
thresholds, asserts per-tier (selection_only / with_args / multi_step),
writes scored report, returns the report dict for programmatic use.

Exit code 1 if accuracy below gate; intended to be invoked by the
``/eval-wazuh-mcp`` slash command after Phase 1 records picks.

Usage:
    uv run python tools/eval/score.py <raw-results-path> [--corpus DIR] [--thresholds FILE]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, TypedDict

import yaml


class TierStats(TypedDict):
    accuracy: float
    passed: int
    failed: int
    total: int


class ThresholdMet(TypedDict):
    """Final report shape — committed to docs/eval-history/."""

    model: str
    run_date: str
    overall: TierStats
    by_tier: dict[str, TierStats]
    by_category: dict[str, TierStats]
    failures: list[dict[str, Any]]
    thresholds_met: bool


_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_DEFAULT_CORPUS = _REPO_ROOT / "docs" / "eval" / "corpus"
_DEFAULT_THRESHOLDS = _REPO_ROOT / "tools" / "eval" / "thresholds.yaml"


def _load_corpus(corpus_dir: Path) -> dict[str, dict[str, dict[str, Any]]]:
    """Load all three corpus tiers into a {tier: {id: entry}} dict."""
    out: dict[str, dict[str, dict[str, Any]]] = {}
    for tier in ("selection_only", "with_args", "multi_step"):
        path = corpus_dir / f"{tier}.yaml"
        entries = yaml.safe_load(path.read_text()) or []
        out[tier] = {e["id"]: e for e in entries}
    return out


def _check_selection(picked: dict[str, Any], expected: dict[str, Any]) -> bool:
    return picked.get("picked_tool") == expected["expected_tool"]


def _check_with_args(picked: dict[str, Any], expected: dict[str, Any]) -> bool:
    if picked.get("picked_tool") != expected["expected_tool"]:
        return False
    expected_args = expected.get("expected_args") or {}
    picked_args = picked.get("picked_args") or {}
    return all(picked_args.get(k) == v for k, v in expected_args.items())


def _check_multi_step(picked: dict[str, Any], expected: dict[str, Any]) -> bool:
    expected_seq = expected["expected_sequence"]
    picked_seq = picked.get("picked_sequence") or []
    if len(picked_seq) != len(expected_seq):
        return False
    for ps, es in zip(picked_seq, expected_seq, strict=True):
        if ps.get("tool") != es["tool"]:
            return False
        if "args" in es:
            ps_args = ps.get("args") or {}
            for k, v in es["args"].items():
                if ps_args.get(k) != v:
                    return False
    return True


def _stats(passed: int, failed: int) -> TierStats:
    total = passed + failed
    return {
        "accuracy": (passed / total) if total else 1.0,
        "passed": passed,
        "failed": failed,
        "total": total,
    }


def _resolve_thresholds(thresholds: dict[str, Any], model: str) -> dict[str, float]:
    """Per-model overrides default, falling back to default per-key."""
    base = dict(thresholds.get("default", {}))
    per_model = (thresholds.get("per_model") or {}).get(model) or {}
    base.update(per_model)
    return base


def score_run(
    raw_path: Path,
    corpus_dir: Path = _DEFAULT_CORPUS,
    thresholds_path: Path = _DEFAULT_THRESHOLDS,
) -> ThresholdMet:
    raw = json.loads(raw_path.read_text())
    corpus = _load_corpus(corpus_dir)
    thresholds = yaml.safe_load(thresholds_path.read_text()) or {}

    model = raw.get("model", "unknown")
    run_date = raw.get("run_date", "unknown")

    by_tier_passed: dict[str, int] = {"selection_only": 0, "with_args": 0, "multi_step": 0}
    by_tier_failed: dict[str, int] = {"selection_only": 0, "with_args": 0, "multi_step": 0}
    by_cat_passed: dict[str, int] = {}
    by_cat_failed: dict[str, int] = {}
    failures: list[dict[str, Any]] = []

    for picked in raw.get("results", []):
        tier = picked["tier"]
        entry_id = picked["id"]
        expected = corpus[tier].get(entry_id)
        if expected is None:
            # picked an id not in the corpus — score as failure
            failures.append(
                {
                    "id": entry_id,
                    "tier": tier,
                    "expected": "<not in corpus>",
                    "picked": picked.get("picked_tool", picked.get("picked_sequence")),
                }
            )
            by_tier_failed[tier] += 1
            continue

        category = expected.get("category", "uncategorized")
        expected_repr: Any
        picked_repr: Any

        if tier == "selection_only":
            ok = _check_selection(picked, expected)
            expected_repr = expected["expected_tool"]
            picked_repr = picked.get("picked_tool")
        elif tier == "with_args":
            ok = _check_with_args(picked, expected)
            expected_repr = {
                "tool": expected["expected_tool"],
                "args": expected.get("expected_args", {}),
            }
            picked_repr = {
                "tool": picked.get("picked_tool"),
                "args": picked.get("picked_args", {}),
            }
        elif tier == "multi_step":
            ok = _check_multi_step(picked, expected)
            expected_repr = expected["expected_sequence"]
            picked_repr = picked.get("picked_sequence")
        else:
            raise ValueError(f"unknown tier: {tier!r}")

        if ok:
            by_tier_passed[tier] += 1
            by_cat_passed[category] = by_cat_passed.get(category, 0) + 1
        else:
            by_tier_failed[tier] += 1
            by_cat_failed[category] = by_cat_failed.get(category, 0) + 1
            failures.append(
                {
                    "id": entry_id,
                    "tier": tier,
                    "category": category,
                    "expected": expected_repr,
                    "picked": picked_repr,
                }
            )

    by_tier: dict[str, TierStats] = {
        t: _stats(by_tier_passed[t], by_tier_failed[t])
        for t in ("selection_only", "with_args", "multi_step")
    }
    by_category: dict[str, TierStats] = {
        c: _stats(by_cat_passed.get(c, 0), by_cat_failed.get(c, 0))
        for c in (set(by_cat_passed) | set(by_cat_failed))
    }
    overall = _stats(
        sum(by_tier_passed.values()),
        sum(by_tier_failed.values()),
    )

    effective_thresholds = _resolve_thresholds(thresholds, model)

    def _meets(key: str, stats: TierStats) -> bool:
        gate = effective_thresholds.get(key)
        if gate is None:
            return True
        return stats["accuracy"] >= gate

    thresholds_met = _meets("overall", overall) and all(_meets(t, by_tier[t]) for t in by_tier)

    return {
        "model": model,
        "run_date": run_date,
        "overall": overall,
        "by_tier": by_tier,
        "by_category": by_category,
        "failures": failures,
        "thresholds_met": thresholds_met,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Score wazuh-mcp eval raw-results.")
    parser.add_argument("raw_path", type=Path, help="Path to raw-results JSON")
    parser.add_argument("--corpus", type=Path, default=_DEFAULT_CORPUS)
    parser.add_argument("--thresholds", type=Path, default=_DEFAULT_THRESHOLDS)
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Output path for scored results (default: alongside raw)",
    )
    args = parser.parse_args()

    report = score_run(args.raw_path, args.corpus, args.thresholds)

    out = args.out or args.raw_path.with_name(
        args.raw_path.name.replace("-results-raw", "-results")
    )
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

    print(f"\n=== eval scoring summary ({report['model']}, {report['run_date']}) ===")
    print(
        f"Overall: {report['overall']['accuracy']:.2%} "
        f"({report['overall']['passed']}/{report['overall']['total']})"
    )
    for tier, stats in report["by_tier"].items():
        print(f"  {tier}: {stats['accuracy']:.2%} ({stats['passed']}/{stats['total']})")
    if report["failures"]:
        print(f"\nFailures ({len(report['failures'])}):")
        for f in report["failures"][:5]:
            print(f"  - {f['id']} [{f['tier']}]: expected {f['expected']!r}, got {f['picked']!r}")
        if len(report["failures"]) > 5:
            print(f"  ... and {len(report['failures']) - 5} more (see {out})")
    print(f"\nReport written to: {out}")
    print(f"Thresholds met: {report['thresholds_met']}")

    return 0 if report["thresholds_met"] else 1


if __name__ == "__main__":
    sys.exit(main())
