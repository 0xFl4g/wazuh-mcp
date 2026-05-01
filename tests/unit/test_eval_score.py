"""Unit tests for tools/eval/score.py — pure-Python scoring."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from tools.eval.score import (
    ThresholdMet,
    score_run,
)


@pytest.fixture
def corpus_dir(tmp_path) -> Path:
    """Minimal three-tier corpus."""
    (tmp_path / "selection_only.yaml").write_text(
        """
- id: t1
  prompt: "p1"
  expected_tool: alerts.search_alerts
  category: triage
- id: t2
  prompt: "p2"
  expected_tool: agents.list_agents
  category: inventory
""".strip()
    )
    (tmp_path / "with_args.yaml").write_text(
        """
- id: a1
  prompt: "p3"
  expected_tool: write.isolate_agent
  expected_args:
    agent_ids: ["001"]
    confirm: true
  category: writes
""".strip()
    )
    (tmp_path / "multi_step.yaml").write_text(
        """
- id: m1
  prompt: "p4"
  expected_sequence:
    - tool: cluster.status
    - tool: write.restart_manager
      args: {scope: "node", confirm: true}
  category: triage
""".strip()
    )
    return tmp_path


@pytest.fixture
def thresholds_path(tmp_path) -> Path:
    p = tmp_path / "thresholds.yaml"
    p.write_text(
        """
default:
  selection_only: 0.50
  with_args: 0.50
  multi_step: 0.50
  overall: 0.50
per_model: {}
""".strip()
    )
    return p


def test_all_pass_returns_threshold_met(corpus_dir, thresholds_path, tmp_path) -> None:
    raw = {
        "model": "claude-opus-4-7",
        "run_date": "2026-04-28",
        "results": [
            {"tier": "selection_only", "id": "t1", "picked_tool": "alerts.search_alerts"},
            {"tier": "selection_only", "id": "t2", "picked_tool": "agents.list_agents"},
            {
                "tier": "with_args",
                "id": "a1",
                "picked_tool": "write.isolate_agent",
                "picked_args": {"agent_ids": ["001"], "confirm": True},
            },
            {
                "tier": "multi_step",
                "id": "m1",
                "picked_sequence": [
                    {"tool": "cluster.status"},
                    {"tool": "write.restart_manager", "args": {"scope": "node", "confirm": True}},
                ],
            },
        ],
    }
    raw_path = tmp_path / "raw.json"
    raw_path.write_text(json.dumps(raw))

    report = score_run(raw_path, corpus_dir, thresholds_path)
    assert report["overall"]["accuracy"] == 1.0
    assert report["overall"]["passed"] == 4
    assert report["overall"]["failed"] == 0
    assert report["thresholds_met"] is True


def test_wrong_tool_fails_selection(corpus_dir, thresholds_path, tmp_path) -> None:
    raw = {
        "model": "claude-opus-4-7",
        "run_date": "2026-04-28",
        "results": [
            {"tier": "selection_only", "id": "t1", "picked_tool": "agents.list_agents"},
            {"tier": "selection_only", "id": "t2", "picked_tool": "agents.list_agents"},
            {
                "tier": "with_args",
                "id": "a1",
                "picked_tool": "write.isolate_agent",
                "picked_args": {"agent_ids": ["001"], "confirm": True},
            },
            {
                "tier": "multi_step",
                "id": "m1",
                "picked_sequence": [
                    {"tool": "cluster.status"},
                    {"tool": "write.restart_manager", "args": {"scope": "node", "confirm": True}},
                ],
            },
        ],
    }
    raw_path = tmp_path / "raw.json"
    raw_path.write_text(json.dumps(raw))

    report = score_run(raw_path, corpus_dir, thresholds_path)
    assert report["by_tier"]["selection_only"]["failed"] == 1
    assert report["by_tier"]["selection_only"]["accuracy"] == 0.5
    failure = next(f for f in report["failures"] if f["id"] == "t1")
    assert failure["expected"] == "alerts.search_alerts"
    assert failure["picked"] == "agents.list_agents"


def test_with_args_subset_match(corpus_dir, thresholds_path, tmp_path) -> None:
    """Extra args in picked are OK; missing/wrong required args fail."""
    raw = {
        "model": "x",
        "run_date": "2026-04-28",
        "results": [
            {
                "tier": "with_args",
                "id": "a1",
                "picked_tool": "write.isolate_agent",
                "picked_args": {"agent_ids": ["001"], "confirm": True, "extra_field": "ok"},
            },
        ],
    }
    raw_path = tmp_path / "raw.json"
    raw_path.write_text(json.dumps(raw))
    report = score_run(raw_path, corpus_dir, thresholds_path)
    assert report["by_tier"]["with_args"]["passed"] == 1


def test_with_args_missing_required_fails(corpus_dir, thresholds_path, tmp_path) -> None:
    raw = {
        "model": "x",
        "run_date": "2026-04-28",
        "results": [
            {
                "tier": "with_args",
                "id": "a1",
                "picked_tool": "write.isolate_agent",
                "picked_args": {"agent_ids": ["001"]},
            },  # missing confirm
        ],
    }
    raw_path = tmp_path / "raw.json"
    raw_path.write_text(json.dumps(raw))
    report = score_run(raw_path, corpus_dir, thresholds_path)
    assert report["by_tier"]["with_args"]["failed"] == 1


def test_multi_step_length_mismatch_fails(corpus_dir, thresholds_path, tmp_path) -> None:
    raw = {
        "model": "x",
        "run_date": "2026-04-28",
        "results": [
            {
                "tier": "multi_step",
                "id": "m1",
                "picked_sequence": [
                    {"tool": "cluster.status"},  # only 1 step, expected 2
                ],
            },
        ],
    }
    raw_path = tmp_path / "raw.json"
    raw_path.write_text(json.dumps(raw))
    report = score_run(raw_path, corpus_dir, thresholds_path)
    assert report["by_tier"]["multi_step"]["failed"] == 1


def test_threshold_not_met_returns_false(corpus_dir, tmp_path) -> None:
    """Set a strict threshold (0.99) and supply only a partial pass."""
    thresholds = tmp_path / "thresholds.yaml"
    thresholds.write_text(
        """
default:
  selection_only: 0.99
  with_args: 0.99
  multi_step: 0.99
  overall: 0.99
per_model: {}
""".strip()
    )
    raw = {
        "model": "x",
        "run_date": "2026-04-28",
        "results": [
            {"tier": "selection_only", "id": "t1", "picked_tool": "agents.list_agents"},  # wrong
            {"tier": "selection_only", "id": "t2", "picked_tool": "agents.list_agents"},
        ],
    }
    raw_path = tmp_path / "raw.json"
    raw_path.write_text(json.dumps(raw))
    report = score_run(raw_path, corpus_dir, thresholds)
    assert report["thresholds_met"] is False


def test_per_model_threshold_override(corpus_dir, tmp_path) -> None:
    """per_model entry overrides default for that model."""
    thresholds = tmp_path / "thresholds.yaml"
    thresholds.write_text(
        """
default:
  overall: 0.99
per_model:
  claude-opus-4-7:
    overall: 0.40
""".strip()
    )
    raw = {
        "model": "claude-opus-4-7",
        "run_date": "2026-04-28",
        "results": [
            {"tier": "selection_only", "id": "t1", "picked_tool": "alerts.search_alerts"},
            {"tier": "selection_only", "id": "t2", "picked_tool": "agents.list_agents"},
        ],
    }
    raw_path = tmp_path / "raw.json"
    raw_path.write_text(json.dumps(raw))
    report = score_run(raw_path, corpus_dir, thresholds)
    # 100% selection_only, 0% other tiers → still meets the per-model 0.40 overall
    assert report["thresholds_met"] is True


def test_threshold_met_class() -> None:
    """ThresholdMet is a TypedDict-like marker for the report shape."""
    # Just verifies the import works; the type itself is documentation.
    assert ThresholdMet is not None
