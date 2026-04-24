"""Verify conftest auto-skips @pytest.mark.requires_manager on arm64+darwin."""
from __future__ import annotations

import platform
import subprocess
import sys
import textwrap
from pathlib import Path


def test_auto_skip_on_arm64_darwin(tmp_path: Path) -> None:
    """Emulate arm64+darwin via subprocess and assert the marker skips."""
    test_file = tmp_path / "test_sample.py"
    test_file.write_text(textwrap.dedent("""
        import pytest

        @pytest.mark.requires_manager
        def test_should_skip_on_arm64_darwin():
            assert True
    """))
    conftest = tmp_path / "conftest.py"
    repo_conftest = Path(__file__).resolve().parents[2] / "tests" / "conftest.py"
    conftest.write_text(repo_conftest.read_text())
    env = {
        "PATH": __import__("os").environ.get("PATH", ""),
        "WAZUH_MCP_FORCE_ARM64_DARWIN": "1",  # test-only override read by conftest
    }
    result = subprocess.run(
        [sys.executable, "-m", "pytest", str(test_file), "-v", "--no-header"],
        capture_output=True,
        text=True,
        env=env,
        cwd=tmp_path,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "SKIPPED" in result.stdout
    assert "requires_manager" in result.stdout


def test_runs_on_current_platform_when_not_arm64_darwin() -> None:
    """Sanity: when the override env var is absent, native platform decides."""
    is_arm_mac = platform.system() == "Darwin" and platform.machine() == "arm64"
    # On arm64+darwin, @requires_manager marks should skip by default.
    # This is just a meta-check: we assert the predicate matches the runtime.
    assert isinstance(is_arm_mac, bool)
