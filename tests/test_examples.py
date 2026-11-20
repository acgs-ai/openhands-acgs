# SPDX-FileCopyrightText: 2026-present ACGS Contributors
#
# SPDX-License-Identifier: Apache-2.0
"""The README only shows code that runs, and the quickstart output it shows is the real output."""

from __future__ import annotations

import json
import os
import re
import runpy
import subprocess
import sys
import textwrap
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from openhands.sdk.security.confirmation_policy import ConfirmRisky

from openhands_acgs import ACGSSecurityAnalyzer
from tests.fakes import REFUND, Recorder, make_conversation, rejections, review_rules, text, tool_call, tool_calls

ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text(encoding="utf-8")
QUICKSTART = ROOT / "examples" / "quickstart.py"
UPSTREAM_WARNING = "ignore:Item 'summary' on TypedDict class 'ChatCompletionReasoningItem':UserWarning"


def _blocks(language: str) -> list[str]:
    return [textwrap.dedent(block) for block in re.findall(rf"```{language}\n(.*?)```", README, re.DOTALL)]


def test_quickstart_output_matches_readme() -> None:
    env = {**os.environ, "OPENHANDS_SUPPRESS_BANNER": "1", "LOG_LEVEL": "WARNING"}
    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-W", "error", "-W", UPSTREAM_WARNING, str(QUICKSTART)],
        capture_output=True,
        text=True,
        check=True,
        cwd=ROOT,
        env=env,
        timeout=300,
    )
    [expected] = [block for block in _blocks("text") if block.startswith("ran:")]
    assert completed.stdout == expected
    assert completed.stderr == ""


def test_readme_embeds_the_quickstart_verbatim() -> None:
    assert QUICKSTART.read_text(encoding="utf-8") in _blocks("python")


def test_deny_and_audit_runs_offline_without_api_keys(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    for key in list(os.environ):
        if key.endswith("API_KEY"):
            monkeypatch.delenv(key)
    # The example sets these at import time; registering them here makes monkeypatch restore them.
    for key, value in {
        "OPENHANDS_SUPPRESS_BANNER": "1",
        "OTEL_SDK_DISABLED": "true",
        "LOG_LEVEL": "WARNING",
    }.items():
        monkeypatch.setenv(key, value)
    # pytest-socket disables network access for this in-process example execution.
    runpy.run_path(str(ROOT / "examples" / "deny_and_audit.py"), run_name="__main__")
    output = capsys.readouterr().out
    execution, audit = output.split("Audit trail (application decisions):\n")
    assert execution == "Executed record_note: The meeting starts at noon.\n"
    decisions = [json.loads(line) for line in audit.splitlines()]
    assert [decision["acgs_verdict"] for decision in decisions] == ["allow", "deny"]
    assert [decision["tool_name"] for decision in decisions] == ["record_note", "record_note"]
    assert decisions[0]["acgs_rule_ids"] == []
    assert decisions[1]["acgs_rule_ids"] == ["ACGS-006"]
    assert "Blocked by" in decisions[1]["acgs_reason"]
    assert "demo-secret" not in output


def test_readme_states_the_supported_versions() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    for package in ("openhands-sdk", "acgs-lite"):
        [requirement] = re.findall(rf'"({package}>=[^"]+)"', pyproject)
        assert f"`{requirement}`" in README
        [floor] = re.findall(rf'"{package}==([^"]+)"', pyproject)
        assert requirement.startswith(f"{package}>={floor},")
    assert README.count("openhands-sdk 1.54.0") == 3
    assert "Requires Python 3.12 to 3.14" in README
    assert 'requires-python = ">=3.12,<3.15"' in pyproject


def test_every_readme_python_block_runs(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    blocks = [block for block in _blocks("python") if block != QUICKSTART.read_text(encoding="utf-8")]
    assert len(blocks) == 5
    namespaces: list[dict[str, Any]] = []
    for index, block in enumerate(blocks):
        conversation = make_conversation(tmp_path / str(index), Recorder(), [text("Done.")])
        namespace: dict[str, Any] = {"__name__": "readme", "conversation": conversation}
        exec(compile(block, "<README>", "exec", dont_inherit=True), namespace)  # noqa: S102
        namespaces.append(namespace)
    assert "normalized: update config | dry run" in capsys.readouterr().out

    setup, loop, usage = namespaces[0], namespaces[1], namespaces[2]
    for namespace in (setup, usage):
        state = namespace["conversation"].state
        assert isinstance(state.security_analyzer, ACGSSecurityAnalyzer)
        assert isinstance(state.confirmation_policy, ConfirmRisky)
    assert namespaces[-1]["analyzer"].agent_id == "payments-app"

    # The README's run loop: its approver says no, so the refund is rejected and the agent finishes.
    recorder = Recorder()
    conversation = make_conversation(
        tmp_path / "loop", recorder, [tool_calls(tool_call("issue_refund", REFUND)), text("Not refunded.")]
    )
    analyzer = ACGSSecurityAnalyzer(constitution=review_rules())
    conversation.set_security_analyzer(analyzer)
    conversation.set_confirmation_policy(ConfirmRisky())
    conversation.send_message("refund A-17")
    run_governed: Callable[..., None] = loop["run_governed"]
    run_governed(conversation, analyzer)
    assert recorder.ran == []
    assert rejections(conversation) == ["ACGS: The reviewer did not approve it, so it was not executed."]
