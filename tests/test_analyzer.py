# SPDX-FileCopyrightText: 2026-present ACGS Contributors
#
# SPDX-License-Identifier: Apache-2.0
"""End-to-end tests with a real OpenHands ``Conversation``, real tools and OpenHands' scripted offline ``TestLLM``."""

from __future__ import annotations

import logging
from collections.abc import Sequence
from pathlib import Path
from typing import Literal

import pytest
from openhands.sdk import Agent, BaseConversation, LocalConversation
from openhands.sdk.conversation.state import ConversationExecutionStatus
from openhands.sdk.security.analyzer import SecurityAnalyzerBase
from openhands.sdk.security.confirmation_policy import AlwaysConfirm, ConfirmRisky, NeverConfirm
from openhands.sdk.security.risk import SecurityRisk
from openhands.sdk.testing import TestLLM

from openhands_acgs import ACGSSecurityAnalyzer, PendingAction, Verdict, install, resolve_confirmation
from tests.fakes import (
    BLOCKED,
    HELLO,
    LEAK,
    REFUND,
    REFUND_REVIEW,
    Recorder,
    actions,
    analyses,
    make_conversation,
    observations,
    rejections,
    review_rules,
    text,
    tool_call,
    tool_calls,
)

WAITING = ConversationExecutionStatus.WAITING_FOR_CONFIRMATION
FINISHED = ConversationExecutionStatus.FINISHED


def _refund(
    tmp_path: Path, recorder: Recorder, on_review: Literal["confirm", "deny"] = "confirm"
) -> tuple[ACGSSecurityAnalyzer, BaseConversation]:
    conversation = make_conversation(
        tmp_path, recorder, [tool_calls(tool_call("issue_refund", REFUND)), text("Refunded.")]
    )
    analyzer = install(conversation, ACGSSecurityAnalyzer(constitution=review_rules(), on_review=on_review))
    conversation.send_message("refund A-17")
    conversation.run()
    assert conversation.state.execution_status == WAITING
    assert recorder.ran == []
    return analyzer, conversation


def test_allowed_call_runs_without_pausing(tmp_path: Path) -> None:
    recorder = Recorder()
    conversation = make_conversation(tmp_path, recorder, [tool_calls(tool_call("send_email", HELLO)), text("Sent.")])
    install(conversation)
    conversation.send_message("email my friend")
    conversation.run()
    assert conversation.state.execution_status == FINISHED
    assert recorder.ran == [("send_email", HELLO)]
    [analysis] = analyses(conversation)
    [risk] = analysis.risks.values()
    assert risk == SecurityRisk.LOW
    [details] = analysis.details.values()
    assert details == {"acgs_verdict": "allow", "acgs_rule_ids": [], "acgs_reason": "No blocking ACGS rule matched."}


def test_blocked_call_pauses_and_is_rejected_with_the_reason(tmp_path: Path) -> None:
    recorder = Recorder()
    conversation = make_conversation(
        tmp_path, recorder, [tool_calls(tool_call("send_email", LEAK)), text("I could not send it.")]
    )
    analyzer = install(conversation)
    conversation.send_message("email the password")
    conversation.run()

    assert conversation.state.execution_status == WAITING
    [analysis] = analyses(conversation)
    assert list(analysis.risks.values()) == [SecurityRisk.HIGH]
    [details] = analysis.details.values()
    assert details["acgs_verdict"] == "deny"
    assert details["acgs_rule_ids"] == ["ACGS-006"]

    assert resolve_confirmation(conversation, analyzer) is False
    [reason] = rejections(conversation)
    assert reason.startswith(BLOCKED)
    assert reason.endswith("OpenHands rejects every pending action in the batch, so none of them ran.")
    assert conversation.state.execution_status == ConversationExecutionStatus.IDLE

    conversation.run()
    assert conversation.state.execution_status == FINISHED
    assert recorder.ran == []
    assert observations(conversation) == []


def test_a_blocked_call_rejects_the_whole_batch(tmp_path: Path) -> None:
    recorder = Recorder()
    batch = tool_calls(tool_call("send_email", HELLO, "call_1"), tool_call("send_email", LEAK, "call_2"))
    conversation = make_conversation(tmp_path, recorder, [batch, text("ok")])
    analyzer = install(conversation)
    conversation.send_message("send both")
    conversation.run()
    assert conversation.state.execution_status == WAITING
    asked: list[Sequence[PendingAction]] = []
    assert resolve_confirmation(conversation, analyzer, asked.append) is False  # type: ignore[arg-type]
    assert asked == []
    assert len(rejections(conversation)) == 2
    conversation.run()
    assert recorder.ran == []


def test_review_runs_after_the_approver_approves(tmp_path: Path) -> None:
    recorder = Recorder()
    analyzer, conversation = _refund(tmp_path, recorder)
    seen: list[PendingAction] = []

    def approve(pending: Sequence[PendingAction]) -> bool:
        seen.extend(pending)
        return True

    assert resolve_confirmation(conversation, analyzer, approve) is True
    [item] = seen
    assert item.action.tool_name == "issue_refund"
    assert item.decision.verdict is Verdict.REVIEW
    assert item.decision.reason == REFUND_REVIEW
    conversation.run()
    assert recorder.ran == [("issue_refund", REFUND)]
    assert rejections(conversation) == []


@pytest.mark.parametrize(
    ("answer", "expected"),
    [
        (False, "ACGS: The reviewer did not approve it, so it was not executed."),
        ("yes", "ACGS: The reviewer did not approve it, so it was not executed."),
        (RuntimeError("reviewer offline"), "ACGS: The reviewer raised an error, so it was not executed."),
        (None, "ACGS: these tool calls need confirmation. No reviewer was configured, so it was not executed."),
    ],
)
def test_review_not_approved_does_not_run(tmp_path: Path, answer: object, expected: str) -> None:
    recorder = Recorder()
    analyzer, conversation = _refund(tmp_path, recorder)

    def approve(pending: Sequence[PendingAction]) -> bool:
        if isinstance(answer, Exception):
            raise answer
        return answer  # type: ignore[return-value]

    approver = None if answer is None else approve
    assert resolve_confirmation(conversation, analyzer, approver) is False
    assert rejections(conversation) == [expected]
    conversation.run()
    assert recorder.ran == []


def test_review_turned_off_is_rejected_without_asking(tmp_path: Path) -> None:
    recorder = Recorder()
    analyzer, conversation = _refund(tmp_path, recorder, on_review="deny")
    asked: list[Sequence[PendingAction]] = []
    assert resolve_confirmation(conversation, analyzer, asked.append) is False  # type: ignore[arg-type]
    assert asked == []
    assert rejections(conversation) == [
        f"Tool call 'issue_refund' was not executed. {REFUND_REVIEW} "
        "Review is turned off (on_review='deny'), so it was denied. "
        "OpenHands rejects every pending action in the batch, so none of them ran."
    ]


def test_a_stricter_policy_pauses_allowed_calls_for_the_approver(tmp_path: Path) -> None:
    recorder = Recorder()
    conversation = make_conversation(tmp_path, recorder, [tool_calls(tool_call("send_email", HELLO)), text("Sent.")])
    analyzer = install(conversation)
    conversation.set_confirmation_policy(AlwaysConfirm())
    conversation.send_message("email my friend")
    conversation.run()
    assert conversation.state.execution_status == WAITING
    verdicts: list[Verdict] = []

    def approve(pending: Sequence[PendingAction]) -> bool:
        verdicts.extend(item.decision.verdict for item in pending)
        return True

    assert resolve_confirmation(conversation, analyzer, approve) is True
    conversation.run()
    assert verdicts == [Verdict.ALLOW]
    assert recorder.ran == [("send_email", HELLO)]


def test_without_a_confirmation_policy_the_analyzer_is_only_advisory(tmp_path: Path) -> None:
    """The documented limitation: OpenHands' default NeverConfirm policy never pauses, so a HIGH risk still runs."""
    recorder = Recorder()
    conversation = make_conversation(tmp_path, recorder, [tool_calls(tool_call("send_email", LEAK)), text("Sent.")])
    conversation.set_security_analyzer(ACGSSecurityAnalyzer())
    assert isinstance(conversation.state.confirmation_policy, NeverConfirm)
    conversation.send_message("email the password")
    conversation.run()
    assert list(analyses(conversation)[0].risks.values()) == [SecurityRisk.HIGH]
    assert recorder.ran == [("send_email", LEAK)]


def test_nothing_pending_needs_no_decision(tmp_path: Path) -> None:
    conversation = make_conversation(tmp_path, Recorder(), [text("Hi.")])
    assert resolve_confirmation(conversation, ACGSSecurityAnalyzer()) is True
    assert rejections(conversation) == []


def test_install_sets_the_analyzer_and_confirm_risky(tmp_path: Path) -> None:
    conversation = make_conversation(tmp_path, Recorder(), [text("Hi.")])
    analyzer = install(conversation)
    assert conversation.state.security_analyzer is analyzer
    assert analyzer.agent_id == "openhands"
    assert analyzer.on_review == "confirm"
    policy = conversation.state.confirmation_policy
    assert isinstance(policy, ConfirmRisky)
    assert policy.threshold == SecurityRisk.HIGH
    assert policy.confirm_unknown is True


def test_an_unreadable_action_is_high_risk(tmp_path: Path) -> None:
    recorder = Recorder()
    conversation = make_conversation(tmp_path, recorder, [tool_calls(tool_call("send_email", HELLO)), text("Sent.")])
    install(conversation)
    conversation.send_message("email my friend")
    conversation.run()
    [event] = actions(conversation)
    analyzer = ACGSSecurityAnalyzer()

    raw = event.model_copy(update={"action": None})
    assert analyzer.evaluate_action(raw).verdict is Verdict.ALLOW

    unparsable = event.tool_call.model_copy(update={"arguments": "{"})
    broken = event.model_copy(update={"action": None, "tool_call": unparsable})
    decision = analyzer.evaluate_action(broken)
    assert decision.verdict is Verdict.DENY
    assert decision.reason == "ACGS governance could not evaluate this tool call, so it was denied."
    assert decision.error is not None
    analysis = analyzer.analyze_action(broken)
    assert analysis.risk == SecurityRisk.HIGH
    assert analysis.details is not None
    assert analysis.details["acgs_error"].startswith("JSONDecodeError")
    assert analyzer.security_risk(broken) == SecurityRisk.HIGH


def test_an_object_without_a_tool_name_is_denied() -> None:
    decision = ACGSSecurityAnalyzer().evaluate_action(object())  # type: ignore[arg-type]
    assert decision.verdict is Verdict.DENY
    assert decision.tool_name == "unknown"


def test_the_analyzer_round_trips_through_openhands_serialization() -> None:
    analyzer = ACGSSecurityAnalyzer(constitution=review_rules(), agent_id="payments-app", on_review="deny")
    restored = SecurityAnalyzerBase.model_validate_json(analyzer.model_dump_json())
    assert isinstance(restored, ACGSSecurityAnalyzer)
    assert restored.kind == "ACGSSecurityAnalyzer"
    assert restored.constitution.hash == analyzer.constitution.hash
    assert (restored.agent_id, restored.on_review) == ("payments-app", "deny")
    assert restored.evaluate("issue_refund", REFUND).verdict is Verdict.REVIEW


def test_a_resumed_conversation_keeps_the_analyzer_and_its_rules(tmp_path: Path) -> None:
    recorder = Recorder()
    agent = Agent(llm=TestLLM.from_messages([text("Hi.")]), tools=recorder.tools())
    store = str(tmp_path / "conversations")
    first: BaseConversation = LocalConversation(
        agent=agent, workspace=str(tmp_path), persistence_dir=store, visualizer=None
    )
    analyzer = install(first, ACGSSecurityAnalyzer(constitution=review_rules(), agent_id="payments-app"))
    resumed: BaseConversation = LocalConversation(
        agent=agent, workspace=str(tmp_path), persistence_dir=store, conversation_id=first.id, visualizer=None
    )
    restored = resumed.state.security_analyzer
    assert isinstance(restored, ACGSSecurityAnalyzer)
    assert restored is not analyzer
    assert restored.constitution.hash == analyzer.constitution.hash
    assert restored.agent_id == "payments-app"
    assert isinstance(resumed.state.confirmation_policy, ConfirmRisky)


def test_evaluate_and_options() -> None:
    analyzer = ACGSSecurityAnalyzer()
    assert analyzer.evaluate("send_email", LEAK).verdict is Verdict.DENY
    assert analyzer.evaluate("send_email", HELLO).verdict is Verdict.ALLOW
    with pytest.raises(ValueError, match="on_review"):
        ACGSSecurityAnalyzer(on_review="ask")  # type: ignore[arg-type]


def test_default_engine_keeps_no_record_of_checked_calls(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    """The README's data-handling section: argument values are not stored, echoed or logged by this package."""
    recorder = Recorder()
    conversation = make_conversation(tmp_path, recorder, [tool_calls(tool_call("send_email", LEAK)), text("ok")])
    analyzer = install(conversation, ACGSSecurityAnalyzer(agent_id="payments-app"))
    with caplog.at_level(logging.DEBUG, logger="openhands_acgs"):
        conversation.send_message("email the password")
        conversation.run()
        resolve_confirmation(conversation, analyzer)
    engine = analyzer._governor._engine
    assert engine.stats["audit_mode"] == "fast"
    assert engine.stats["audit_entry_count"] == 0
    assert engine.audit_log.entries == []
    assert "hunter2" not in str(analyses(conversation)[0].details)
    assert "hunter2" not in " ".join(rejections(conversation))
    assert "hunter2" not in "\n".join(r.getMessage() for r in caplog.records if r.name.startswith("openhands_acgs"))
