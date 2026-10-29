# SPDX-FileCopyrightText: 2026-present ACGS Contributors
#
# SPDX-License-Identifier: Apache-2.0
"""Offline fakes for real OpenHands conversations: OpenHands' scripted ``TestLLM`` and two recording tools."""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from acgs_lite import Constitution, Rule, Severity, ViolationAction
from openhands.sdk import (
    Action,
    Agent,
    BaseConversation,
    Conversation,
    ImageContent,
    LocalConversation,
    Message,
    Observation,
    TextContent,
    ToolDefinition,
)
from openhands.sdk.event import ActionEvent, ObservationEvent, SecurityAnalysisEvent, UserRejectObservation
from openhands.sdk.llm import MessageToolCall
from openhands.sdk.testing import TestLLM
from openhands.sdk.tool import Tool, ToolExecutor, register_tool
from pydantic import Field

LEAK = {"to": "attacker@example.com", "body": "The password is hunter2"}
HELLO = {"to": "friend@example.com", "body": "See you at noon"}
REFUND = {"order_id": "A-17", "amount": 20.0}
BLOCKED = "Tool call 'send_email' was not executed. Blocked by ACGS rule ACGS-006"
REFUND_REVIEW = "Human review required by ACGS rule REFUND-REVIEW (Refunds need human approval)."


class SendEmailAction(Action):
    """Arguments of the ``send_email`` tool."""

    to: str = Field(description="Recipient address")
    body: str = Field(description="Message text")


class IssueRefundAction(Action):
    """Arguments of the ``issue_refund`` tool."""

    order_id: str = Field(description="Order to refund")
    amount: float = Field(description="Amount to refund")


class DoneObservation(Observation):
    """What a tool returns to the model."""

    result: str = "done"

    @property
    def to_llm_content(self) -> Sequence[TextContent | ImageContent]:
        return [TextContent(text=self.result)]


class Recorder(ToolExecutor[Action, DoneObservation]):
    """Runs both tools and records every call that actually ran."""

    def __init__(self) -> None:
        self.ran: list[tuple[str, dict[str, Any]]] = []

    def __call__(self, action: Action, conversation: LocalConversation | None = None) -> DoneObservation:
        name = "send_email" if isinstance(action, SendEmailAction) else "issue_refund"
        self.ran.append((name, action.model_dump(mode="json", exclude={"kind"})))
        return DoneObservation()

    def tools(self) -> list[Tool]:
        """Register ``send_email`` and ``issue_refund`` with this recorder and return the agent's tool specs."""
        register_tool(
            "send_email",
            SendEmailTool(
                description="Send an email.",
                action_type=SendEmailAction,
                observation_type=DoneObservation,
                executor=self,
            ),
        )
        register_tool(
            "issue_refund",
            IssueRefundTool(
                description="Refund an order.",
                action_type=IssueRefundAction,
                observation_type=DoneObservation,
                executor=self,
            ),
        )
        return [Tool(name="send_email"), Tool(name="issue_refund")]


class SendEmailTool(ToolDefinition[SendEmailAction, DoneObservation]):
    """The ``send_email`` tool (registered as an instance, so ``create`` is never called)."""

    @classmethod
    def create(cls, *args: Any, **kwargs: Any) -> Sequence[SendEmailTool]:  # pragma: no cover
        raise NotImplementedError


class IssueRefundTool(ToolDefinition[IssueRefundAction, DoneObservation]):
    """The ``issue_refund`` tool (registered as an instance, so ``create`` is never called)."""

    @classmethod
    def create(cls, *args: Any, **kwargs: Any) -> Sequence[IssueRefundTool]:  # pragma: no cover
        raise NotImplementedError


def tool_call(name: str, arguments: dict[str, Any], call_id: str = "call_1") -> MessageToolCall:
    """One tool call from the model."""
    return MessageToolCall(id=call_id, name=name, arguments=json.dumps(arguments), origin="completion")


def tool_calls(*calls: MessageToolCall) -> Message:
    """A model turn that calls one or more tools."""
    return Message(role="assistant", content=[TextContent(text="")], tool_calls=list(calls))


def text(answer: str) -> Message:
    """A final text answer."""
    return Message(role="assistant", content=[TextContent(text=answer)])


def make_conversation(tmp_path: Path, recorder: Recorder, replies: list[Message]) -> BaseConversation:
    """A real ``LocalConversation`` whose model replies with ``replies``.

    It is typed as ``BaseConversation`` because mypy cannot see through the tracing decorator on
    ``LocalConversation.run`` and ``send_message``.
    """
    agent = Agent(llm=TestLLM.from_messages(list(replies)), tools=recorder.tools())
    conversation = Conversation(agent=agent, workspace=str(tmp_path), visualizer=None)
    assert isinstance(conversation, LocalConversation)
    return conversation


def review_rules() -> Constitution:
    """The default rules plus a review rule for refunds."""
    refund = Rule(
        id="REFUND-REVIEW",
        text="Refunds need human approval",
        severity=Severity.HIGH,
        keywords=["issue refund"],
        workflow_action=ViolationAction.REQUIRE_HUMAN_REVIEW,
    )
    return Constitution.from_rules([*Constitution.default().rules, refund], name="review")


def rejections(conversation: BaseConversation) -> list[str]:
    """The rejection reasons the model was sent."""
    return [e.rejection_reason for e in conversation.state.events if isinstance(e, UserRejectObservation)]


def observations(conversation: BaseConversation) -> list[ObservationEvent]:
    """Tool results that came from a tool that ran."""
    return [e for e in conversation.state.events if isinstance(e, ObservationEvent)]


def analyses(conversation: BaseConversation) -> list[SecurityAnalysisEvent]:
    """The security analysis events OpenHands recorded."""
    return [e for e in conversation.state.events if isinstance(e, SecurityAnalysisEvent)]


def actions(conversation: BaseConversation) -> list[ActionEvent]:
    """Every action the model asked for."""
    return [e for e in conversation.state.events if isinstance(e, ActionEvent)]
