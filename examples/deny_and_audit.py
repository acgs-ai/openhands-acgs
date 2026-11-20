"""Run one allowed and one denied OpenHands tool call offline, then print the decision trail."""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Sequence

# Disable banner, telemetry and info logs before importing OpenHands; no model service is used.
os.environ["OPENHANDS_SUPPRESS_BANNER"] = "1"
os.environ["OTEL_SDK_DISABLED"] = "true"
os.environ["LOG_LEVEL"] = "WARNING"

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
from openhands.sdk.event import ActionEvent, SecurityAnalysisEvent
from openhands.sdk.llm import MessageToolCall
from openhands.sdk.testing import TestLLM
from openhands.sdk.tool import Tool, ToolExecutor, register_tool
from pydantic import Field

from openhands_acgs import ACGSSecurityAnalyzer, install, resolve_confirmation


class RecordNoteAction(Action):
    """Arguments of the local note tool."""

    body: str = Field(description="Note body")


class NoteDone(Observation):
    """Minimal observation returned after recording a note."""

    @property
    def to_llm_content(self) -> Sequence[TextContent | ImageContent]:
        return [TextContent(text="Note recorded.")]


class NoteExecutor(ToolExecutor[RecordNoteAction, NoteDone]):
    """Execute the demo note tool locally."""

    def __call__(self, action: RecordNoteAction, conversation: LocalConversation | None = None) -> NoteDone:
        print(f"Executed record_note: {action.body}")
        return NoteDone()


class RecordNoteTool(ToolDefinition[RecordNoteAction, NoteDone]):
    """OpenHands tool wrapper for ``record_note``."""

    @classmethod
    def create(cls, *args: object, **kwargs: object) -> Sequence[RecordNoteTool]:
        return [
            cls(
                description="Record a demo note.",
                action_type=RecordNoteAction,
                observation_type=NoteDone,
                executor=NoteExecutor(),
            )
        ]


def _call(call_id: str, body: str) -> Message:
    tool_call = MessageToolCall(
        id=call_id,
        name="record_note",
        arguments=json.dumps({"body": body}),
        origin="completion",
    )
    return Message(role="assistant", content=[TextContent(text="")], tool_calls=[tool_call])


def _run(conversation: BaseConversation, analyzer: ACGSSecurityAnalyzer) -> None:
    conversation.run()
    while conversation.state.execution_status == ConversationExecutionStatus.WAITING_FOR_CONFIRMATION:
        resolve_confirmation(conversation, analyzer)
        conversation.run()


def main() -> None:
    llm = TestLLM.from_messages(
        [
            _call("note-1", "The meeting starts at noon."),
            _call("note-2", "The admin password is demo-secret."),
            Message(role="assistant", content=[TextContent(text="Done.")]),
        ]
    )
    register_tool("record_note", RecordNoteTool)
    agent = Agent(llm=llm, tools=[Tool(name="record_note")])

    with tempfile.TemporaryDirectory() as workspace:
        conversation: BaseConversation = LocalConversation(
            agent=agent, workspace=workspace, persistence_dir=f"{workspace}/.conversations", visualizer=None
        )
        analyzer = install(conversation)
        conversation.send_message("Record the two notes.")
        _run(conversation, analyzer)
        tool_names = {
            event.id: event.tool_name for event in conversation.state.events if isinstance(event, ActionEvent)
        }
        decisions: list[dict[str, object]] = []
        for event in conversation.state.events:
            if isinstance(event, SecurityAnalysisEvent):
                for action_id, details in event.details.items():
                    decisions.append({"tool_name": tool_names.get(action_id, "unknown"), **details})

    print("Audit trail (application decisions):")
    for entry in decisions:
        print(json.dumps(entry, sort_keys=True))


if __name__ == "__main__":
    main()
