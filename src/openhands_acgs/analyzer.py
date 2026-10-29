# SPDX-FileCopyrightText: 2026-present ACGS Contributors
#
# SPDX-License-Identifier: Apache-2.0
"""ACGS governance for OpenHands agents: a security analyzer plus a confirmation helper."""

from __future__ import annotations

import json
import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, Literal

from acgs_lite import Constitution
from openhands.sdk.conversation import BaseConversation
from openhands.sdk.conversation.state import ConversationState
from openhands.sdk.event import ActionEvent
from openhands.sdk.security.analyzer import SecurityAnalysis, SecurityAnalyzerBase
from openhands.sdk.security.confirmation_policy import ConfirmRisky
from openhands.sdk.security.risk import SecurityRisk
from pydantic import Field, PrivateAttr

from openhands_acgs._governance import GovernanceDecision, ToolCallGovernor, Verdict

logger = logging.getLogger(__name__)

_RISK_FOR_VERDICT = {
    Verdict.ALLOW: SecurityRisk.LOW,
    Verdict.REVIEW: SecurityRisk.HIGH,
    Verdict.DENY: SecurityRisk.HIGH,
}
_NO_REVIEWER = "No reviewer was configured, so it was not executed."
_REVIEW_DISABLED = "Review is turned off (on_review='deny'), so it was denied."
_REVIEWER_DECLINED = "The reviewer did not approve it, so it was not executed."
_REVIEWER_FAILED = "The reviewer raised an error, so it was not executed."
_BATCH_NOTE = "OpenHands rejects every pending action in the batch, so none of them ran."


@dataclass(frozen=True)
class PendingAction:
    """One action that is waiting for confirmation, with its ACGS decision."""

    action: ActionEvent
    """The OpenHands action event."""

    decision: GovernanceDecision
    """What ACGS decided for this action."""


Approver = Callable[[Sequence[PendingAction]], bool]
"""Called with every pending action when none is denied; returns ``True`` only to run them all."""


class ACGSSecurityAnalyzer(SecurityAnalyzerBase):
    """Rate each OpenHands action with an ACGS constitution.

    ``security_risk`` returns ``HIGH`` for an action that ACGS denies or wants a person to review, and for any action
    it cannot evaluate. It returns ``LOW`` otherwise. The analyzer never stops an action itself: OpenHands pauses a
    ``HIGH`` action only when the conversation's confirmation policy asks for it (``ConfirmRisky()`` does; the
    default ``NeverConfirm()`` does not). Use ``install`` to set both, and ``resolve_confirmation`` to reject what
    ACGS denies while the conversation is paused.

    The analysis details hold the verdict, the matched rule IDs and the reason, never the action's arguments.
    """

    constitution: Constitution = Field(
        default_factory=Constitution.default,
        description="The ACGS rules to apply. Defaults to the acgs-lite default constitution.",
    )
    agent_id: str = Field(default="openhands", description="The agent ID passed to the ACGS engine.")
    on_review: Literal["confirm", "deny"] = Field(
        default="confirm",
        description=(
            "'confirm' lets resolve_confirmation ask the approver about review-only matches; 'deny' rejects them."
        ),
    )

    _governor: ToolCallGovernor = PrivateAttr()

    def model_post_init(self, context: Any, /) -> None:
        """Build the ACGS engine for the configured constitution."""
        super().model_post_init(context)
        self._governor = ToolCallGovernor(self.constitution, agent_id=self.agent_id)

    def evaluate(self, tool_name: str, arguments: Any) -> GovernanceDecision:
        """Evaluate one tool call without running it. Never raises; errors give ``DENY``."""
        return self._governor.evaluate(tool_name, arguments)

    def evaluate_action(self, action: ActionEvent) -> GovernanceDecision:
        """Evaluate an OpenHands action event. Never raises; errors give ``DENY``."""
        try:
            name = str(action.tool_name)
            arguments = _arguments(action)
        except Exception as error:
            logger.warning("ACGS could not read an OpenHands action; treating it as denied", exc_info=True)
            return GovernanceDecision(
                verdict=Verdict.DENY,
                tool_name=str(getattr(action, "tool_name", "unknown")),
                reason="ACGS governance could not evaluate this tool call, so it was denied.",
                error=f"{type(error).__name__}: {error}",
            )
        return self.evaluate(name, arguments)

    def security_risk(self, action: ActionEvent) -> SecurityRisk:
        """Return ``HIGH`` for an ACGS deny or review (or any error), ``LOW`` for an allow."""
        return self.analyze_action(action).risk

    def analyze_action(self, action: ActionEvent) -> SecurityAnalysis:
        """Return the risk plus the ACGS verdict, rule IDs and reason (no argument values)."""
        decision = self.evaluate_action(action)
        details: dict[str, Any] = {
            "acgs_verdict": decision.verdict.value,
            "acgs_rule_ids": list(decision.rule_ids),
            "acgs_reason": decision.reason,
        }
        if decision.error is not None:
            details["acgs_error"] = decision.error
        return SecurityAnalysis(risk=_RISK_FOR_VERDICT[decision.verdict], details=details)


def install(conversation: BaseConversation, analyzer: ACGSSecurityAnalyzer | None = None) -> ACGSSecurityAnalyzer:
    """Set the ACGS analyzer and a ``ConfirmRisky()`` policy (pause on ``HIGH`` or ``UNKNOWN``) on a conversation.

    Args:
        conversation: The OpenHands conversation.
        analyzer: The analyzer to use. Defaults to ``ACGSSecurityAnalyzer()``.

    Returns:
        The analyzer that was set.
    """
    analyzer = analyzer if analyzer is not None else ACGSSecurityAnalyzer()
    conversation.set_security_analyzer(analyzer)
    conversation.set_confirmation_policy(ConfirmRisky(threshold=SecurityRisk.HIGH, confirm_unknown=True))
    return analyzer


def resolve_confirmation(
    conversation: BaseConversation,
    analyzer: ACGSSecurityAnalyzer,
    approve: Approver | None = None,
) -> bool:
    """Decide what to do with the actions a paused conversation is waiting on.

    Call this when ``conversation.state.execution_status`` is ``WAITING_FOR_CONFIRMATION``. Every pending action is
    evaluated again with ``analyzer``:

    - if any action is denied (or is a review-only match and ``on_review="deny"``), all pending actions are rejected
      with ``reject_pending_actions`` and the reason is sent back to the agent;
    - otherwise ``approve`` is called with all pending actions. Only a return value of ``True`` approves them. If
      there is no approver, it returns anything else, or it raises, all pending actions are rejected.

    Args:
        conversation: The paused OpenHands conversation.
        analyzer: The ACGS analyzer whose rules apply.
        approve: Optional callback that asks a person about the pending actions.

    Returns:
        ``True`` if the caller should call ``conversation.run()`` to execute the pending actions; ``False`` if they
        were rejected (calling ``run()`` again then lets the agent continue without them).
    """
    events = conversation.state.events
    unmatched = ConversationState.get_unmatched_actions(events)
    pending = [PendingAction(action, analyzer.evaluate_action(action)) for action in unmatched]
    if not pending:
        return True

    blocked = [item for item in pending if _blocks(item.decision, analyzer)]
    if blocked:
        reasons = " ".join(_blocked_reason(item.decision) for item in blocked)
        _reject(conversation, f"{reasons} {_BATCH_NOTE}")
        return False

    if approve is None:
        _reject(conversation, f"ACGS: these tool calls need confirmation. {_NO_REVIEWER}")
        return False
    try:
        approved = approve(pending) is True
    except Exception:
        logger.warning("ACGS approver raised; rejecting the pending actions", exc_info=True)
        _reject(conversation, f"ACGS: {_REVIEWER_FAILED}")
        return False
    if not approved:
        _reject(conversation, f"ACGS: {_REVIEWER_DECLINED}")
        return False
    return True


def _arguments(action: ActionEvent) -> Any:
    if action.action is not None:
        return action.action.model_dump(mode="json", exclude={"kind"})
    return json.loads(action.tool_call.arguments)


def _blocks(decision: GovernanceDecision, analyzer: ACGSSecurityAnalyzer) -> bool:
    if decision.verdict is Verdict.DENY:
        return True
    return decision.verdict is Verdict.REVIEW and analyzer.on_review == "deny"


def _blocked_reason(decision: GovernanceDecision) -> str:
    reason = f"Tool call '{decision.tool_name}' was not executed. {decision.reason}"
    if decision.verdict is Verdict.REVIEW:
        reason = f"{reason} {_REVIEW_DISABLED}"
    return reason


def _reject(conversation: BaseConversation, reason: str) -> None:
    logger.info("ACGS rejected the pending OpenHands actions")
    conversation.reject_pending_actions(reason)
