# SPDX-FileCopyrightText: 2026-present ACGS Contributors
#
# SPDX-License-Identifier: Apache-2.0
import openhands_acgs


def test_public_api() -> None:
    assert sorted(openhands_acgs.__all__) == sorted(
        [
            "ACGSSecurityAnalyzer",
            "Approver",
            "GovernanceDecision",
            "PendingAction",
            "Verdict",
            "format_tool_call",
            "install",
            "resolve_confirmation",
        ]
    )
    for name in openhands_acgs.__all__:
        assert getattr(openhands_acgs, name) is not None
