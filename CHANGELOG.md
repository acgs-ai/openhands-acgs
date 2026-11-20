# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). Entries for new releases are generated with `cz bump`.

## [Unreleased]

## 0.2.0 (2026-11-20)

### Added

- Offline `examples/deny_and_audit.py`: one allowed and one denied OpenHands tool call, with an application
  decision trail.
- Regression coverage for nested JSON-native arguments and bytes/bytearray formatting against acgs-lite 4.0.0.

### Changed

- Runtime support now allows `acgs-lite>=3.0.1,<5`. The locked environment resolves acgs-lite 4.0.0; the CI
  `test-min` job keeps testing the 3.0.1 floor, and default compatibility behavior is unchanged.
- Document the compatibility matrix and acgs-lite 4.x production signing and JSON-only payload requirements.

## 0.1.0 (2026-10-28)

### Added

- `ACGSSecurityAnalyzer`: an OpenHands security analyzer that rates each action against an ACGS constitution:
  `HIGH` for a blocking rule, a review-only match or any error, `LOW` otherwise. The analysis details carry the
  ACGS verdict, rule IDs and reason, never argument values. The analyzer, including its constitution, is saved and
  restored with persisted conversations.
- `install(conversation)`: sets the analyzer and a `ConfirmRisky()` policy, so `HIGH` actions pause the agent.
- `resolve_confirmation(conversation, analyzer, approve)`: rejects the pending actions when ACGS denies any of
  them, and otherwise runs them only if the approver returns `True`.
- `on_review="deny"` rejects review-only matches without asking.
- `ACGSSecurityAnalyzer.evaluate` and `evaluate_action`.
