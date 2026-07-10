from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Iterable, List


# Placeholder-only IAM conditional support.
# TODO: Implement real CEL condition parsing/evaluation in a future pass.


@dataclass(frozen=True)
class ConditionOption:
    option_id: str
    expression: str
    narrowed_prefixes: List[str]
    narrowed_equals: List[str]
    narrowed_services: List[str]
    narrowed_resource_types: List[str]
    unresolved: bool
    filter_summary: str


class StatementConditionalsEngine:
    """
    Placeholder conditionals engine.

    For now this intentionally does not evaluate or narrow IAM conditions.
    It preserves the contract used by IAM graph builders so full evaluation can
    be introduced later without changing call sites.
    """

    def __init__(self, *, enabled: bool = True) -> None:
        self.enabled = bool(enabled)

    def evaluate_options(self, condition: Any) -> list[ConditionOption]:
        if not self.enabled or not isinstance(condition, dict):
            return [
                ConditionOption(
                    option_id="default",
                    expression="",
                    narrowed_prefixes=[],
                    narrowed_equals=[],
                    narrowed_services=[],
                    narrowed_resource_types=[],
                    unresolved=False,
                    filter_summary="",
                )
            ]

        expression = str(condition.get("expression") or "").strip()
        if not expression:
            return [
                ConditionOption(
                    option_id="default",
                    expression="",
                    narrowed_prefixes=[],
                    narrowed_equals=[],
                    narrowed_services=[],
                    narrowed_resource_types=[],
                    unresolved=False,
                    filter_summary="",
                )
            ]

        option_id = hashlib.sha1(expression.encode("utf-8"), usedforsecurity=False).hexdigest()[:8]
        return [
            ConditionOption(
                option_id=option_id,
                expression=expression,
                narrowed_prefixes=[],
                narrowed_equals=[],
                narrowed_services=[],
                narrowed_resource_types=[],
                unresolved=True,
                filter_summary="condition evaluation placeholder",
            )
        ]

    def narrow_with_option(self, resource_names: Iterable[str], option: ConditionOption | None) -> list[str]:
        _ = option
        # Placeholder behavior: no narrowing.
        return [str(name or "").strip() for name in (resource_names or []) if str(name or "").strip()]
