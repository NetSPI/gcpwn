from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, List


# Minimal, conservative IAM-condition (CEL) evaluation.
#
# Full CEL is a programming language; graphing only needs the resource-scoping subset that
# actually narrows which resources a grant reaches. We recognise, deterministically and with
# NO wall-clock dependency:
#   resource.name.startsWith('p') / .endsWith('s') / resource.name == 'x'
#   resource.type == 'svc/Type' / resource.type.startsWith('svc/')
# request.time / expiry predicates are recognised but intentionally do NOT narrow (evaluating
# them against "now" would make the graph non-reproducible), so a purely time-bound grant is
# left at full scope.
#
# CONSERVATIVE by design: we only narrow when the whole expression is a disjunction (||) of
# recognised predicates. Anything containing && , negation, or an unrecognised term leaves the
# option unresolved and un-narrowed, so a half-understood condition never DROPS a real edge
# (false negatives in a defensive tool are worse than an over-broad edge). All narrowing is
# gated behind --cond-eval (engine disabled by default), so default builds are unchanged.


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
    narrowed_suffixes: List[str] = field(default_factory=list)


_RE_STARTSWITH = re.compile(r"resource\.name\.startsWith\(\s*['\"]([^'\"]+)['\"]\s*\)")
_RE_ENDSWITH = re.compile(r"resource\.name\.endsWith\(\s*['\"]([^'\"]+)['\"]\s*\)")
_RE_NAME_EQ = re.compile(r"resource\.name\s*==\s*['\"]([^'\"]+)['\"]")
_RE_TYPE_EQ = re.compile(r"resource\.type\s*==\s*['\"]([^'\"]+)['\"]")
_RE_TYPE_STARTS = re.compile(r"resource\.type\.startsWith\(\s*['\"]([^'\"]+)['\"]\s*\)")
# Time / expiry predicates: recognised (so they don't force "unresolved") but non-narrowing.
_RE_TIME = re.compile(r"request\.time\s*[<>]=?\s*timestamp\(\s*['\"][^'\"]+['\"]\s*\)")


def _default_option() -> ConditionOption:
    return ConditionOption(
        option_id="default",
        expression="",
        narrowed_prefixes=[],
        narrowed_equals=[],
        narrowed_services=[],
        narrowed_resource_types=[],
        unresolved=False,
        filter_summary="",
        narrowed_suffixes=[],
    )


def _sorted_unique(values: Iterable[str]) -> list[str]:
    return sorted({str(v).strip() for v in values if str(v).strip()})


class StatementConditionalsEngine:
    """Conservative CEL-subset conditionals engine (see module docstring)."""

    def __init__(self, *, enabled: bool = True) -> None:
        self.enabled = bool(enabled)

    def evaluate_options(self, condition: Any) -> list[ConditionOption]:
        if not self.enabled or not isinstance(condition, dict):
            return [_default_option()]
        expression = str(condition.get("expression") or "").strip()
        if not expression:
            return [_default_option()]

        option_id = hashlib.sha1(expression.encode("utf-8"), usedforsecurity=False).hexdigest()[:8]

        prefixes = _sorted_unique(_RE_STARTSWITH.findall(expression))
        suffixes = _sorted_unique(_RE_ENDSWITH.findall(expression))
        equals = _sorted_unique(_RE_NAME_EQ.findall(expression))
        resource_types = _sorted_unique(
            list(_RE_TYPE_EQ.findall(expression)) + list(_RE_TYPE_STARTS.findall(expression))
        )

        # Residue test: strip every recognised predicate (and time predicates) plus the
        # disjunction scaffolding (|| , parens, whitespace). If anything is left -- &&, a
        # negation, a comparison we don't model, another variable -- we did NOT fully
        # understand the expression and must not narrow.
        residue = expression
        for pattern in (_RE_STARTSWITH, _RE_ENDSWITH, _RE_NAME_EQ, _RE_TYPE_EQ, _RE_TYPE_STARTS, _RE_TIME):
            residue = pattern.sub("", residue)
        residue = re.sub(r"[\s()]|\|\|", "", residue)
        fully_understood = residue == ""

        if not fully_understood:
            return [
                ConditionOption(
                    option_id=option_id,
                    expression=expression,
                    narrowed_prefixes=[],
                    narrowed_equals=[],
                    narrowed_services=[],
                    narrowed_resource_types=[],
                    unresolved=True,
                    filter_summary="unparsed condition (not narrowed; edge kept at full scope)",
                    narrowed_suffixes=[],
                )
            ]

        summary_bits = []
        if prefixes:
            summary_bits.append(f"name startsWith {prefixes}")
        if suffixes:
            summary_bits.append(f"name endsWith {suffixes}")
        if equals:
            summary_bits.append(f"name == {equals}")
        if resource_types:
            summary_bits.append(f"type in {resource_types}")
        if _RE_TIME.search(expression):
            summary_bits.append("time-bound (not evaluated)")
        return [
            ConditionOption(
                option_id=option_id,
                expression=expression,
                narrowed_prefixes=prefixes,
                narrowed_equals=equals,
                narrowed_services=[],
                narrowed_resource_types=resource_types,
                unresolved=False,
                filter_summary="; ".join(summary_bits),
                narrowed_suffixes=suffixes,
            )
        ]

    def narrow_with_option(self, resource_names: Iterable[str], option: ConditionOption | None) -> list[str]:
        names = [str(name or "").strip() for name in (resource_names or []) if str(name or "").strip()]
        if option is None or option.unresolved:
            return names
        prefixes = tuple(option.narrowed_prefixes or ())
        suffixes = tuple(option.narrowed_suffixes or ())
        equals = set(option.narrowed_equals or ())
        if not (prefixes or suffixes or equals):
            # No resource.name predicate (e.g. type-only or purely time-bound): don't narrow
            # by name. Any resource.type narrowing is applied by the matcher via
            # condition_resource_types, not here.
            return names

        def _matches(name: str) -> bool:
            # Match the scope name against the predicate(s). A scope passes if it satisfies ANY
            # recognised predicate (the expression is a disjunction). Full-name comparison keeps
            # this predictable; a CEL resource.name and the stored scope are both resource paths.
            if name in equals:
                return True
            if prefixes and name.startswith(prefixes):
                return True
            if suffixes and name.endswith(suffixes):
                return True
            return False

        kept = [name for name in names if _matches(name)]
        # Only narrow to a non-empty PROPER subset. If NONE of the binding's own scopes match,
        # the condition almost certainly targets child resources the binding reaches but that
        # are not in this scope set (e.g. a project-level grant conditioned on bucket names) --
        # narrowing to empty there would drop a real edge (false negative). Keep the original
        # scopes in that case: an over-broad edge is safer than a missed path for a defensive
        # tool, and matches the "never narrow on a half-understood condition" contract.
        return kept if kept else names
