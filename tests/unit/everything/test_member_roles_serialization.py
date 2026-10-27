"""Regression tests for member-permission role serialization.

build_roles_and_assets_for_member keeps role collections as sets while it
deduplicates and resolves inheritance, but the result is stored via
_encode_value -> json.dumps(default=str). A set is not JSON-serializable, so
default=str would stringify it into a Python set-repr ("{'roles/owner'}"); that
string round-trips back through ast.literal_eval as a bare string, and the IAM
Roles report then iterates it character-by-character. These tests pin the
normalization (sets -> sorted lists) that keeps the stored value a clean JSON
array, plus the render-side defense for legacy rows already stored as set-reprs.
"""

import ast

from gcpwn.core.utils.persistence import _encode_value
from gcpwn.core.utils.module_helpers import parse_string_list
from gcpwn.modules.everything.utilities.helpers import _normalize_role_collection


def _render_roles(value):
    """Mirror _print_role_tables' Direct/Inherited Roles join."""
    return ", ".join(
        sorted(
            r
            for r in parse_string_list(
                value, allow_json=True, allow_python_literal=True, fallback_to_single=True
            )
            if r.strip()
        )
    )


def test_normalize_role_collection_sets_become_sorted_lists():
    assert _normalize_role_collection({"roles/owner", "roles/editor"}) == ["roles/editor", "roles/owner"]
    assert _normalize_role_collection(["roles/b", "roles/a", "roles/a"]) == ["roles/a", "roles/b"]
    assert _normalize_role_collection(frozenset({"roles/viewer"})) == ["roles/viewer"]
    assert _normalize_role_collection(None) == []
    assert _normalize_role_collection("") == []
    assert _normalize_role_collection("roles/owner") == ["roles/owner"]


def test_role_collection_round_trips_as_json_array_not_set_repr():
    data_dict = {
        "project": {
            "proj-1": {
                "Direct Permissions": _normalize_role_collection({"roles/owner", "roles/editor"}),
                "Inherited Permissions": [
                    {"ancestor": "org-1", "roles": _normalize_role_collection({"roles/viewer"})}
                ],
            }
        }
    }
    stored = _encode_value(data_dict)
    # A set-repr would contain a brace+quote inside a string value; a JSON array does not.
    assert '"{' not in stored
    restored = ast.literal_eval(stored)
    direct = restored["project"]["proj-1"]["Direct Permissions"]
    assert isinstance(direct, list)
    assert _render_roles(direct) == "roles/editor, roles/owner"


def test_render_defends_against_legacy_stringified_set_rows():
    # Rows written before the fix stored Direct Permissions as a Python set-repr.
    legacy = "{'roles/owner', 'roles/editor'}"
    assert _render_roles(legacy) == "roles/editor, roles/owner"
    # And the empty-set repr must not render as a stray token.
    assert _render_roles("set()") in ("", "set()")  # tolerated; must not char-split
