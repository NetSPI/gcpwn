from __future__ import annotations

import argparse

from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.enum_framework import (
    NESTED,
    PROJECT,
    Component,
    build_extra_args,
    component_args,
    make_action_accumulators,
    run_components,
)
from gcpwn.core.utils.service_runtime import parse_component_args, print_missing_dependency, resolve_selected_components
from gcpwn.modules.gcp.firestore.utilities.helpers import (
    FirestoreCollectionsResource,
    FirestoreDatabasesResource,
    FirestoreRulesResource,
)


COMPONENTS = [
    Component("databases", FirestoreDatabasesResource, "Firestore Databases", "Databases",
              help_text="Enumerate Firestore databases", scope=PROJECT, primary_sort_key="database_id",
              supports_iam=False, manual_id_arg="database_ids",
              manual_help="Firestore database IDs (e.g. `(default)` or a named ID)."),
    Component("collections", FirestoreCollectionsResource, "Firestore Collections", "Collections",
              help_text="Enumerate top-level Firestore collections", scope=NESTED, parent_key="databases",
              dependency_label="Databases", primary_sort_key="database_id",
              supports_get=False, supports_iam=False),
]

ALL_KEYS = ["databases", "rules", "collections"]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--rules", action="store_true", help="Enumerate Firestore security rules metadata")
        parser.add_argument("--download-limit", type=int, default=0, help="Limit documents downloaded per collection (0 = unlimited).")

    return parse_component_args(
        user_args,
        description="Enumerate Firestore resources (read-only)",
        components=component_args(COMPONENTS),
        add_extra_args=build_extra_args(COMPONENTS, extra=_add_extra_args),
        standard_args=("download", "get", "debug"),
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    if getattr(args, "download_limit", 0) < 0:
        UtilityTools.print_error("--download-limit must be 0 or greater.")
        return -1
    if getattr(args, "download", False):
        args.collections = True

    sel = resolve_selected_components(args, ALL_KEYS)
    for key in ALL_KEYS:
        setattr(args, key, sel[key])

    project_id = session.project_id
    db_resource = FirestoreDatabasesResource(session)

    discovered = {}
    if sel["databases"] or sel["collections"]:
        discovered = run_components(session, args, components=COMPONENTS,
                                    column_name="firestore_actions_allowed", module_name="enum_firestore")

    target_database_ids = [str(r.get("database_id") or "").strip() for r in discovered.get("databases", []) if isinstance(r, dict) and r.get("database_id")]
    if not target_database_ids and (sel["rules"] or sel["collections"]):
        target_database_ids = db_resource.resolve_cached_targets(project_id=project_id)

    if sel["rules"]:
        rules_resource = FirestoreRulesResource(session)
        scope_actions, api_actions, _iam = make_action_accumulators()
        rules_rows = rules_resource.enumerate(project_id=project_id, include_get=args.get,
                                              database_ids=target_database_ids, scope_actions=scope_actions, api_actions=api_actions)
        if rules_rows:
            rules_resource.save(rules_rows, project_id=project_id)
        UtilityTools.summary_wrapup(project_id, "Firestore Rules", rules_rows, rules_resource.COLUMNS,
                                    primary_resource="Rules", primary_sort_key="database_id")
        from gcpwn.core.utils.service_runtime import flush_actions
        flush_actions(session, project_id, "firestore_actions_allowed", (scope_actions, api_actions, _iam))

    if sel["collections"] and getattr(args, "download", False):
        if not target_database_ids:
            print_missing_dependency(component_name="Firestore collections", dependency_name="Databases",
                                     module_name="enum_firestore", manual_flags=["--database-ids", "--database-ids-file"])
        else:
            collections_resource = FirestoreCollectionsResource(session)
            for database_id in target_database_ids:
                collections_resource.download_database_documents(project_id=project_id, database_id=database_id,
                                                                 limit=args.download_limit, action_dict=None)
    return 1
