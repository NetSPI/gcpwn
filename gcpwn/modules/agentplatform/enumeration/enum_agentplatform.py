from __future__ import annotations

from collections import defaultdict

from gcpwn.core.action_schema import ACTION_EVIDENCE_TEST_IAM_PERMISSIONS
from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.action_recording import has_recorded_actions
from gcpwn.core.utils.service_runtime import (
    map_regions_with_disabled_short_circuit,
    parse_component_args,
    resolve_selected_components,
)
from gcpwn.modules.agentplatform.utilities.helpers import (
    AgentPlatformDatasetsResource,
    AgentPlatformEndpointsResource,
    AgentPlatformEntityTypesResource,
    AgentPlatformFeatureGroupsResource,
    AgentPlatformFeatureOnlineStoresResource,
    AgentPlatformFeatureViewsResource,
    AgentPlatformFeaturestoresResource,
    AgentPlatformModelsResource,
    AgentPlatformNotebookRuntimeTemplatesResource,
    AgentPlatformReasoningEnginesResource,
)


COMPONENTS = [
    ("datasets", "Enumerate aiplatform datasets"),
    ("endpoints", "Enumerate aiplatform endpoints"),
    ("models", "Enumerate aiplatform models"),
    ("featurestores", "Enumerate aiplatform featurestores"),
    ("entity_types", "Enumerate aiplatform entity types"),
    ("feature_groups", "Enumerate aiplatform feature groups"),
    ("feature_online_stores", "Enumerate aiplatform feature online stores"),
    ("feature_views", "Enumerate aiplatform feature views"),
    ("reasoning_engines", "Enumerate aiplatform reasoning engines"),
    ("notebook_runtime_templates", "Enumerate aiplatform notebook runtime templates"),
]


def _parse_args(user_args):
    return parse_component_args(
        user_args,
        description="Enumerate aiplatform resources (read-only)",
        components=COMPONENTS,
        standard_args=("iam", "get", "debug"),
        standard_arg_overrides={
            "iam": {"help": "Run TestIamPermissions on enumerated aiplatform resources"},
        },
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    selected = resolve_selected_components(args, [component_key for component_key, _help_text in COMPONENTS])
    project_id = session.project_id
    scope_actions = {
        "project_permissions": defaultdict(set),
        "folder_permissions": {},
        "organization_permissions": {},
    }
    api_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
    iam_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))

    try:
        datasets_resource = AgentPlatformDatasetsResource(session)
        endpoints_resource = AgentPlatformEndpointsResource(session)
        models_resource = AgentPlatformModelsResource(session)
        featurestores_resource = AgentPlatformFeaturestoresResource(session)
        entity_types_resource = AgentPlatformEntityTypesResource(session)
        feature_groups_resource = AgentPlatformFeatureGroupsResource(session)
        feature_online_stores_resource = AgentPlatformFeatureOnlineStoresResource(session)
        feature_views_resource = AgentPlatformFeatureViewsResource(session)
        reasoning_engines_resource = AgentPlatformReasoningEnginesResource(session)
        notebook_runtime_templates_resource = AgentPlatformNotebookRuntimeTemplatesResource(session)
    except RuntimeError as exc:
        print(f"[X] {exc}")
        return -1

    cached_featurestores: dict[str, list[dict]] = {}
    cached_feature_online_stores: dict[str, list[dict]] = {}

    if selected.get("datasets", False):
        all_rows = []
        dataset_locations = ["global"]
        listed_by_location = map_regions_with_disabled_short_circuit(
            dataset_locations,
            lambda location: datasets_resource.list(
                project_id=project_id,
                location=location,
                action_dict=scope_actions,
            ),
            threads=getattr(args, "threads", 3),
        )
        for location, listed in listed_by_location:
            if listed in ("Not Enabled", None):
                continue
            if not listed:
                continue
            if args.get:
                listed = [
                    datasets_resource.get(resource_id=str(row.get("name", "")).strip(), action_dict=api_actions) or row
                    for row in listed
                ]
            if args.iam:
                for row in listed:
                    name = str(row.get("name") or "").strip()
                    if name:
                        datasets_resource.test_iam_permissions(resource_id=name, action_dict=iam_actions)
            datasets_resource.save(listed, project_id=project_id, location=location)
            all_rows.extend(listed)

        if all_rows:
            UtilityTools.summary_wrapup(project_id, "AgentPlatform Datasets", all_rows, datasets_resource.COLUMNS, primary_resource="Datasets", primary_sort_key="location")
        else:
            print(f"[*] No AgentPlatform Datasets found in project {project_id}.")

    if selected.get("endpoints", False):
        all_rows = []
        endpoint_locations = ["global"]
        if args.iam:
            print("[!] Skipping aiplatform endpoint TestIamPermissions: endpoints do not support testIamPermissions.")
        listed_by_location = map_regions_with_disabled_short_circuit(
            endpoint_locations,
            lambda location: endpoints_resource.list(
                project_id=project_id,
                location=location,
                action_dict=scope_actions,
            ),
            threads=getattr(args, "threads", 3),
        )
        for location, listed in listed_by_location:
            if listed in ("Not Enabled", None):
                continue
            if listed:
                if args.get:
                    listed = [
                        endpoints_resource.get(resource_id=str(row.get("name", "")).strip(), action_dict=api_actions) or row
                        for row in listed
                    ]
                endpoints_resource.save(listed, project_id=project_id, location=location)
                all_rows.extend(listed)
        if all_rows:
            UtilityTools.summary_wrapup(
                project_id,
                "AgentPlatform Endpoints",
                all_rows,
                endpoints_resource.COLUMNS,
                primary_resource="Endpoints",
                primary_sort_key="location",
            )
        else:
            print(f"[*] No AgentPlatform Endpoints found in project {project_id}.")

    if selected.get("models", False):
        all_rows = []
        model_locations = ["global"]
        listed_by_location = map_regions_with_disabled_short_circuit(
            model_locations,
            lambda location: models_resource.list(
                project_id=project_id,
                location=location,
                action_dict=scope_actions,
            ),
            threads=getattr(args, "threads", 3),
        )
        for location, listed in listed_by_location:
            if listed in ("Not Enabled", None):
                continue
            if listed:
                if args.get:
                    listed = [
                        models_resource.get(resource_id=str(row.get("name", "")).strip(), action_dict=api_actions) or row
                        for row in listed
                    ]
                if args.iam:
                    for row in listed:
                        name = str(row.get("name") or "").strip()
                        if name:
                            models_resource.test_iam_permissions(resource_id=name, action_dict=iam_actions)
                models_resource.save(listed, project_id=project_id, location=location)
                all_rows.extend(listed)
        if all_rows:
            UtilityTools.summary_wrapup(
                project_id,
                "AgentPlatform Models",
                all_rows,
                models_resource.COLUMNS,
                primary_resource="Models",
                primary_sort_key="location",
            )
        else:
            print(f"[*] No AgentPlatform Models found in project {project_id}.")
    if selected.get("featurestores", False) or selected.get("entity_types", False):
        all_featurestores = []
        featurestore_locations = ["global"]

        for location in featurestore_locations:
            listed = featurestores_resource.list(project_id=project_id, location=location, action_dict=scope_actions)
            if listed in ("Not Enabled", None):
                continue
            if not listed:
                cached_featurestores[location] = []
                continue
            if args.get:
                listed = [
                    featurestores_resource.get(resource_id=str(row.get("name", "")).strip(), action_dict=api_actions) or row
                    for row in listed
                ]
            if args.iam:
                for row in listed:
                    name = str(row.get("name") or "").strip()
                    if name:
                        featurestores_resource.test_iam_permissions(resource_id=name, action_dict=iam_actions)
            featurestores_resource.save(listed, project_id=project_id, location=location)
            cached_featurestores[location] = listed
            all_featurestores.extend(listed)

        if selected.get("featurestores", False):
            if all_featurestores:
                UtilityTools.summary_wrapup(project_id, "AgentPlatform Featurestores", all_featurestores, featurestores_resource.COLUMNS, primary_resource="Featurestores", primary_sort_key="location")
            else:
                print(f"[*] No AgentPlatform Featurestores found in project {project_id}.")

        if selected.get("entity_types", False):
            all_entity_types = []
            for location, parent_featurestores in cached_featurestores.items():
                for featurestore_row in parent_featurestores:
                    featurestore_name = str(featurestore_row.get("name", "")).strip()
                    if not featurestore_name:
                        continue
                    listed_entity_types = entity_types_resource.list(parent=featurestore_name, action_dict=scope_actions)
                    if listed_entity_types in ("Not Enabled", None) or not listed_entity_types:
                        continue
                    if args.get:
                        listed_entity_types = [
                            entity_types_resource.get(resource_id=str(row.get("name", "")).strip(), action_dict=api_actions) or row
                            for row in listed_entity_types
                        ]
                    if args.iam:
                        for row in listed_entity_types:
                            name = str(row.get("name") or "").strip()
                            if name:
                                entity_types_resource.test_iam_permissions(resource_id=name, action_dict=iam_actions)
                    entity_types_resource.save(
                        listed_entity_types,
                        project_id=project_id,
                        featurestore_name=featurestore_name,
                        location=location,
                    )
                    all_entity_types.extend(listed_entity_types)
            if all_entity_types:
                UtilityTools.summary_wrapup(project_id, "AgentPlatform Entity Types", all_entity_types, entity_types_resource.COLUMNS, primary_resource="Entity Types", primary_sort_key="location")
            else:
                print(f"[*] No AgentPlatform Entity Types found in project {project_id}.")

    if selected.get("feature_groups", False):
        all_rows = []
        feature_group_locations = ["global"]
        listed_by_location = map_regions_with_disabled_short_circuit(
            feature_group_locations,
            lambda location: feature_groups_resource.list(
                project_id=project_id,
                location=location,
                action_dict=scope_actions,
            ),
            threads=getattr(args, "threads", 3),
        )
        for location, listed in listed_by_location:
            if listed in ("Not Enabled", None):
                continue
            if not listed:
                continue
            if args.get:
                listed = [
                    feature_groups_resource.get(resource_id=str(row.get("name", "")).strip(), action_dict=api_actions) or row
                    for row in listed
                ]
            if args.iam:
                for row in listed:
                    name = str(row.get("name") or "").strip()
                    if name:
                        feature_groups_resource.test_iam_permissions(resource_id=name, action_dict=iam_actions)
            feature_groups_resource.save(listed, project_id=project_id, location=location)
            all_rows.extend(listed)
        if all_rows:
            UtilityTools.summary_wrapup(project_id, "AgentPlatform Feature Groups", all_rows, feature_groups_resource.COLUMNS, primary_resource="Feature Groups", primary_sort_key="location")
        else:
            print(f"[*] No AgentPlatform Feature Groups found in project {project_id}.")

    if selected.get("feature_online_stores", False) or selected.get("feature_views", False):
        all_feature_online_stores: list[dict] = []
        feature_online_store_locations = ["global"]
        for location in feature_online_store_locations:
            listed = feature_online_stores_resource.list(project_id=project_id, location=location, action_dict=scope_actions)
            if listed in ("Not Enabled", None):
                continue
            if not listed:
                cached_feature_online_stores[location] = []
                continue
            if args.get:
                listed = [
                    feature_online_stores_resource.get(resource_id=str(row.get("name", "")).strip(), action_dict=api_actions) or row
                    for row in listed
                ]
            if args.iam:
                for row in listed:
                    name = str(row.get("name") or "").strip()
                    if name:
                        feature_online_stores_resource.test_iam_permissions(resource_id=name, action_dict=iam_actions)
            feature_online_stores_resource.save(listed, project_id=project_id, location=location)
            cached_feature_online_stores[location] = listed
            all_feature_online_stores.extend(listed)

        if selected.get("feature_online_stores", False):
            if all_feature_online_stores:
                UtilityTools.summary_wrapup(
                    project_id,
                    "AgentPlatform Feature Online Stores",
                    all_feature_online_stores,
                    feature_online_stores_resource.COLUMNS,
                    primary_resource="Feature Online Stores",
                    primary_sort_key="location",
                )
            else:
                print(f"[*] No AgentPlatform Feature Online Stores found in project {project_id}.")

        if selected.get("feature_views", False):
            all_feature_views = []
            for location, parent_feature_online_stores in cached_feature_online_stores.items():
                for feature_online_store_row in parent_feature_online_stores:
                    feature_online_store_name = str(feature_online_store_row.get("name", "")).strip()
                    if not feature_online_store_name:
                        continue
                    listed_feature_views = feature_views_resource.list(parent=feature_online_store_name, action_dict=api_actions)
                    if listed_feature_views in ("Not Enabled", None) or not listed_feature_views:
                        continue
                    if args.get:
                        listed_feature_views = [
                            feature_views_resource.get(resource_id=str(row.get("name", "")).strip(), action_dict=api_actions) or row
                            for row in listed_feature_views
                        ]
                    if args.iam:
                        for row in listed_feature_views:
                            name = str(row.get("name") or "").strip()
                            if name:
                                feature_views_resource.test_iam_permissions(resource_id=name, action_dict=iam_actions)
                    feature_views_resource.save(
                        listed_feature_views,
                        project_id=project_id,
                        feature_online_store_name=feature_online_store_name,
                        location=location,
                    )
                    all_feature_views.extend(listed_feature_views)
            if all_feature_views:
                UtilityTools.summary_wrapup(project_id, "AgentPlatform Feature Views", all_feature_views, feature_views_resource.COLUMNS, primary_resource="Feature Views", primary_sort_key="location")
            else:
                print(f"[*] No AgentPlatform Feature Views found in project {project_id}.")

    if selected.get("reasoning_engines", False):
        all_rows = []
        reasoning_engine_locations = ["global"]
        listed_by_location = map_regions_with_disabled_short_circuit(
            reasoning_engine_locations,
            lambda location: reasoning_engines_resource.list(
                project_id=project_id,
                location=location,
                action_dict=scope_actions,
            ),
            threads=getattr(args, "threads", 3),
        )
        for location, listed in listed_by_location:
            if listed in ("Not Enabled", None):
                continue
            if not listed:
                continue
            if args.get:
                listed = [
                    reasoning_engines_resource.get(resource_id=str(row.get("name", "")).strip(), action_dict=api_actions) or row
                    for row in listed
                ]
            if args.iam:
                for row in listed:
                    name = str(row.get("name") or "").strip()
                    if name:
                        reasoning_engines_resource.test_iam_permissions(resource_id=name, action_dict=iam_actions)
            reasoning_engines_resource.save(listed, project_id=project_id, location=location)
            all_rows.extend(listed)
        if all_rows:
            UtilityTools.summary_wrapup(project_id, "AgentPlatform Reasoning Engines", all_rows, reasoning_engines_resource.COLUMNS, primary_resource="Reasoning Engines", primary_sort_key="location")
        else:
            print(f"[*] No AgentPlatform Reasoning Engines found in project {project_id}.")

    if selected.get("notebook_runtime_templates", False):
        all_rows = []
        notebook_runtime_template_locations = ["global"]
        listed_by_location = map_regions_with_disabled_short_circuit(
            notebook_runtime_template_locations,
            lambda location: notebook_runtime_templates_resource.list(
                project_id=project_id,
                location=location,
                action_dict=scope_actions,
            ),
            threads=getattr(args, "threads", 3),
        )
        for location, listed in listed_by_location:
            if listed in ("Not Enabled", None):
                continue
            if not listed:
                continue
            if args.get:
                listed = [
                    notebook_runtime_templates_resource.get(resource_id=str(row.get("name", "")).strip(), action_dict=api_actions) or row
                    for row in listed
                ]
            if args.iam:
                for row in listed:
                    name = str(row.get("name") or "").strip()
                    if name:
                        notebook_runtime_templates_resource.test_iam_permissions(resource_id=name, action_dict=iam_actions)
            notebook_runtime_templates_resource.save(listed, project_id=project_id, location=location)
            all_rows.extend(listed)
        if all_rows:
            UtilityTools.summary_wrapup(project_id, "AgentPlatform Notebook Runtime Templates", all_rows, notebook_runtime_templates_resource.COLUMNS, primary_resource="Notebook Runtime Templates", primary_sort_key="location")
        else:
            print(f"[*] No AgentPlatform Notebook Runtime Templates found in project {project_id}.")

    if has_recorded_actions(scope_actions):
        session.insert_actions(scope_actions, project_id, column_name="agentplatform_actions_allowed")
    if has_recorded_actions(api_actions):
        session.insert_actions(api_actions, project_id, column_name="agentplatform_actions_allowed")
    if has_recorded_actions(iam_actions):
        session.insert_actions(
            iam_actions,
            project_id,
            column_name="agentplatform_actions_allowed",
            evidence_type=ACTION_EVIDENCE_TEST_IAM_PERMISSIONS,
        )

    return 1
