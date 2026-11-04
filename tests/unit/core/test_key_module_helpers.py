from __future__ import annotations

from gcpwn.core.utils.module_helpers import (
    bigquery_table_iam_resource_name,
    extract_location_from_resource_name,
    extract_project_id_from_resource,
    name_from_input,
    normalize_service_account_resource_name,
    split_bigquery_table_id,
)


def test_key_module_helpers_service_account_normalization() -> None:
    assert normalize_service_account_resource_name("bot@example.iam.gserviceaccount.com") == (
        "projects/-/serviceAccounts/bot@example.iam.gserviceaccount.com"
    )
    assert normalize_service_account_resource_name("serviceAccount:bot@example.iam.gserviceaccount.com") == (
        "projects/-/serviceAccounts/bot@example.iam.gserviceaccount.com"
    )
    assert normalize_service_account_resource_name(
        "projects/demo-project/serviceAccounts/bot@example.iam.gserviceaccount.com"
    ) == "projects/demo-project/serviceAccounts/bot@example.iam.gserviceaccount.com"


def test_key_module_helpers_project_and_location_extraction() -> None:
    resource_name = "projects/demo-project/zones/us-central1-a/instances/vm-1"
    assert extract_project_id_from_resource(resource_name) == "demo-project"
    assert extract_location_from_resource_name(resource_name, include_zones=True) == "us-central1-a"
    # Without include_zones, the zone is not surfaced (only /locations/ segments are)
    assert extract_location_from_resource_name(resource_name, include_zones=False) == ""


def test_key_module_helpers_location_segment_always_returned() -> None:
    # Resources using /locations/ are returned regardless of include_zones
    name = "projects/demo-project/locations/us-central1/services/my-service"
    assert extract_location_from_resource_name(name, include_zones=True) == "us-central1"
    assert extract_location_from_resource_name(name, include_zones=False) == "us-central1"


def test_key_module_helpers_bigquery_table_parsing() -> None:
    project_id, dataset_id, table_id = split_bigquery_table_id("demo-project:analytics.events")
    assert project_id == "demo-project"
    assert dataset_id == "analytics"
    assert table_id == "events"
    assert bigquery_table_iam_resource_name("demo-project:analytics.events") == (
        "projects/demo-project/datasets/analytics/tables/events"
    )


def test_key_module_helpers_name_from_input_template() -> None:
    built = name_from_input(
        "us-central1/my-function",
        project_id="demo-project",
        template=("projects/{project_id}", "locations", 0, "functions", 1),
    )
    assert built == "projects/demo-project/locations/us-central1/functions/my-function"

    passthrough = name_from_input(
        "projects/demo-project/locations/us-central1/functions/my-function",
        project_id="ignored",
        template=("projects/{project_id}", "locations", 0, "functions", 1),
    )
    assert passthrough == "projects/demo-project/locations/us-central1/functions/my-function"
