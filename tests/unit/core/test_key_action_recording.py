from __future__ import annotations

from gcpwn.core.utils.action_recording import has_recorded_actions, record_permissions


def test_key_action_recording_records_scope_permissions() -> None:
    action_dict: dict = {}

    record_permissions(
        action_dict,
        permissions=["resourcemanager.projects.getIamPolicy", "resourcemanager.projects.getIamPolicy"],
        scope_key="project_actions_allowed",
        scope_label="demo-project",
    )

    assert action_dict == {
        "project_actions_allowed": {
            "demo-project": {"resourcemanager.projects.getIamPolicy"}
        }
    }


def test_key_action_recording_records_resource_permissions() -> None:
    action_dict: dict = {}

    record_permissions(
        action_dict,
        permissions="cloudtasks.queues.setIamPolicy",
        project_id="demo-project",
        resource_type="queues",
        resource_label="projects/demo-project/locations/us-central1/queues/my-queue",
    )

    assert action_dict["demo-project"]["cloudtasks.queues.setIamPolicy"]["queues"] == {
        "projects/demo-project/locations/us-central1/queues/my-queue"
    }


def test_key_action_recording_has_recorded_actions() -> None:
    action_dict = {
        "demo-project": {
            "cloudtasks.queues.setIamPolicy": {
                "queues": {"projects/demo-project/locations/us-central1/queues/my-queue"}
            }
        }
    }
    assert has_recorded_actions(action_dict) is True
