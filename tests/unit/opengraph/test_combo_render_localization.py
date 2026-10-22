"""A merged combo node that fans out to many target SAs must still render each path with
ONLY that path's terminal SA and the evidence relevant to it -- no cross-target leakage.

This is the readability contract for the node-wise combo merge: one combo node carries the
condensed evidence (permission_source_summary), every target SA is its own path, and the
rendered `needs:` line for a given path does not list other targets' grants.
"""

from __future__ import annotations

from gcpwn.modules.opengraph.utilities.helpers.pathfinding.model import AttackGraph
from gcpwn.modules.opengraph.utilities.helpers.pathfinding.render import render_path_expanded
from gcpwn.modules.opengraph.utilities.helpers.pathfinding.search import enumerate_paths


def _graph():
    # subject -HAS_COMBO_BINDING-> combo -CREATE_X_AS_SA-> cap -RunsAs-> {sa1, sa2}
    pss = [
        "roles/cloudbuild.builds.builder @ project:p: cloudbuild.builds.create",
        "roles/iam.serviceAccountUser @ project:p: iam.serviceAccounts.actAs",
    ]
    n = {
        "user:atk@x.com": {"id": "user:atk@x.com", "kinds": ["GoogleUser"], "kind": "GoogleUser", "properties": {}},
        "combo_iambinding@project:p#abc": {
            "id": "combo_iambinding@project:p#abc", "kinds": ["GCPIamMultiBinding"], "kind": "GCPIamMultiBinding",
            "properties": {"role_name": "combo:CREATE_CLOUDBUILD_BUILD_AS_SA", "permission_source_summary": pss},
        },
        "cap:new:cloudbuildbuild@project:p#1": {
            "id": "cap:new:cloudbuildbuild@project:p#1", "kinds": ["GCPCloudbuildbuild", "GCPResource"],
            "kind": "GCPCloudbuildbuild", "properties": {},
        },
        "serviceAccount:sa1@p.iam.gserviceaccount.com": {"id": "serviceAccount:sa1@p.iam.gserviceaccount.com", "kinds": ["GCPServiceAccount"], "kind": "GCPServiceAccount", "properties": {}},
        "serviceAccount:sa2@p.iam.gserviceaccount.com": {"id": "serviceAccount:sa2@p.iam.gserviceaccount.com", "kinds": ["GCPServiceAccount"], "kind": "GCPServiceAccount", "properties": {}},
    }
    e = [
        {"start": "user:atk@x.com", "end": "combo_iambinding@project:p#abc", "kind": "HAS_COMBO_BINDING", "properties": {}},
        {"start": "combo_iambinding@project:p#abc", "end": "cap:new:cloudbuildbuild@project:p#1", "kind": "CREATE_CLOUDBUILD_BUILD_AS_SA", "properties": {}},
        {"start": "cap:new:cloudbuildbuild@project:p#1", "end": "serviceAccount:sa1@p.iam.gserviceaccount.com", "kind": "RunsAs", "properties": {}},
        {"start": "cap:new:cloudbuildbuild@project:p#1", "end": "serviceAccount:sa2@p.iam.gserviceaccount.com", "kind": "RunsAs", "properties": {}},
    ]
    return AttackGraph(n, e)


def test_path_to_one_target_does_not_leak_other_targets():
    graph = _graph()
    paths, _ = enumerate_paths(graph, {"serviceAccount:sa1@p.iam.gserviceaccount.com"}, max_depth=6)
    assert paths, "expected a path to sa1"
    text = "\n".join(render_path_expanded(graph, paths[0]))
    # The path terminates at sa1 and never mentions the sibling target sa2.
    assert "sa1" in text
    assert "sa2" not in text
    # The combo evidence (create + actAs) is shown, localized to this path.
    assert "cloudbuild.builds.builder" in text and "iam.serviceAccountUser" in text
