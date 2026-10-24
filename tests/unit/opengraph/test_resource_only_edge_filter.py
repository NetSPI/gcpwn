"""Unit tests for the default resource-only edge filter (process_og Phase 3.4).

Covers both classes it hides by default:
  (a) resource setIamPolicy edges (CAN_MODIFY_BUCKET_IAM etc.), by edge KIND; and
  (b) ROLE_OWNER/ROLE_EDITOR fan-out to non-identity resources, by destination node TYPE
      (owner/editor -> SA and -> org/folder/project are PE and must stay).
"""

from __future__ import annotations

from gcpwn.modules.opengraph.processing.process_og_gcpwn_data import _filter_resource_only_edges
from gcpwn.modules.opengraph.utilities.helpers.graph.core_helpers import OpenGraphBuilder


def _graph():
    b = OpenGraphBuilder()
    # nodes
    b.add_node("user:eve@x.com", "GoogleUser")
    b.add_node("serviceAccount:svc@p.iam.gserviceaccount.com", "GCPServiceAccount")
    b.add_node("resource:proj-a@proj-a", "GCPProject")
    b.add_node("resource:111", "GCPOrganization")
    b.add_node("resource:vm1@proj-a", "GCPComputeInstance")
    b.add_node("resource:b1@proj-a", "GCPBucket")
    b.add_node("iambinding:roles/owner@project:proj-a", "GCPIamSimpleBinding")
    b.add_node("iambinding:custom@project:proj-a", "GCPIamSimpleBinding")
    # owner fan-out: SA + project + org (KEEP) and vm + bucket (DROP)
    b.add_edge("iambinding:roles/owner@project:proj-a", "serviceAccount:svc@p.iam.gserviceaccount.com", "ROLE_OWNER")
    b.add_edge("iambinding:roles/owner@project:proj-a", "resource:proj-a@proj-a", "ROLE_OWNER")
    b.add_edge("iambinding:roles/owner@project:proj-a", "resource:111", "ROLE_EDITOR")
    b.add_edge("iambinding:roles/owner@project:proj-a", "resource:vm1@proj-a", "ROLE_OWNER")
    b.add_edge("iambinding:roles/owner@project:proj-a", "resource:b1@proj-a", "ROLE_EDITOR")
    # resource setIamPolicy edge (DROP by kind) + a kept scope setIamPolicy (KEEP)
    b.add_edge("iambinding:custom@project:proj-a", "resource:b1@proj-a", "CAN_MODIFY_BUCKET_IAM")
    b.add_edge("iambinding:custom@project:proj-a", "resource:proj-a@proj-a", "CAN_MODIFY_PROJECT_IAM")
    return b


def _kinds_to(b):
    return {(k[1], k[2]) for k in b.edge_map}


def test_filter_drops_resource_only_edges_keeps_pe():
    b = _graph()
    removed = _filter_resource_only_edges(b)
    kinds = _kinds_to(b)
    # dropped: owner->vm, owner/editor->bucket, CAN_MODIFY_BUCKET_IAM
    assert removed == 3, f"expected 3 removed, got {removed}"
    assert ("ROLE_OWNER", "resource:vm1@proj-a") not in kinds
    assert ("ROLE_EDITOR", "resource:b1@proj-a") not in kinds
    assert ("CAN_MODIFY_BUCKET_IAM", "resource:b1@proj-a") not in kinds
    # kept: owner->SA, owner->project, editor->org, CAN_MODIFY_PROJECT_IAM
    assert ("ROLE_OWNER", "serviceAccount:svc@p.iam.gserviceaccount.com") in kinds
    assert ("ROLE_OWNER", "resource:proj-a@proj-a") in kinds
    assert ("ROLE_EDITOR", "resource:111") in kinds
    assert ("CAN_MODIFY_PROJECT_IAM", "resource:proj-a@proj-a") in kinds


def test_filter_is_idempotent():
    b = _graph()
    _filter_resource_only_edges(b)
    assert _filter_resource_only_edges(b) == 0
