"""Golden-output regression for the full OpenGraph pipeline.

A single comprehensive fake dataset is run through ALL four stage builders
(principals -> IAM bindings -> inferred permissions -> resource expansion) and
the emitted node/edge sets are asserted byte-for-byte against a frozen snapshot.

This is the safety net for efficiency/bloat refactors of `process_og`: any change
that adds, drops, renames, or re-targets a node or edge fails here immediately.
It deliberately exercises every major edge family at once -- identity +
group membership, Workspace super-admin impersonation, IAM bindings with
org->folder->project inheritance provenance (`#src:org:111`), roles/owner +
roles/editor collapse, SA impersonation + token-creator, SA-key-for, the
priv-esc capability hops (cloudfunction / cloudscheduler / compute startup),
and the full Workload Identity Federation chain.

If a snapshot line legitimately needs to change, regenerate by reading the
failure diff -- do NOT loosen the assertions.
"""

from __future__ import annotations

import json

from gcpwn.modules.opengraph.processing.process_og_gcpwn_data import _run_iam_bindings_stage
from gcpwn.modules.opengraph.utilities.helpers.graph.context import (
    OpenGraphBuildContext,
    OpenGraphBuildOptions,
)
from gcpwn.modules.opengraph.utilities.stage_1_principals import build_users_groups_graph
from gcpwn.modules.opengraph.utilities.stage_3_inferred_permissions import (
    build_iam_inferred_permissions_graph,
)
from gcpwn.modules.opengraph.utilities.stage_4_resource_expansion import (
    build_resource_expansion_graph,
)

from conftest import FakeSession, _policy

_SA = "serviceAccount:svc@proj-a.iam.gserviceaccount.com"


def _comprehensive_tables() -> dict[str, list[dict]]:
    return {
        "abstract_tree_hierarchy": [
            {"name": "organizations/111", "type": "organization", "display_name": "corp", "project_id": ""},
            {"name": "folders/222", "type": "folder", "display_name": "eng", "project_id": "", "parent": "organizations/111"},
            {"name": "projects/proj-a", "type": "project", "display_name": "proj-a", "project_id": "proj-a", "parent": "folders/222"},
        ],
        "iam_allow_policies": [
            {"project_id": "", "resource_type": "organization", "resource_name": "organizations/111",
             "policy": _policy(("roles/owner", ["user:alice@corp.com"]))},
            {"project_id": "proj-a", "resource_type": "project", "resource_name": "projects/proj-a",
             "policy": _policy(("roles/editor", ["group:eng@corp.com"]), ("projects/proj-a/roles/Custom", [_SA]))},
            {"project_id": "proj-a", "resource_type": "service-account", "resource_name": _SA.split(":", 1)[1],
             "policy": _policy(("roles/iam.serviceAccountTokenCreator", ["user:bob@corp.com"]))},
        ],
        "iam_roles": [
            {"name": "projects/proj-a/roles/Custom",
             "included_permissions": json.dumps(["resourcemanager.projects.setIamPolicy"])},
        ],
        "iam_service_accounts": [
            {"name": "projects/proj-a/serviceAccounts/svc@proj-a.iam.gserviceaccount.com",
             "email": "svc@proj-a.iam.gserviceaccount.com", "project_id": "proj-a"},
        ],
        "iam_sa_keys": [
            {"name": "projects/proj-a/serviceAccounts/svc@proj-a.iam.gserviceaccount.com/keys/k1"},
        ],
        "cloudcompute_instances": [
            {"name": "projects/proj-a/zones/us-central1-a/instances/vm1", "project_id": "proj-a",
             "service_account_emails": json.dumps(["svc@proj-a.iam.gserviceaccount.com"])},
        ],
        "cloudfunctions_functions": [],
        "cloudrun_services": [],
        "cloudrun_jobs": [],
        "workload_identity_pools": [
            {"name": "projects/123/locations/global/workloadIdentityPools/pool1", "pool_id": "pool1", "project_id": "proj-a"},
        ],
        "workload_identity_providers": [
            {"name": "projects/123/locations/global/workloadIdentityPools/pool1/providers/gh",
             "pool_name": "projects/123/locations/global/workloadIdentityPools/pool1", "provider_id": "gh", "project_id": "proj-a"},
        ],
        "workspace_users": [
            {"email": "admin@corp.com", "user_id": "1"},
            {"email": "alice@corp.com", "user_id": "2"},
            {"email": "bob@corp.com", "user_id": "3"},
        ],
        "workspace_groups": [{"email": "eng@corp.com", "name": "groups/eng"}],
        "workspace_group_memberships": [
            {"group_member": "group:eng@corp.com", "member": "user:alice@corp.com", "source": "x"},
        ],
        "workspace_admin_roles": [{"role_id": "RS", "is_super_admin_role": "true"}],
        "workspace_role_assignments": [{"role_id": "RS", "assigned_to": "1"}],
    }


def _build_full_graph():
    ctx = OpenGraphBuildContext(
        session=FakeSession(_comprehensive_tables()),
        options=OpenGraphBuildOptions(expand_inheritance=True, include_all=True),
    )
    build_users_groups_graph(ctx)
    _run_iam_bindings_stage(ctx)
    build_iam_inferred_permissions_graph(ctx)
    build_resource_expansion_graph(ctx)
    return ctx


def _parse(block: str, arity: int) -> set[tuple[str, ...]]:
    out: set[tuple[str, ...]] = set()
    for line in block.strip().splitlines():
        parts = tuple(line.split("\t"))
        assert len(parts) == arity, f"bad golden line: {line!r}"
        out.add(parts)
    return out


GOLDEN_NODES = """
capability:CREATE_AND_INVOKE_CLOUDFUNCTION_AS_SA@project:proj-a:hop_1	GCPIamCapability
capability:CREATE_CLOUDSCHEDULER_JOB_AS_SA@project:proj-a:hop_1	GCPIamCapability
capability:UPDATE_AND_INVOKE_CLOUDFUNCTION_AS_SA@project:proj-a:hop_1	GCPIamCapability
external_identity_source:ProviderNoCondition@projects/123/locations/global/workloadIdentityPools/pool1/providers/gh	GCPExternalIdentitySource
group:eng@corp.com	GoogleGroup
iambinding:projects/proj-a/roles/Custom@project:proj-a	GCPIamSimpleBinding
iambinding:roles/editor@project:proj-a	GCPIamSimpleBinding
iambinding:roles/iam.serviceAccountTokenCreator@service-account:svc@proj-a.iam.gserviceaccount.com	GCPIamSimpleBinding
iambinding:roles/owner@folder:222#src:org:111	GCPIamSimpleBinding
iambinding:roles/owner@org:111	GCPIamSimpleBinding
iambinding:roles/owner@project:proj-a#src:org:111	GCPIamSimpleBinding
resource:folders/222	GCPFolder
resource:organizations/111	GCPOrganization
resource:projects/123/locations/global/workloadIdentityPools/pool1	GCPWorkloadIdentityPool
resource:projects/123/locations/global/workloadIdentityPools/pool1/providers/gh	GCPWorkloadIdentityProvider
resource:projects/proj-a	GCPProject
resource:projects/proj-a/zones/us-central1-a/instances/vm1	GCPComputeInstance
serviceAccount:svc@proj-a.iam.gserviceaccount.com	GCPServiceAccount
service_account_key:projects/proj-a/serviceAccounts/svc@proj-a.iam.gserviceaccount.com/keys/k1	GCPServiceAccountKey
user:admin@corp.com	GoogleUser
user:alice@corp.com	GoogleUser
user:bob@corp.com	GoogleUser
"""

GOLDEN_EDGES = """
capability:CREATE_AND_INVOKE_CLOUDFUNCTION_AS_SA@project:proj-a:hop_1	CREATE_AND_INVOKE_CLOUDFUNCTION_AS_SA	serviceAccount:svc@proj-a.iam.gserviceaccount.com
capability:CREATE_CLOUDSCHEDULER_JOB_AS_SA@project:proj-a:hop_1	CREATE_CLOUDSCHEDULER_JOB_AS_SA	serviceAccount:svc@proj-a.iam.gserviceaccount.com
capability:UPDATE_AND_INVOKE_CLOUDFUNCTION_AS_SA@project:proj-a:hop_1	UPDATE_AND_INVOKE_CLOUDFUNCTION_AS_SA	serviceAccount:svc@proj-a.iam.gserviceaccount.com
external_identity_source:ProviderNoCondition@projects/123/locations/global/workloadIdentityPools/pool1/providers/gh	GCP_FEDERATION_POSSIBLE	resource:projects/123/locations/global/workloadIdentityPools/pool1/providers/gh
group:eng@corp.com	HAS_IAM_BINDING	iambinding:roles/editor@project:proj-a
iambinding:projects/proj-a/roles/Custom@project:proj-a	CAN_MODIFY_PROJECT_IAM	resource:projects/proj-a
iambinding:roles/editor@project:proj-a	CAN_CREATE_CLOUDSCHEDULER_JOB	capability:CREATE_CLOUDSCHEDULER_JOB_AS_SA@project:proj-a:hop_1
iambinding:roles/editor@project:proj-a	CAN_CREATE_DEPLOY_INVOKE_CLOUDFUNCTION	capability:CREATE_AND_INVOKE_CLOUDFUNCTION_AS_SA@project:proj-a:hop_1
iambinding:roles/editor@project:proj-a	CAN_UPDATE_DEPLOY_INVOKE_CLOUDFUNCTION	capability:UPDATE_AND_INVOKE_CLOUDFUNCTION_AS_SA@project:proj-a:hop_1
iambinding:roles/editor@project:proj-a	RESET_COMPUTE_STARTUP_SA	resource:projects/proj-a
iambinding:roles/editor@project:proj-a	ROLE_EDITOR	resource:projects/proj-a
iambinding:roles/editor@project:proj-a	ROLE_EDITOR	serviceAccount:svc@proj-a.iam.gserviceaccount.com
iambinding:roles/editor@project:proj-a	START_COMPUTE_STARTUP_SA	resource:projects/proj-a
iambinding:roles/iam.serviceAccountTokenCreator@service-account:svc@proj-a.iam.gserviceaccount.com	CAN_CREATE_SA_ACCESS_TOKEN	serviceAccount:svc@proj-a.iam.gserviceaccount.com
iambinding:roles/iam.serviceAccountTokenCreator@service-account:svc@proj-a.iam.gserviceaccount.com	CAN_IMPERSONATE_SA	serviceAccount:svc@proj-a.iam.gserviceaccount.com
iambinding:roles/owner@folder:222#src:org:111	ROLE_OWNER	resource:folders/222
iambinding:roles/owner@org:111	ROLE_OWNER	resource:organizations/111
iambinding:roles/owner@project:proj-a#src:org:111	CAN_CREATE_CLOUDSCHEDULER_JOB	capability:CREATE_CLOUDSCHEDULER_JOB_AS_SA@project:proj-a:hop_1
iambinding:roles/owner@project:proj-a#src:org:111	CAN_CREATE_DEPLOY_INVOKE_CLOUDFUNCTION	capability:CREATE_AND_INVOKE_CLOUDFUNCTION_AS_SA@project:proj-a:hop_1
iambinding:roles/owner@project:proj-a#src:org:111	CAN_UPDATE_DEPLOY_INVOKE_CLOUDFUNCTION	capability:UPDATE_AND_INVOKE_CLOUDFUNCTION_AS_SA@project:proj-a:hop_1
iambinding:roles/owner@project:proj-a#src:org:111	RESET_COMPUTE_STARTUP_SA	resource:projects/proj-a
iambinding:roles/owner@project:proj-a#src:org:111	ROLE_OWNER	resource:projects/proj-a
iambinding:roles/owner@project:proj-a#src:org:111	ROLE_OWNER	resource:projects/proj-a/zones/us-central1-a/instances/vm1
iambinding:roles/owner@project:proj-a#src:org:111	ROLE_OWNER	serviceAccount:svc@proj-a.iam.gserviceaccount.com
iambinding:roles/owner@project:proj-a#src:org:111	START_COMPUTE_STARTUP_SA	resource:projects/proj-a
resource:projects/123/locations/global/workloadIdentityPools/pool1/providers/gh	WIF_PROVIDER_IN_POOL	resource:projects/123/locations/global/workloadIdentityPools/pool1
resource:projects/proj-a	EXISTS_IN_PROJECT	resource:projects/123/locations/global/workloadIdentityPools/pool1
resource:projects/proj-a	EXISTS_IN_PROJECT	resource:projects/123/locations/global/workloadIdentityPools/pool1/providers/gh
resource:projects/proj-a	EXISTS_IN_PROJECT	resource:projects/proj-a/zones/us-central1-a/instances/vm1
resource:projects/proj-a	EXISTS_IN_PROJECT	serviceAccount:svc@proj-a.iam.gserviceaccount.com
resource:projects/proj-a	RESET_COMPUTE_STARTUP_SA	serviceAccount:svc@proj-a.iam.gserviceaccount.com
resource:projects/proj-a	START_COMPUTE_STARTUP_SA	serviceAccount:svc@proj-a.iam.gserviceaccount.com
serviceAccount:svc@proj-a.iam.gserviceaccount.com	HAS_IAM_BINDING	iambinding:projects/proj-a/roles/Custom@project:proj-a
service_account_key:projects/proj-a/serviceAccounts/svc@proj-a.iam.gserviceaccount.com/keys/k1	GCP_SERVICE_ACCOUNT_KEY_FOR	serviceAccount:svc@proj-a.iam.gserviceaccount.com
user:admin@corp.com	CAN_IMPERSONATE	user:alice@corp.com
user:admin@corp.com	CAN_IMPERSONATE	user:bob@corp.com
user:admin@corp.com	CAN_RESET_PASSWORD	user:alice@corp.com
user:admin@corp.com	CAN_RESET_PASSWORD	user:bob@corp.com
user:alice@corp.com	GOOGLE_MEMBER_OF	group:eng@corp.com
user:alice@corp.com	HAS_IAM_BINDING	iambinding:roles/owner@folder:222#src:org:111
user:alice@corp.com	HAS_IAM_BINDING	iambinding:roles/owner@org:111
user:alice@corp.com	HAS_IAM_BINDING	iambinding:roles/owner@project:proj-a#src:org:111
user:bob@corp.com	HAS_IAM_BINDING	iambinding:roles/iam.serviceAccountTokenCreator@service-account:svc@proj-a.iam.gserviceaccount.com
"""


def test_full_pipeline_node_set_is_golden():
    ctx = _build_full_graph()
    actual = {(n.node_id, n.node_type) for n in ctx.builder.node_map.values()}
    expected = _parse(GOLDEN_NODES, 2)
    assert actual == expected, (
        f"\nunexpected (new) nodes: {sorted(actual - expected)}"
        f"\nmissing (dropped) nodes: {sorted(expected - actual)}"
    )


def test_full_pipeline_edge_set_is_golden():
    ctx = _build_full_graph()
    actual = {(e.source_id, e.edge_type, e.destination_id) for e in ctx.builder.edge_map.values()}
    expected = _parse(GOLDEN_EDGES, 3)
    assert actual == expected, (
        f"\nunexpected (new) edges: {sorted(actual - expected)}"
        f"\nmissing (dropped) edges: {sorted(expected - actual)}"
    )
