"""Byte-reproducibility regression for the full OpenGraph pipeline.

The exported graph must be byte-identical regardless of the order rows arrive in
from the DB. Upstream many collections are set/dict-derived, so insertion order is
not stable run-to-run; the pipeline compensates by sorting entries before matching,
emitting events in a canonical order, keying combo nodes on their concrete scope set,
merging collapsed-edge evidence deterministically, and sorting the exported node/edge
arrays with a total-order key. This test perturbs the input row order (reverses every
table) and asserts the serialized export does not change by a single byte.

If this fails, some collection is leaking nondeterministic order into the export; fix
the ordering at its source rather than deleting this test.
"""

from __future__ import annotations

import json

from gcpwn.modules.opengraph.processing.process_og_gcpwn_data import (
    _run_iam_bindings_stage,
    export_opengraph_json,
)
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

from conftest import FakeSession
from test_pipeline_golden import _comprehensive_tables


def _export_for(tables: dict[str, list[dict]]) -> str:
    ctx = OpenGraphBuildContext(
        session=FakeSession(tables),
        options=OpenGraphBuildOptions(expand_inheritance=True, include_all=True),
    )
    build_users_groups_graph(ctx)
    _run_iam_bindings_stage(ctx)
    build_iam_inferred_permissions_graph(ctx)
    build_resource_expansion_graph(ctx)
    # Mirror run_module's finalize order: dedup collapses combo/CAP nodes (the pass whose
    # edge-redirect ordering previously raced), then the export sorts + serializes.
    ctx.builder.dedup_cap_nodes()
    payload = export_opengraph_json(
        list(ctx.builder.node_map.values()),
        list(ctx.builder.edge_map.values()),
    )
    return json.dumps(payload, ensure_ascii=False)


def _reversed_rows(tables: dict[str, list[dict]]) -> dict[str, list[dict]]:
    return {name: list(reversed(rows)) for name, rows in tables.items()}


def test_export_is_byte_identical_across_builds():
    assert _export_for(_comprehensive_tables()) == _export_for(_comprehensive_tables())


def test_export_is_byte_identical_under_input_row_reordering():
    canonical = _export_for(_comprehensive_tables())
    reordered = _export_for(_reversed_rows(_comprehensive_tables()))
    assert reordered == canonical
