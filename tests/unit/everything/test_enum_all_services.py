"""Byte-exact coverage for the declarative ``_SERVICES`` table that replaced the
29 hand-written per-service dispatch blocks in ``enum_all.run_module``.

We never import a real GCP client or run ``run_module`` end to end. Instead we
drive the two pure helpers that build the per-service sub-call argv:

  * ``_build_service_args(spec, args, download_requested)`` -> ``list[str]``
  * ``_service_selected(spec, args, every_flag_missing)`` -> ``bool``

``args`` is a plain ``SimpleNamespace`` and ``download_requested`` is a closure
over a fixed token set -- mirroring the real ``_download_requested`` closure in
``run_module`` but with no argparse / session involved. The point is to lock the
exact argv each service emits across every flag combination so a future edit to
a ``ServiceSpec`` row can't silently change what a sub-module receives.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from gcpwn.modules.everything.enumeration import enum_all
from gcpwn.modules.everything.enumeration.enum_all import (
    _SERVICES,
    ServiceSpec,
    _build_service_args,
    _service_selected,
)


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #
def _args(**overrides):
    """An args namespace with the full set of attributes ``_build_service_args``
    and ``_service_selected`` touch. Defaults are 'nothing requested'."""
    base = {
        "debug": False,
        "threads": 4,
        "zones_list": None,
        "regions_list": None,
        "get": False,
        "iam": False,
        "download_output": None,
    }
    # Every gate flag referenced across the spec table defaults to False so a
    # SimpleNamespace never trips _service_selected's getattr fallback.
    for spec in _SERVICES:
        for flag in spec.gate_flags:
            base.setdefault(flag, False)
    base.update(overrides)
    return SimpleNamespace(**base)


def _downloader(*active_tokens):
    """Build a ``download_requested(*tokens)`` stub returning True iff any passed
    token is in the active set -- matching ``run_module._download_requested``."""
    active = set(active_tokens)

    def download_requested(*tokens):
        return any(str(t).strip() in active for t in tokens)

    return download_requested


_NO_DOWNLOAD = _downloader()  # download disabled: every probe is False


def _spec_by_module_tail(tail: str) -> ServiceSpec:
    for spec in _SERVICES:
        if spec.module.split(".")[-1] == tail:
            return spec
    raise KeyError(tail)


# --------------------------------------------------------------------------- #
# Table-shape sanity: every spec builds without error, for all gate flags      #
# --------------------------------------------------------------------------- #
def test_services_table_is_non_empty_and_specs_are_frozen():
    assert len(_SERVICES) == 43  # gameservers removed (gameservices API retired by Google + client broken on py3.12+)
    for spec in _SERVICES:
        assert isinstance(spec, ServiceSpec)
        assert spec.module.startswith("gcpwn.modules.")
        assert spec.gate_flags, "every spec must declare at least one gate flag"
        with pytest.raises(Exception):
            spec.gate_flags = ()  # frozen dataclass -> immutable


def test_every_spec_builds_without_error_minimal():
    args = _args()
    for spec in _SERVICES:
        out = _build_service_args(spec, args, _NO_DOWNLOAD)
        assert isinstance(out, list)
        assert all(isinstance(tok, str) for tok in out)


def test_every_spec_builds_without_error_maximal():
    # debug + get + iam + zones + regions + every download token active.
    args = _args(
        debug=True,
        get=True,
        iam=True,
        zones_list="z1,z2",
        regions_list="r1,r2",
        download_output="/out",
    )
    downloader = _downloader(*enum_all.ALL_DOWNLOAD_TOKENS)
    for spec in _SERVICES:
        out = _build_service_args(spec, args, downloader)
        assert isinstance(out, list)
        assert all(isinstance(tok, str) for tok in out)


# --------------------------------------------------------------------------- #
# Byte-exact representative cases                                              #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "args_kwargs, tokens, expected",
    [
        # richest spec: threads + zones + regions + get + iam + all 3 download rules + one --output
        (dict(debug=True, threads=8, zones_list="us-central1-a", regions_list="us-central1",
              get=True, iam=True, download_output="/tmp/out"),
         ("compute_screenshot", "compute_serial", "compute_artifacts"),
         ["-v", "--threads", "8", "--zones-list", "us-central1-a", "--regions-list", "us-central1",
          "--get", "--iam", "--take-screenshot", "--download-serial", "--download", "--output", "/tmp/out"]),
        # only the screenshot rule fires; --output still appends exactly once
        (dict(threads=4, download_output="/d"), ("compute_screenshot",),
         ["--threads", "4", "--take-screenshot", "--output", "/d"]),
        # any_download True but download_output None -> no --output tail
        (dict(threads=4, download_output=None), ("compute_artifacts",),
         ["--threads", "4", "--download"]),
        # nothing fired -> no --output even though download_output is set
        (dict(threads=2, download_output="/d"), (),
         ["--threads", "2"]),
    ],
    ids=["full-blast", "only-screenshot", "download-no-output-dir", "no-downloads"],
)
def test_compute_resources_arg_building(args_kwargs, tokens, expected):
    spec = _spec_by_module_tail("enum_cloudcompute_resources")
    out = _build_service_args(spec, _args(**args_kwargs), _downloader(*tokens))
    assert out == expected


@pytest.mark.parametrize(
    "tokens, expected",
    [
        (("buckets",), ["--iam", "--download", "--output", "/bkt"]),
        ((), ["--iam"]),  # download disabled -> no --download/--output
    ],
    ids=["download", "no-download"],
)
def test_storage_arg_building(tokens, expected):
    spec = _spec_by_module_tail("enum_cloudstorage")
    out = _build_service_args(spec, _args(iam=True, download_output="/bkt"), _downloader(*tokens))
    assert out == expected


def test_bigquery_download_emits_table_subtoken_and_no_output():
    """BigQuery's download rule is the multi-token ('--download', 'table'); the
    spec has no download_output so --output is never appended even with a dir."""
    spec = _spec_by_module_tail("enum_bigquery")
    args = _args(download_output="/ignored")
    out = _build_service_args(spec, args, _downloader("bigquery_tables"))
    assert out == ["--download", "table"]
    assert "--output" not in out


def test_secrets_download_emits_values_subtoken():
    spec = _spec_by_module_tail("enum_secretsmanager")
    args = _args(iam=True, download_output="/x")
    out = _build_service_args(spec, args, _downloader("secrets"))
    # secrets spec has no download_output -> --output absent despite the dir.
    assert out == ["--iam", "--download", "--values"]


@pytest.mark.parametrize(
    "args_kwargs, tokens, expected",
    [
        # function_env is a get_token: forces --get, but is NOT a download rule
        (dict(threads=3, regions_list="r1", download_output="/f"), ("function_env",),
         ["--threads", "3", "--regions-list", "r1", "--get"]),
        # function_source is a download rule -> --download + --output
        (dict(threads=4, regions_list="r1", download_output="/f"), ("function_source",),
         ["--threads", "4", "--regions-list", "r1", "--download", "--output", "/f"]),
        # both: --get (from env) precedes the download flags (from source)
        (dict(regions_list="r1", download_output="/f"), ("function_env", "function_source"),
         ["--threads", "4", "--regions-list", "r1", "--get", "--download", "--output", "/f"]),
    ],
    ids=["env-token-get-only", "source-token-download", "env-and-source"],
)
def test_functions_arg_building(args_kwargs, tokens, expected):
    spec = _spec_by_module_tail("enum_cloudfunctions")
    out = _build_service_args(spec, _args(**args_kwargs), _downloader(*tokens))
    assert out == expected


@pytest.mark.parametrize(
    "args_kwargs, expected",
    [
        # extra_args (component flags) come right after -v (debug) and before --iam
        (dict(debug=True, iam=True),
         ["-v", "--service-accounts", "--custom-roles", "--pools", "--providers", "--iam"]),
        (dict(),
         ["--service-accounts", "--custom-roles", "--pools", "--providers"]),
    ],
    ids=["with-debug-and-iam", "plain"],
)
def test_iam_extra_args_building(args_kwargs, expected):
    spec = _spec_by_module_tail("enum_iam")
    out = _build_service_args(spec, _args(**args_kwargs), _NO_DOWNLOAD)
    assert out == expected


def test_dns_download_no_output_dir_spec():
    spec = _spec_by_module_tail("enum_clouddns")
    args = _args(download_output="/x")
    out = _build_service_args(spec, args, _downloader("clouddns_record_sets"))
    # clouddns has no download_output flag -> never appends --output.
    assert out == ["--download"]


def test_kms_threads_and_regions_no_iam_no_get():
    """KMS sets threads+regions but not iam; --get is gated on args.get only."""
    spec = _spec_by_module_tail("enum_kms")
    args = _args(threads=6, regions_list="europe-west1", iam=True, get=True)
    out = _build_service_args(spec, args, _NO_DOWNLOAD)
    # iam=True but spec.iam is False -> no --iam. get=True and spec.get default
    # True -> --get is emitted.
    assert out == ["--threads", "6", "--regions-list", "europe-west1", "--get"]


def test_tasks_full_with_download_output():
    spec = _spec_by_module_tail("enum_cloudtasks")
    args = _args(threads=4, regions_list="r1", iam=True, get=True, download_output="/t")
    out = _build_service_args(spec, args, _downloader("cloudtasks_requests"))
    assert out == [
        "--threads",
        "4",
        "--regions-list",
        "r1",
        "--get",
        "--iam",
        "--download",
        "--output",
        "/t",
    ]


@pytest.mark.parametrize(
    "args_kwargs, expected",
    [
        (dict(), []),                 # plain spec, get off -> nothing
        (dict(get=True), ["--get"]),  # get on -> --get only
    ],
    ids=["minimal", "get-only"],
)
def test_bigtable_arg_building(args_kwargs, expected):
    spec = _spec_by_module_tail("enum_bigtable")
    out = _build_service_args(spec, _args(**args_kwargs), _NO_DOWNLOAD)
    assert out == expected


# --------------------------------------------------------------------------- #
# Conditional emission: zones/regions only when both spec-enabled AND arg set   #
# --------------------------------------------------------------------------- #
def test_zones_skipped_when_spec_disabled():
    # cloud_storage has zones=False; passing zones_list must not add it.
    spec = _spec_by_module_tail("enum_cloudstorage")
    out = _build_service_args(spec, _args(zones_list="z1", regions_list="r1"), _NO_DOWNLOAD)
    assert "--zones-list" not in out
    assert "--regions-list" not in out  # storage has regions=False too


def test_regions_present_only_for_region_specs_when_arg_set():
    spec = _spec_by_module_tail("enum_kms")  # threads=True, regions=True, zones=False
    out = _build_service_args(spec, _args(threads=4, regions_list="r1", zones_list="z1"), _NO_DOWNLOAD)
    # zones suppressed (spec.zones False); threads always present (spec.threads True).
    assert out == ["--threads", "4", "--regions-list", "r1"]


def test_region_spec_omits_regions_when_arg_unset():
    spec = _spec_by_module_tail("enum_kms")
    out = _build_service_args(spec, _args(threads=4, regions_list=None), _NO_DOWNLOAD)
    # threads always present; regions omitted because the arg is unset.
    assert out == ["--threads", "4"]


def test_threads_uses_arg_value_stringified():
    spec = _spec_by_module_tail("enum_gke")  # threads=True
    out = _build_service_args(spec, _args(threads=12), _NO_DOWNLOAD)
    assert out == ["--threads", "12"]
    assert out[1] == "12" and isinstance(out[1], str)


# --------------------------------------------------------------------------- #
# download disabled vs requested: the closure governs every probe              #
# --------------------------------------------------------------------------- #
def test_disabled_download_closure_suppresses_all_download_flags():
    args = _args(download_output="/out")
    for spec in _SERVICES:
        out = _build_service_args(spec, args, _NO_DOWNLOAD)
        assert "--download" not in out
        assert "--take-screenshot" not in out
        assert "--download-serial" not in out
        assert "--output" not in out


def test_output_appended_at_most_once_even_with_multiple_download_rules():
    spec = _spec_by_module_tail("enum_cloudcompute_resources")
    args = _args(download_output="/d")
    out = _build_service_args(
        spec, args, _downloader("compute_screenshot", "compute_serial", "compute_artifacts")
    )
    assert out.count("--output") == 1
    assert out.count("/d") == 1


def test_output_only_for_specs_with_download_output_true():
    """Cross-check: among specs with a download rule, only those with
    download_output=True ever emit --output."""
    args = _args(download_output="/o")
    downloader = _downloader(*enum_all.ALL_DOWNLOAD_TOKENS)
    has_output = {"enum_cloudcompute_resources", "enum_cloudfunctions", "enum_cloudstorage", "enum_cloudtasks"}
    for spec in _SERVICES:
        tail = spec.module.split(".")[-1]
        out = _build_service_args(spec, args, downloader)
        if "--output" in out:
            assert tail in has_output, f"{tail} unexpectedly emitted --output"
        elif tail in has_output and spec.downloads:
            # these specs SHOULD emit --output when a download fires
            assert "--output" in out, f"{tail} expected --output"


# --------------------------------------------------------------------------- #
# _service_selected                                                           #
# --------------------------------------------------------------------------- #
def test_run_module_parser_defines_every_service_flag():
    # Regression: every service in _SERVICES must be wired into the run_module parser
    # (the sequential path). The legacy --<flag> flags are now built by a loop over
    # _PARALLEL_SERVICES (hidden from --help), so assert each service's gate key is
    # covered there (or is the compute umbrella) -- a missing one makes `enum_all
    # --<flag>` hard-fail with 'unrecognized arguments'.
    from gcpwn.modules.everything.enumeration.enum_all import _PARALLEL_SERVICES

    parallel_keys = {key for key, _flag in _PARALLEL_SERVICES}
    for spec in _SERVICES:
        key = spec.gate_flags[0]
        assert key in parallel_keys or key == "cloud_compute", (
            f"service {spec.module} gate key {key!r} is not wired via _PARALLEL_SERVICES"
        )


def test_every_service_flag_resolves_as_a_modules_token():
    # Each service's legacy flag name must also work as a --modules token (so
    # `--modules cloud-storage` == `--cloud-storage`), plus the friendly aliases.
    from gcpwn.modules.everything.enumeration.enum_all import (
        _MODULE_TOKEN_MAP,
        _norm_token,
        _resolve_module_tokens,
    )

    for spec in _SERVICES:
        key = spec.gate_flags[0]
        assert _norm_token(key.replace("_", "-")) in _MODULE_TOKEN_MAP, f"{key} not a --modules token"
    # a mixed comma/space batch resolves; unknown tokens are reported
    keys, unknown = _resolve_module_tokens([["storage,iam", "gke"], ["bq"]])
    assert keys == {"cloud_storage", "cloud_iam", "gke", "cloud_bigquery"}
    assert not unknown
    keys, unknown = _resolve_module_tokens([["storage", "definitely_not_a_service"]])
    assert unknown == ["definitely_not_a_service"] and keys == {"cloud_storage"}


def test_workspace_identity_is_seeded_and_selectable():
    # Regression: workspace_identity must be a seeded gate key (so args.workspace_identity
    # exists for the every_flag_missing/planning blocks -- otherwise every `modules run
    # enum_all` AttributeErrors) AND reachable via --modules now that there is no
    # --workspace-cloud-identity flag.
    from gcpwn.modules.everything.enumeration.enum_all import (
        _ALL_GATE_KEYS,
        _MODULE_TOKEN_MAP,
        _norm_token,
    )

    assert "workspace_identity" in _ALL_GATE_KEYS
    assert _MODULE_TOKEN_MAP[_norm_token("workspace")] == "workspace_identity"


def test_service_selected_true_when_every_flag_missing():
    for spec in _SERVICES:
        # opt-in services (e.g. Cloud Asset Inventory) never run under the run-all default
        assert _service_selected(spec, _args(), every_flag_missing=True) is (not spec.opt_in)


def test_service_selected_false_when_no_gate_set_and_flags_present():
    for spec in _SERVICES:
        assert _service_selected(spec, _args(), every_flag_missing=False) is False


@pytest.mark.parametrize(
    "args_overrides, every_flag_missing, expected",
    [
        # KMS's own gate flag set -> selected.
        ({"cloud_kms": True}, False, True),
        # A different service's flag set -> KMS stays unselected.
        ({"cloud_run": True}, False, False),
    ],
    ids=["own_gate_flag_selects", "unrelated_gate_does_not_select"],
)
def test_service_selected_kms_gate_flag(args_overrides, every_flag_missing, expected):
    spec = _spec_by_module_tail("enum_kms")  # gate flag: cloud_kms
    args = _args(**args_overrides)
    assert _service_selected(spec, args, every_flag_missing=every_flag_missing) is expected


def test_service_selected_compute_resources_has_two_gate_flags():
    """Compute resources is selectable via either the umbrella --cloud-compute
    (cloud_compute) or its own --cloud-compute-resources flag."""
    spec = _spec_by_module_tail("enum_cloudcompute_resources")
    assert spec.gate_flags == ("cloud_compute", "cloud_compute_resources")
    assert _service_selected(spec, _args(cloud_compute=True), every_flag_missing=False) is True
    assert _service_selected(spec, _args(cloud_compute_resources=True), every_flag_missing=False) is True
    assert _service_selected(spec, _args(), every_flag_missing=False) is False


def test_parallel_services_opt_in_is_additive():
    """Opt-in services (asset_inventory) are additive in the parallel path, matching
    the sequential every_flag_missing semantics: a bare run skips them; their flag adds
    them WITHOUT suppressing the other services."""
    from gcpwn.modules.everything.enumeration.enum_all import _enabled_parallel_services

    def keys(argv):
        return {key for key, _ in _enabled_parallel_services(argv)}

    bare = keys([])
    assert "cloud_storage" in bare and "asset_inventory" not in bare
    # opt-in token ALONE is additive (every non-opt-in service still runs, plus it)
    only_opt_in = keys(["--modules", "asset-inventory"])
    assert {"asset_inventory", "cloud_storage", "cloud_run"} <= only_opt_in
    # a real service token + the opt-in token -> just that service plus the opt-in
    combo = keys(["--modules", "storage,asset-inventory"])
    assert combo >= {"cloud_storage", "asset_inventory"} and "cloud_run" not in combo


def test_service_selected_missing_attr_defaults_false():
    """getattr fallback: a namespace lacking a gate attr must not raise and must
    read as unselected (mirrors how run_module never adds the attr if absent)."""
    spec = _spec_by_module_tail("enum_bigtable")
    bare = SimpleNamespace()  # no cloud_bigtable attribute at all
    assert _service_selected(spec, bare, every_flag_missing=False) is False
    assert _service_selected(spec, bare, every_flag_missing=True) is True


# --------------------------------------------------------------------------- #
# get gating: get_tokens OR args.get, and spec.get default                     #
# --------------------------------------------------------------------------- #
def test_get_requires_args_get_for_non_token_specs():
    spec = _spec_by_module_tail("enum_cloudstorage")
    assert "--get" not in _build_service_args(spec, _args(get=False), _NO_DOWNLOAD)
    assert "--get" in _build_service_args(spec, _args(get=True), _NO_DOWNLOAD)


def test_get_emitted_once_when_both_args_get_and_token_present():
    spec = _spec_by_module_tail("enum_cloudfunctions")
    out = _build_service_args(spec, _args(get=True), _downloader("function_env"))
    assert out.count("--get") == 1
