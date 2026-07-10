from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
ENUM_DIR = REPO_ROOT / "gcpwn" / "modules"


def test_service_specific_iam_enum_modules_do_not_exist() -> None:
    offenders = [
        path.relative_to(REPO_ROOT).as_posix()
        for path in sorted(ENUM_DIR.glob("*/enumeration/*_iam.py"))
        if "gcpwn/modules/iam/" not in path.as_posix()
    ]
    assert offenders == [], (
        "IAM binding enumeration should live in enum_gcp_policy_bindings/IAMPolicyBindingsResource, "
        f"not service-specific *_iam modules: {offenders}"
    )
