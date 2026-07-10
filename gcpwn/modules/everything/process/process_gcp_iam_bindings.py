import argparse
import traceback

from gcpwn.core.console import UtilityTools
from gcpwn.modules.everything.utilities.helpers import generate_summary_of_roles_or_vulns
from gcpwn.modules.everything.utilities.iam_policy_bindings import (
    IAMPolicyBindingsResource,
    materialize_member_permissions,
)


def run_module(user_args, session):
    parser = argparse.ArgumentParser(description="Report consolidated per-member IAM roles/assets", allow_abbrev=False)
    parser.add_argument("-v", "--debug", action="store_true", required=False, help="Get verbose data returned")
    parser.add_argument("--txt", action="store_true", help="Output in TXT format")
    parser.add_argument("--csv", action="store_true", help="Output in CSV format")
    parser.add_argument("--silent", action="store_true", help="No stdout")
    parser.add_argument("--output", required=False, help="Output directory to store IAM snapshot report")
    parser.add_argument(
        "--force-refresh-bindings",
        action="store_true",
        help="Re-enumerate IAM bindings before reporting (recommended if new resources were added)",
    )
    args = parser.parse_args(user_args)

    def _enumerate_bindings(reason: str) -> None:
        print(reason)
        try:
            IAMPolicyBindingsResource(session).run(save_raw_policies=True)
        except Exception:
            if args.debug:
                print(traceback.format_exc())

    if args.force_refresh_bindings:
        _enumerate_bindings("[*] Refreshing IAM bindings (forced)...")

    # The member-inverted view is materialized inherently after bindings
    # enumeration (enum_all / enum_gcp_policy_bindings); here we (re)materialize and
    # take the per-member roles/assets back to render the snapshot report.
    entries = materialize_member_permissions(session)
    if not entries and not args.force_refresh_bindings:
        _enumerate_bindings("[*] No IAM bindings found; enumerating IAM policies across resources now...")
        entries = materialize_member_permissions(session)

    if not entries:
        print(f"{UtilityTools.RED}[X] No IAM bindings were found. Run 'modules run enum_gcp_policy_bindings' first.{UtilityTools.RESET}")
        return

    for index, entry in enumerate(entries):
        generate_summary_of_roles_or_vulns(
            session,
            entry["member"],
            entry["data_dict"],
            first_run=(index == 0),
            output_file=args.output,
            csv=args.csv,
            txt=args.txt,
            stdout=not args.silent,
        )
    return 1
