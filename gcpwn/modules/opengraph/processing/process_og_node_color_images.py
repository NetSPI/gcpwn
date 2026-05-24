from __future__ import annotations

import argparse

from gcpwn.modules.opengraph.utilities.helpers.ui_formatting.custom_node_sync import (
    push_custom_node_attributes,
)

_DEFAULT_CUSTOM_NODE_URL = "http://127.0.0.1:8080/api/v2/custom-nodes"


def _parse_args(user_args):
    parser = argparse.ArgumentParser(
        description="Push OpenGraph/BloodHound custom node color/image metadata",
        allow_abbrev=False,
    )
    parser.add_argument(
        "--push-custom-node-attributes-url",
        default=_DEFAULT_CUSTOM_NODE_URL,
        required=False,
        help=(
            "BloodHound custom-node endpoint URL. "
            "Typical local endpoint: http://127.0.0.1:8080/api/v2/custom-nodes"
        ),
    )
    parser.add_argument(
        "--push-custom-node-attributes-token",
        default="",
        required=False,
        help="Bearer JWT token used for custom-node push when auth mode is bearer.",
    )
    parser.add_argument(
        "--custom-node-auth-mode",
        choices=("bearer", "signature"),
        default="bearer",
        required=False,
        help="BloodHound API auth mode: bearer JWT or signature (API key/ID HMAC).",
    )
    parser.add_argument(
        "--push-custom-node-attributes-token-id",
        default="",
        required=False,
        help="BloodHound API token ID used for signature auth mode.",
    )
    parser.add_argument(
        "--push-custom-node-attributes-token-key",
        default="",
        required=False,
        help="BloodHound API token KEY/secret used for signature auth mode.",
    )
    parser.add_argument(
        "--prompt-custom-node-token",
        action="store_true",
        help="Prompt for bearer token if not supplied with --push-custom-node-attributes-token.",
    )
    parser.add_argument(
        "--prompt-custom-node-signature-creds",
        action="store_true",
        help="Prompt for API token ID/key if not supplied for signature auth mode.",
    )
    return parser.parse_args(user_args)


def _has_session_prompt_helpers(session) -> bool:
    has_selector = hasattr(session, "choice_selector") and callable(getattr(session, "choice_selector"))
    has_prompt = hasattr(session, "choice_prompt") and callable(getattr(session, "choice_prompt"))
    return bool(has_selector and has_prompt)


def _prompt_text(session, prompt: str, *, regex: str | None = None) -> str:
    if not hasattr(session, "choice_prompt") or not callable(getattr(session, "choice_prompt")):
        return ""
    return str(session.choice_prompt(prompt, regex=regex) or "").strip()


def _select_auth_mode(session) -> str | None:
    choice = None
    if hasattr(session, "choice_selector") and callable(getattr(session, "choice_selector")):
        choice = session.choice_selector(
            ["Bearer JWT", "API key signature"],
            "Custom-node sync: choose auth mode",
        )
    if not choice:
        return None
    return "signature" if str(choice).strip().lower().startswith("api key") else "bearer"


def _interactive_prompt_inputs(session, default_url: str) -> dict[str, str] | None:
    if not _has_session_prompt_helpers(session):
        print("[X] No arguments were supplied and this session cannot prompt interactively.")
        return None

    print("[*] No arguments supplied. Launching BloodHound custom-node sync setup.")
    entered_url = _prompt_text(
        session,
        f"BloodHound custom-node URL (press Enter to use default: {default_url}): ",
    )
    custom_nodes_url = entered_url or default_url
    auth_mode = _select_auth_mode(session)
    if not auth_mode:
        return None

    if auth_mode == "bearer":
        print("[*] Token tip: open BloodHound in browser, then DevTools -> Network.")
        print("[*] Click any authenticated API request and copy the Authorization Bearer token value.")
        custom_nodes_token = _prompt_text(session, "BloodHound bearer token: ")
        if not custom_nodes_token:
            print("[X] No bearer token provided. Aborting custom-node sync.")
            return None
        return {
            "custom_nodes_url": custom_nodes_url,
            "auth_mode": "bearer",
            "custom_nodes_token": custom_nodes_token,
        }

    cached_catalog = _load_cached_signature_catalog(session)
    selected = _select_cached_signature_or_new(session, cached_catalog)
    if selected is None:
        return None
    if selected:
        token_id = str(selected.get("custom_nodes_token_id") or "").strip()
        token_key = str(selected.get("custom_nodes_token_key") or "").strip()
        selected_url = str(selected.get("custom_nodes_url") or "").strip()
        return {
            # Respect the URL the user just entered for this run.
            "custom_nodes_url": custom_nodes_url or selected_url,
            "auth_mode": "signature",
            "custom_nodes_token_id": token_id,
            "custom_nodes_token_key": token_key,
        }

    print("[*] API key tip: BloodHound -> My Profile -> API Key Management -> Create Token.")
    token_id = _prompt_text(session, "BloodHound API token ID: ")
    token_key = _prompt_text(session, "BloodHound API token KEY/secret: ")
    if not token_id or not token_key:
        print("[X] API token ID/key are required for signature mode. Aborting custom-node sync.")
        return None
    return {
        "custom_nodes_url": custom_nodes_url,
        "auth_mode": "signature",
        "custom_nodes_token_id": token_id,
        "custom_nodes_token_key": token_key,
    }


def _load_cached_signature_catalog(session) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    raw_catalog = session.get_data("opengraph_ui_config") or []
    for raw_entry in raw_catalog:
        token_id = str(raw_entry.get("custom_nodes_token_id") or "").strip()
        token_key = str(raw_entry.get("custom_nodes_token_key") or "").strip()
        if not token_id or not token_key:
            continue
        entries.append(
            {
                "custom_nodes_url": str(raw_entry.get("custom_nodes_url") or "").strip(),
                "auth_mode": str(raw_entry.get("auth_mode") or "signature").strip().lower() or "signature",
                "custom_nodes_token_id": token_id,
                "custom_nodes_token_key": token_key,
            }
        )

    deduped: list[dict[str, str]] = []
    seen_ids: set[str] = set()
    for entry in entries:
        token_id = str(entry.get("custom_nodes_token_id") or "").strip()
        if not token_id or token_id in seen_ids:
            continue
        seen_ids.add(token_id)
        deduped.append(entry)
    return deduped


def _save_signature_config(
    session,
    *,
    custom_nodes_url: str,
    auth_mode: str,
    custom_nodes_token_id: str,
    custom_nodes_token_key: str,
) -> None:
    url_token = str(custom_nodes_url or "").strip()
    auth_token = str(auth_mode or "").strip().lower()
    id_token = str(custom_nodes_token_id or "").strip()
    key_token = str(custom_nodes_token_key or "").strip()
    if not id_token or not key_token:
        return
    session.insert_data(
        "opengraph_ui_config",
        {
            "custom_nodes_token_id": id_token,
            "custom_nodes_token_key": key_token,
            "custom_nodes_url": url_token,
            "auth_mode": auth_token or "signature",
        },
        if_column_matches=["custom_nodes_token_id", "workspace_id"],
    )
    print("[*] Saved BloodHound signature credentials to opengraph_ui_config for optional future reuse.")


def _select_cached_signature_or_new(session, candidates: list[dict[str, str]]) -> dict[str, str] | None:
    if not candidates:
        return {}

    menu_rows: list[dict[str, str]] = []
    for entry in candidates:
        token_id = str(entry.get("custom_nodes_token_id") or "").strip()
        url = str(entry.get("custom_nodes_url") or "").strip() or _DEFAULT_CUSTOM_NODE_URL
        menu_rows.append(
            {
                "choice_type": "saved",
                "custom_nodes_url": url,
                "auth_mode": "signature",
                "custom_nodes_token_id": token_id,
                "custom_nodes_token_key": str(entry.get("custom_nodes_token_key") or "").strip(),
                "printout": f"Saved Token ID: {token_id} ({url})",
            }
        )
    menu_rows.append(
        {
            "choice_type": "new",
            "printout": "Enter a new API token ID/key",
        }
    )

    if not hasattr(session, "choice_selector") or not callable(getattr(session, "choice_selector")):
        return None
    selected = session.choice_selector(
        menu_rows,
        "Choose a saved BloodHound API token or enter a new one:",
        fields=["printout"],
    )

    if not selected:
        return None
    if str(selected.get("choice_type") or "").strip() == "new":
        return {}
    return {
        "custom_nodes_url": str(selected.get("custom_nodes_url") or "").strip(),
        "auth_mode": "signature",
        "custom_nodes_token_id": str(selected.get("custom_nodes_token_id") or "").strip(),
        "custom_nodes_token_key": str(selected.get("custom_nodes_token_key") or "").strip(),
    }


def _maybe_reuse_cached_signature_credentials(
    session,
    *,
    custom_nodes_url: str,
    auth_mode: str,
    custom_nodes_token_id: str,
    custom_nodes_token_key: str,
    default_url: str,
) -> tuple[str, str, str, str, bool]:
    """
    Optionally reuse cached signature credentials with explicit user consent.

    Returns (url, auth_mode, token_id, token_key, reused_cached).
    """
    mode = str(auth_mode or "").strip().lower()
    if mode != "signature":
        return custom_nodes_url, auth_mode, custom_nodes_token_id, custom_nodes_token_key, False
    if custom_nodes_token_id and custom_nodes_token_key:
        return custom_nodes_url, auth_mode, custom_nodes_token_id, custom_nodes_token_key, False
    if not _has_session_prompt_helpers(session):
        return custom_nodes_url, auth_mode, custom_nodes_token_id, custom_nodes_token_key, False

    cached_catalog = _load_cached_signature_catalog(session)
    selected = _select_cached_signature_or_new(session, cached_catalog)
    if selected is None:
        return custom_nodes_url, auth_mode, custom_nodes_token_id, custom_nodes_token_key, False
    if not selected:
        return custom_nodes_url, auth_mode, custom_nodes_token_id, custom_nodes_token_key, False
    selected_token_id = str(selected.get("custom_nodes_token_id") or "").strip()
    selected_token_key = str(selected.get("custom_nodes_token_key") or "").strip()
    selected_url = str(selected.get("custom_nodes_url") or "").strip()
    if not selected_token_id or not selected_token_key:
        return custom_nodes_url, auth_mode, custom_nodes_token_id, custom_nodes_token_key, False

    # Respect an explicit URL passed on this invocation over saved URL metadata.
    reused_url = str(custom_nodes_url or "").strip() or selected_url or str(default_url or "").strip()
    return (
        reused_url,
        "signature",
        custom_nodes_token_id or selected_token_id,
        custom_nodes_token_key or selected_token_key,
        True,
    )


def run_module(user_args, session):
    args_list = list(user_args or [])
    args = _parse_args(args_list)

    custom_nodes_url = str(args.push_custom_node_attributes_url or "")
    custom_nodes_token = str(args.push_custom_node_attributes_token or "")
    auth_mode = str(args.custom_node_auth_mode or "bearer")
    custom_nodes_token_id = str(args.push_custom_node_attributes_token_id or "")
    custom_nodes_token_key = str(args.push_custom_node_attributes_token_key or "")
    prompt_for_token = bool(args.prompt_custom_node_token)
    prompt_for_signature_credentials = bool(args.prompt_custom_node_signature_creds)

    reused_cached = False
    custom_nodes_url, auth_mode, custom_nodes_token_id, custom_nodes_token_key, reused_cached = (
        _maybe_reuse_cached_signature_credentials(
            session,
            custom_nodes_url=custom_nodes_url,
            auth_mode=auth_mode,
            custom_nodes_token_id=custom_nodes_token_id,
            custom_nodes_token_key=custom_nodes_token_key,
            default_url=_DEFAULT_CUSTOM_NODE_URL,
        )
    )

    # If the user runs this module with no flags and did not opt to reuse cached creds, run interactive setup.
    if not args_list and not reused_cached:
        prompted_inputs = _interactive_prompt_inputs(session, _DEFAULT_CUSTOM_NODE_URL)
        if not prompted_inputs:
            return -1
        custom_nodes_url = str(prompted_inputs.get("custom_nodes_url") or custom_nodes_url)
        auth_mode = str(prompted_inputs.get("auth_mode") or auth_mode)
        custom_nodes_token = str(prompted_inputs.get("custom_nodes_token") or custom_nodes_token)
        custom_nodes_token_id = str(prompted_inputs.get("custom_nodes_token_id") or custom_nodes_token_id)
        custom_nodes_token_key = str(prompted_inputs.get("custom_nodes_token_key") or custom_nodes_token_key)
        prompt_for_token = False
        prompt_for_signature_credentials = False
    elif prompt_for_token and auth_mode == "bearer" and not custom_nodes_token:
        if not _has_session_prompt_helpers(session):
            print("[X] --prompt-custom-node-token requested but this session cannot prompt interactively.")
            return -1
        custom_nodes_token = _prompt_text(session, "BloodHound bearer token: ")
        if not custom_nodes_token:
            print("[X] No bearer token provided.")
            return -1
        prompt_for_token = False
    elif prompt_for_signature_credentials and auth_mode == "signature" and (
        not custom_nodes_token_id or not custom_nodes_token_key
    ):
        if not _has_session_prompt_helpers(session):
            print("[X] --prompt-custom-node-signature-creds requested but this session cannot prompt interactively.")
            return -1
        print("[*] API key tip: BloodHound -> My Profile -> API Key Management -> Create Token.")
        custom_nodes_token_id = custom_nodes_token_id or _prompt_text(session, "BloodHound API token ID: ")
        custom_nodes_token_key = custom_nodes_token_key or _prompt_text(session, "BloodHound API token KEY/secret: ")
        if not custom_nodes_token_id or not custom_nodes_token_key:
            print("[X] API token ID/key are required for signature mode.")
            return -1
        prompt_for_signature_credentials = False

    mode = str(auth_mode or "bearer").strip().lower()
    if mode not in {"bearer", "signature"}:
        print(f"[*] Skipping custom-nodes push: unsupported auth mode '{mode}'.")
        return -1
    result = push_custom_node_attributes(
        custom_nodes_url=str(custom_nodes_url or ""),
        custom_nodes_token=str(custom_nodes_token or "").strip(),
        auth_mode=mode,
        custom_nodes_token_id=str(custom_nodes_token_id or "").strip(),
        custom_nodes_token_key=str(custom_nodes_token_key or "").strip(),
    )

    if bool(result.get("ok")) and auth_mode == "signature" and custom_nodes_token_id and custom_nodes_token_key:
        _save_signature_config(
            session,
            custom_nodes_url=custom_nodes_url,
            auth_mode=auth_mode,
            custom_nodes_token_id=custom_nodes_token_id,
            custom_nodes_token_key=custom_nodes_token_key,
        )

    if bool(result.get("ok")):
        return 1
    return -1
