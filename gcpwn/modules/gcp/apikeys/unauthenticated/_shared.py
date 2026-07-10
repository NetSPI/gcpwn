from __future__ import annotations

import warnings
from typing import Any

# Shared helpers for the apikeys unauthenticated modules
# (enum_all_scopes / gemini_exploit / vertex_exploit). These were previously
# duplicated byte-for-byte in each module.

# TLS verification is ON by default; --insecure flips this for intercepting
# proxies (e.g. Burp). Set once in run_module before any request is built,
# then read via tls_verify() at request-build time.
_VERIFY_TLS = True


def set_tls_verification(*, insecure: bool) -> None:
    global _VERIFY_TLS
    _VERIFY_TLS = not insecure
    if insecure:
        import urllib3

        warnings.filterwarnings("ignore", message="Unverified HTTPS request")
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def tls_verify() -> bool:
    return _VERIFY_TLS


def prompt_yes_no(session: Any, prompt: str) -> bool:
    if session is not None and hasattr(session, "choice_prompt"):
        answer = session.choice_prompt(prompt, regex=r"^[yYnN]$")
    else:
        answer = input("> " + prompt).strip()
    return str(answer or "").strip().lower() == "y"
