"""Error text that is safe to show to clients and to store in incident events."""

from __future__ import annotations

import re

# Credentials in a URL: everything between "://" and the last "@" before the first "/".
_URL_USERINFO = re.compile(r"(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*://)[^/\s]*@")

# Exceptions Aegis raises itself ("cycle timed out after 60s") describe what happened and
# are safe to show. Library errors (httpx, OpenAI, sqlite) embed URLs and hostnames.
_OWN_MESSAGE_TYPES = (ValueError, KeyError, TypeError, RuntimeError, TimeoutError)


def redact_urls(text: str) -> str:
    """Remove the user:password part of every URL in the text."""
    return _URL_USERINFO.sub(r"\g<scheme>", text)


def error_summary(exc: BaseException) -> str:
    """
    Describe an exception as its class and HTTP status, without library detail.

    The full text stays in the server log; clients get this.
    """
    name = type(exc).__name__
    status = getattr(getattr(exc, "response", None), "status_code", None)
    if isinstance(status, int):
        return f"{name} (HTTP {status})"
    if isinstance(exc, _OWN_MESSAGE_TYPES) and str(exc):
        return f"{name}: {redact_urls(str(exc))}"
    return name
