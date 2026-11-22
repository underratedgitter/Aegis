"""ASGI middleware shared by the control plane and the demo services."""

from __future__ import annotations

import re
import uuid
from typing import TYPE_CHECKING

from fastapi import HTTPException
from starlette.datastructures import Headers, MutableHeaders
from starlette.responses import JSONResponse

if TYPE_CHECKING:
    from collections.abc import Mapping

    from starlette.requests import Request
    from starlette.types import ASGIApp, Message, Receive, Scope, Send

# The control room ships inline event handlers (onclick=...) and one inline
# style attribute. CSP level 3 lets those be allowed on their own through
# script-src-attr and style-src-attr while inline <script>/<style> elements,
# javascript: URLs and every external origin stay blocked.
UI_CSP = "; ".join(
    [
        "default-src 'self'",
        "script-src 'self'",
        "script-src-attr 'unsafe-inline'",
        "style-src 'self'",
        "style-src-attr 'unsafe-inline'",
        "img-src 'self' data:",
        "connect-src 'self'",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'self'",
        "frame-ancestors 'none'",
    ]
)

# FastAPI's generated /docs and /redoc pages load their bundles from jsDelivr
# and boot with an inline script, so they cannot run under UI_CSP.
DOCS_CSP = "; ".join(
    [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net",
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com",
        "img-src 'self' data: https://fastapi.tiangolo.com https://cdn.redoc.ly",
        "font-src 'self' https://fonts.gstatic.com",
        "worker-src blob:",
        "connect-src 'self'",
        "object-src 'none'",
        "base-uri 'none'",
        "frame-ancestors 'none'",
    ]
)

# JSON-only services never render markup, so nothing may load at all.
API_CSP = "default-src 'none'; frame-ancestors 'none'"


_REQUEST_ID = re.compile(r"[A-Za-z0-9._-]{1,64}")


def request_id(client_value: str | None) -> str:
    """
    Use the caller's X-Request-Id only when it is short and plain, else make a new one.

    The id is written to logs, and the investigator reads those logs, so free text from
    a client must not get through.
    """
    if client_value and _REQUEST_ID.fullmatch(client_value):
        return client_value
    return str(uuid.uuid4())


def security_headers(policy: str, https: bool) -> dict[str, str]:
    """The hardening headers every response carries."""
    headers = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        "Content-Security-Policy": policy,
    }
    if https:
        headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return headers


async def internal_error_response(request: Request, _: Exception) -> JSONResponse:
    """
    Answer an unhandled exception with a generic 500.

    Starlette builds this response outside the middleware stack, so it needs the
    security headers added by hand, and the exception detail stays in the server log.
    """
    return JSONResponse(
        {"detail": "Internal server error."},
        status_code=500,
        headers=security_headers(API_CSP, request.url.scheme == "https"),
    )


class SecurityHeadersMiddleware:
    """Add browser hardening headers to every HTTP response, including errors."""

    def __init__(
        self, app: ASGIApp, csp: str, path_csp: Mapping[str, str] | None = None
    ) -> None:
        self.app = app
        self.csp = csp
        self.path_csp = dict(path_csp or {})

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        policy = self.path_csp.get(scope["path"], self.csp)
        added = security_headers(policy, scope.get("scheme") == "https")

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in added.items():
                    headers[name] = value
            await send(message)

        await self.app(scope, receive, send_with_headers)


class BodyLimitMiddleware:
    """
    Reject request bodies larger than ``max_bytes`` with 413.

    A declared Content-Length is refused before the app runs. Chunked bodies,
    which declare no length, are counted as they stream in and refused as soon
    as they cross the limit, so a client cannot buffer unbounded JSON in memory.
    """

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        declared = Headers(scope=scope).get("content-length")
        if declared is not None:
            if not declared.isascii() or not declared.isdigit():
                await self._reject(400, "Invalid Content-Length header.", scope, receive, send)
                return
            if int(declared) > self.max_bytes:
                await self._reject(413, "Request body too large.", scope, receive, send)
                return

        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise HTTPException(status_code=413, detail="Request body too large.")
            return message

        await self.app(scope, limited_receive, send)

    @staticmethod
    async def _reject(status: int, detail: str, scope: Scope, receive: Receive, send: Send) -> None:
        await JSONResponse({"detail": detail}, status_code=status)(scope, receive, send)
