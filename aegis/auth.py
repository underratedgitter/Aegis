"""Shared construction of outbound bearer-token headers."""

from __future__ import annotations


def bearer_header(key: str) -> dict[str, str]:
    """
    Build the Authorization header for a configured API key.

    Args:
        key: The shared API key. Must not be empty or whitespace-only.

    Returns:
        A header mapping suitable for httpx or urllib.

    Raises:
        ValueError: If the key is empty or whitespace-only. Callers should
            surface a configuration error instead of sending a bare
            ``Bearer `` header that the receiving service will reject with 401.
    """
    if not isinstance(key, str) or not key.strip():
        raise ValueError("API key must be a non-empty string")
    return {"Authorization": f"Bearer {key}"}
