"""Network helpers: trustworthy client IP and SSRF-safe URL checks."""

import asyncio
import ipaddress
import socket
from urllib.parse import urlparse

from fastapi import Request

from app.config import settings


def client_ip(request: Request) -> str:
    """
    The caller's IP. X-Forwarded-For is attacker-controlled unless a trusted reverse proxy
    sets it, so it is honoured only when TRUST_PROXY_HEADERS=true, and then the entry added by
    the last TRUSTED_PROXY_HOPS proxies is used (never the client-supplied left-most value).
    """
    if settings.trust_proxy_headers:
        parts = [p.strip() for p in request.headers.get("x-forwarded-for", "").split(",") if p.strip()]
        hops = max(1, settings.trusted_proxy_hops)
        if len(parts) >= hops:
            return parts[-hops]
    return request.client.host if request.client else "unknown"


def _is_public(ip: ipaddress._BaseAddress) -> bool:
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified)


async def assert_public_http_url(url: str) -> None:
    """Raise ValueError unless ``url`` is http(s) and every address it resolves to is public (blocks SSRF to internal services / cloud metadata)."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("URL must be http(s)")
    if settings.allow_private_webhooks:
        return
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80),
                                                            type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"Cannot resolve {parsed.hostname}") from exc
    for info in infos:
        if not _is_public(ipaddress.ip_address(info[4][0])):
            raise ValueError("Webhook target resolves to a private or internal address (set ALLOW_PRIVATE_WEBHOOKS=true to permit)")
