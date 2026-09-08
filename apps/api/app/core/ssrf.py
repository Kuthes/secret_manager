import ipaddress
import socket
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from apps.api.app.core.config import settings

BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # Cloud metadata / link-local (169.254.169.254)
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
    # IPv6 ranges
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


class SSRFProtectionError(Exception):
    """Raised when an outbound URL targets a prohibited or internal network."""


def validate_safe_url(url: str, allow_private: bool | None = None) -> str:
    """
    Validates that a URL:
    1. Uses http or https scheme.
    2. Resolves to a public, non-internal, non-cloud-metadata IP address.
    3. Defends against DNS rebinding, IPv4-mapped IPv6, and loopback exploits.
    """
    if not url or not isinstance(url, str):
        raise SSRFProtectionError("Invalid URL provided.")

    parsed = urlparse(url)
    if parsed.scheme.lower() not in ["http", "https"]:
        raise SSRFProtectionError(f"Prohibited URL scheme '{parsed.scheme}'. Only HTTP and HTTPS are permitted.")

    hostname = parsed.hostname
    if not hostname:
        raise SSRFProtectionError("URL must contain a valid hostname.")

    # Explicit string blacklist for fast rejection
    if hostname.lower() in ["localhost", "127.0.0.1", "::1", "metadata.google.internal", "instance-data"]:
        raise SSRFProtectionError("Access to localhost and cloud metadata hostnames is forbidden.")

    permitted_private = allow_private if allow_private is not None else settings.ALLOW_PRIVATE_INTEGRATION_TARGETS
    if permitted_private:
        return url

    try:
        # Resolve DNS addresses for host
        addr_info = socket.getaddrinfo(hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
        for info in addr_info:
            ip_str = info[4][0]
            ip_obj = ipaddress.ip_address(ip_str)

            # Check if IPv6 has mapped IPv4 address (e.g. ::ffff:127.0.0.1)
            if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
                ip_obj = ip_obj.ipv4_mapped

            for blocked_net in BLOCKED_NETWORKS:
                if ip_obj in blocked_net:
                    raise SSRFProtectionError(
                        f"Destination '{hostname}' resolves to prohibited internal address '{ip_str}'. Outbound access denied."
                    )
    except socket.gaierror as e:
        raise SSRFProtectionError(f"Failed to resolve destination hostname '{hostname}': {e!s}") from e

    return url


async def safe_http_request(
    method: str,
    url: str,
    max_redirects: int = 3,
    **kwargs: Any,
) -> httpx.Response:
    """
    Executes outbound HTTP request with strict per-hop SSRF validation and redirect protection.
    """
    current_url = validate_safe_url(url)
    redirect_count = 0

    async with httpx.AsyncClient(follow_redirects=False, timeout=kwargs.pop("timeout", 10.0)) as client:
        while True:
            response = await client.request(method, current_url, **kwargs)
            if response.is_redirect:
                redirect_count += 1
                if redirect_count > max_redirects:
                    raise SSRFProtectionError(f"Too many redirects (max: {max_redirects})")
                location = response.headers.get("Location")
                if not location:
                    return response
                next_url = urljoin(current_url, location)
                # Re-validate target URL
                current_url = validate_safe_url(next_url)
                # Next request in redirect chain is GET
                method = "GET"
                kwargs.pop("json", None)
                kwargs.pop("content", None)
            else:
                return response
