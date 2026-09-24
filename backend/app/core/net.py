"""Client address resolution.

``X-Forwarded-For`` is client-controlled: any caller can set it. It is
therefore honoured **only** when the directly connected peer is inside a
configured trusted proxy range. This module is the single source of truth for
that decision so the rate limiter and the audit log cannot drift apart.
"""

from __future__ import annotations

import ipaddress

from starlette.types import Scope

type IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def is_trusted_proxy(ip: str | None, networks: tuple[IPNetwork, ...]) -> bool:
    """Return whether ``ip`` belongs to one of the trusted proxy networks."""
    if not ip or not networks:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in network for network in networks)


def client_ip_from_scope(scope: Scope, trusted_networks: tuple[IPNetwork, ...] = ()) -> str | None:
    """Resolve the client IP behind an ASGI scope.

    When the peer is a trusted proxy, the *right-most* ``X-Forwarded-For``
    entry is used (that hop was appended by infrastructure we control). In every
    other case the value is ignored and the socket peer address is returned.

    Args:
        scope: The ASGI connection scope.
        trusted_networks: Networks allowed to assert forwarding headers.

    Returns:
        The best available client IP, or ``None`` if it cannot be determined.
    """
    peer = scope.get("client")
    peer_ip = str(peer[0]) if peer and peer[0] else None

    if not is_trusted_proxy(peer_ip, trusted_networks):
        return peer_ip

    headers = dict(scope.get("headers", []))
    forwarded = headers.get(b"x-forwarded-for")
    if forwarded:
        hops = [hop.strip() for hop in forwarded.decode("latin-1").split(",") if hop.strip()]
        if hops:
            last_hop: str = hops[-1]
            return last_hop

    real_ip = headers.get(b"x-real-ip")
    if real_ip:
        return real_ip.decode("latin-1").strip() or peer_ip

    return peer_ip
