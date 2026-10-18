"""SSRF network policy: every address a host resolves to must satisfy the mode."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Awaitable, Callable
from typing import Literal

from injectkit.errors import NetworkPolicyError

type NetworkMode = Literal["public_only", "loopback", "private"]
type IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
type Resolver = Callable[[str, int], Awaitable[list[str]]]

_CGNAT = ipaddress.ip_network("100.64.0.0/10")
# Prefixes that embed IPv4 addresses and can tunnel to internal hosts.
_TUNNELS = tuple(
    ipaddress.ip_network(net) for net in ("64:ff9b::/96", "64:ff9b:1::/48", "2002::/16")
)
_RFC1918_AND_ULA = tuple(
    ipaddress.ip_network(net)
    for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
)
# Cloud metadata endpoints that sit outside link-local (ULA / CGNAT ranges).
_METADATA = frozenset(ipaddress.ip_address(addr) for addr in ("fd00:ec2::254", "100.100.100.200"))


def unmap(address: IPAddress) -> IPAddress:
    """Return the embedded IPv4 address of an IPv4-mapped IPv6 address."""
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def _is_always_denied(address: IPAddress) -> bool:
    return (
        address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
        or address in _METADATA
        or (isinstance(address, ipaddress.IPv6Address) and any(address in n for n in _TUNNELS))
        or (isinstance(address, ipaddress.IPv4Address) and address in _CGNAT)
    )


def check_address(address: IPAddress, mode: NetworkMode) -> None:
    """Raise NetworkPolicyError unless address is allowed in mode."""
    ip = unmap(address)
    if ip.is_loopback:  # before the reserved check: Python flags ::1 as reserved
        allowed = mode in ("loopback", "private")
    elif _is_always_denied(ip):
        raise NetworkPolicyError(f"address {ip} is never allowed (link-local/metadata/special)")
    elif any(ip in net for net in _RFC1918_AND_ULA):
        allowed = mode == "private"
    else:
        allowed = ip.is_global
    if not allowed:
        raise NetworkPolicyError(f"address {ip} is not allowed by network policy '{mode}'")


async def system_resolver(host: str, port: int) -> list[str]:
    """Resolve via the OS (``loop.getaddrinfo``), returning unique address strings."""
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(str(info[4][0]) for info in infos))


def _parse(raw: str) -> IPAddress:
    try:
        return ipaddress.ip_address(raw.split("%", 1)[0])
    except ValueError:
        raise NetworkPolicyError("resolver returned an unparseable address") from None


async def resolve_and_check(
    host: str,
    port: int,
    mode: NetworkMode,
    *,
    resolver: Resolver = system_resolver,
) -> tuple[str, ...]:
    """Resolve ``host`` and require that **every** address passes the policy.

    Hosts are always resolved (never pattern-matched), so numeric obfuscation such
    as ``2130706433`` is judged by the address it really maps to.
    """
    name = host.strip().removeprefix("[").removesuffix("]").rstrip(".")
    if not name:
        raise NetworkPolicyError("empty host")
    literal = _literal_or_none(name)
    if literal is not None:
        check_address(literal, mode)
        return (str(literal),)
    try:
        raw_addresses = await resolver(name, port)
    except (OSError, UnicodeError):
        raise NetworkPolicyError(f"could not resolve host '{name}'") from None
    if not raw_addresses:
        raise NetworkPolicyError(f"host '{name}' resolved to no addresses")
    addresses = [_parse(raw) for raw in raw_addresses]
    for address in addresses:
        check_address(address, mode)
    return tuple(raw.split("%", 1)[0] for raw in raw_addresses)


def _literal_or_none(name: str) -> IPAddress | None:
    try:
        return ipaddress.ip_address(name.split("%", 1)[0])
    except ValueError:
        return None
