import ipaddress
import socket

import pytest

from injectkit.errors import NetworkPolicyError
from injectkit.netpolicy import (
    NetworkMode,
    check_address,
    resolve_and_check,
)

ALWAYS_DENIED = [
    "169.254.169.254",
    "169.254.0.1",
    "fe80::1",
    "fd00:ec2::254",
    "100.100.100.200",
    "100.64.0.1",
    str(ipaddress.IPv4Address(0)),  # the unspecified address, built to avoid a bind-all lint
    "::",
    "224.0.0.1",
    "ff02::1",
    "240.0.0.1",
    "::ffff:169.254.169.254",
    "198.18.0.1",
]
LOOPBACK = ["127.0.0.1", "127.9.9.9", "::1", "::ffff:127.0.0.1"]
PRIVATE = ["10.0.0.1", "172.16.5.4", "172.31.255.255", "192.168.1.1", "fd12::1", "::ffff:10.0.0.1"]
PUBLIC = ["93.184.216.34", "8.8.8.8", "2606:4700:4700::1111", "::ffff:8.8.8.8"]
MODES: list[NetworkMode] = ["public_only", "loopback", "private"]


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("address", ALWAYS_DENIED)
def test_always_denied_in_every_mode(address: str, mode: NetworkMode) -> None:
    with pytest.raises(NetworkPolicyError):
        check_address(ipaddress.ip_address(address), mode)


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("address", PUBLIC)
def test_public_allowed_in_every_mode(address: str, mode: NetworkMode) -> None:
    check_address(ipaddress.ip_address(address), mode)


@pytest.mark.parametrize("address", LOOPBACK)
def test_loopback_matrix(address: str) -> None:
    ip = ipaddress.ip_address(address)
    with pytest.raises(NetworkPolicyError):
        check_address(ip, "public_only")
    check_address(ip, "loopback")
    check_address(ip, "private")


@pytest.mark.parametrize("address", PRIVATE)
def test_private_matrix(address: str) -> None:
    ip = ipaddress.ip_address(address)
    with pytest.raises(NetworkPolicyError):
        check_address(ip, "public_only")
    with pytest.raises(NetworkPolicyError):
        check_address(ip, "loopback")
    check_address(ip, "private")


def resolver_returning(*addresses: str):
    async def resolver(host: str, port: int) -> list[str]:
        return list(addresses)

    return resolver


async def test_every_resolved_address_must_pass() -> None:
    mixed = resolver_returning("93.184.216.34", "127.0.0.1")
    with pytest.raises(NetworkPolicyError):
        await resolve_and_check("example.test", 443, "public_only", resolver=mixed)


async def test_resolved_public_addresses_are_returned() -> None:
    ok = resolver_returning("93.184.216.34", "2606:4700:4700::1111")
    result = await resolve_and_check("example.test", 443, "public_only", resolver=ok)
    assert result == ("93.184.216.34", "2606:4700:4700::1111")


async def test_empty_resolution_is_rejected() -> None:
    with pytest.raises(NetworkPolicyError):
        await resolve_and_check("example.test", 443, "public_only", resolver=resolver_returning())


async def test_unparseable_resolver_output_is_rejected() -> None:
    with pytest.raises(NetworkPolicyError):
        await resolve_and_check(
            "example.test", 443, "public_only", resolver=resolver_returning("not-an-ip")
        )


async def test_resolver_failure_becomes_policy_error() -> None:
    async def failing(host: str, port: int) -> list[str]:
        raise socket.gaierror(socket.EAI_NONAME, "unknown")

    with pytest.raises(NetworkPolicyError, match="resolve"):
        await resolve_and_check("nope.invalid", 443, "public_only", resolver=failing)


async def test_ip_literal_is_checked_without_resolver() -> None:
    async def boom(host: str, port: int) -> list[str]:
        raise AssertionError("resolver must not be called for IP literals")

    with pytest.raises(NetworkPolicyError):
        await resolve_and_check("169.254.169.254", 80, "private", resolver=boom)
    assert await resolve_and_check("[::1]", 80, "loopback", resolver=boom) == ("::1",)


async def test_ipv6_zone_id_is_stripped_then_denied() -> None:
    with pytest.raises(NetworkPolicyError):
        await resolve_and_check("fe80::1%eth0", 80, "private", resolver=resolver_returning())


async def test_real_resolver_localhost_denied_by_default() -> None:
    with pytest.raises(NetworkPolicyError):
        await resolve_and_check("localhost", 80, "public_only")


async def test_real_resolver_localhost_allowed_in_loopback_mode() -> None:
    addresses = await resolve_and_check("localhost", 80, "loopback")
    assert addresses
    assert all(ipaddress.ip_address(a).is_loopback for a in addresses)


async def test_decimal_obfuscated_host_is_resolved_then_denied() -> None:
    # getaddrinfo maps 2130706433 -> 127.0.0.1; the policy must judge the result.
    with pytest.raises(NetworkPolicyError):
        await resolve_and_check("2130706433", 80, "public_only")


async def test_empty_host_is_rejected() -> None:
    with pytest.raises(NetworkPolicyError):
        await resolve_and_check("", 80, "public_only")
