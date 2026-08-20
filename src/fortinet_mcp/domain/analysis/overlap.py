"""
Overlapping subnet detection for `ipmask`/`iprange` address objects.
`fqdn`/`geography`/etc. address types have no static IP range to compare
and are silently skipped (not flagged as an error -- they're just outside
this check's scope).
"""
from __future__ import annotations

import ipaddress
from typing import Any, Optional


def _to_range(obj: dict[str, Any]) -> Optional[tuple[int, int]]:
    obj_type = obj.get("type", "ipmask")

    if obj_type == "iprange":
        start, end = obj.get("start-ip"), obj.get("end-ip")
        if not start or not end:
            return None
        try:
            return int(ipaddress.IPv4Address(start)), int(ipaddress.IPv4Address(end))
        except ValueError:
            return None

    if obj_type == "ipmask":
        subnet = obj.get("subnet")
        if not subnet:
            return None
        try:
            if " " in subnet:
                network_str, netmask_str = subnet.split()
                network = ipaddress.IPv4Network(f"{network_str}/{netmask_str}", strict=False)
            else:
                network = ipaddress.IPv4Network(subnet, strict=False)
            return int(network.network_address), int(network.broadcast_address)
        except ValueError:
            return None

    return None  # fqdn, geography, dynamic, ... -- nothing static to compare


def find_overlapping_subnets(address_objects: list[dict[str, Any]]) -> list[dict[str, Any]]:
    parsed: list[tuple[str, tuple[int, int]]] = []
    for obj in address_objects:
        name = obj.get("name")
        rng = _to_range(obj)
        if name and rng is not None:
            parsed.append((name, rng))

    findings = []
    for i in range(len(parsed)):
        name_a, (a1, a2) = parsed[i]
        for j in range(i + 1, len(parsed)):
            name_b, (b1, b2) = parsed[j]
            if a1 > b2 or b1 > a2:
                continue  # no overlap at all

            if a1 == b1 and a2 == b2:
                relationship = "equal"
            elif a1 <= b1 and a2 >= b2:
                relationship = "a_contains_b"
            elif b1 <= a1 and b2 >= a2:
                relationship = "b_contains_a"
            else:
                relationship = "overlap"

            findings.append({"object_a": name_a, "object_b": name_b, "relationship": relationship})
    return findings
