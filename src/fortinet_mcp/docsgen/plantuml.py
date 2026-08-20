"""PlantUML component-diagram generation for device topology."""
from __future__ import annotations

from typing import Any

from ._util import safe_id


def generate_topology(
    device_name: str,
    interfaces: list[dict[str, Any]],
    static_routes: list[dict[str, Any]],
    virtual_ips: list[dict[str, Any]],
) -> str:
    fw_id = safe_id(device_name) or "fw"
    lines = ["@startuml", f"title Topology - {device_name}", "", f'node "{device_name}" as {fw_id}']

    iface_names = {i.get("name") for i in interfaces if i.get("name")}
    for name in sorted(iface_names):
        iface_id = safe_id(name)
        lines.append(f'component "{name}" as {iface_id}')
        lines.append(f"{fw_id} -- {iface_id}")

    for route in static_routes:
        dst = route.get("dst")
        via_iface = route.get("device")
        if not dst:
            continue
        dst_id = safe_id(f"net_{dst}")
        lines.append(f'node "{dst}" as {dst_id}')
        source = safe_id(via_iface) if via_iface else fw_id
        lines.append(f"{source} --> {dst_id}")

    for vip in virtual_ips:
        name = vip.get("name")
        extip, mappedip = vip.get("extip"), vip.get("mappedip")
        if not name or not extip or not mappedip:
            continue
        vip_id = safe_id(f"vip_{name}")
        lines.append(f'component "VIP {name}\\n{extip} -> {mappedip}" as {vip_id}')
        extintf = vip.get("extintf")
        source = safe_id(extintf) if extintf and extintf in iface_names else fw_id
        lines.append(f"{source} --> {vip_id}")

    lines.append("")
    lines.append("@enduml")
    return "\n".join(lines)
