"""Mermaid flowchart generation for device topology."""
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
    lines = ["flowchart LR", f'    {fw_id}["{device_name}"]']

    iface_names = {i.get("name") for i in interfaces if i.get("name")}
    for name in sorted(iface_names):
        lines.append(f'    {fw_id} --- {safe_id(name)}["{name}"]')

    for route in static_routes:
        dst = route.get("dst")
        via_iface = route.get("device")
        if not dst:
            continue
        dst_id = safe_id(f"net_{dst}")
        lines.append(f'    {dst_id}(["{dst}"])')
        if via_iface:
            lines.append(f"    {safe_id(via_iface)} --> {dst_id}")
        else:
            lines.append(f"    {fw_id} --> {dst_id}")

    for vip in virtual_ips:
        name = vip.get("name")
        extip, mappedip = vip.get("extip"), vip.get("mappedip")
        if not name or not extip or not mappedip:
            continue
        vip_id = safe_id(f"vip_{name}")
        lines.append(f'    {vip_id}["VIP {name}<br/>{extip} -&gt; {mappedip}"]')
        extintf = vip.get("extintf")
        if extintf and extintf in iface_names:
            lines.append(f"    {safe_id(extintf)} --> {vip_id}")
        else:
            lines.append(f"    {fw_id} --> {vip_id}")

    return "\n".join(lines)
