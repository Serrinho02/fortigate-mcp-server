"""Markdown documentation generation for policies, routing, and device summaries."""
from __future__ import annotations

from typing import Any

from ._util import escape_markdown_cell, join_names


def generate_policy_doc(device_name: str, policies: list[dict[str, Any]]) -> str:
    lines = [
        f"# Firewall Policies -- {device_name}",
        "",
        "| ID | Name | Src Intf | Dst Intf | Source | Destination | Service | Action | Status | Comments |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for p in policies:
        lines.append(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |".format(
                escape_markdown_cell(p.get("policyid")),
                escape_markdown_cell(p.get("name")),
                escape_markdown_cell(join_names(p.get("srcintf"))),
                escape_markdown_cell(join_names(p.get("dstintf"))),
                escape_markdown_cell(join_names(p.get("srcaddr"))),
                escape_markdown_cell(join_names(p.get("dstaddr"))),
                escape_markdown_cell(join_names(p.get("service"))),
                escape_markdown_cell(p.get("action")),
                escape_markdown_cell(p.get("status", "enable")),
                escape_markdown_cell(p.get("comments")),
            )
        )
    if not policies:
        lines.append("| _(no policies)_ | | | | | | | | | |")
    return "\n".join(lines)


def generate_routing_doc(
    device_name: str, static_routes: list[dict[str, Any]], routing_table: list[dict[str, Any]]
) -> str:
    lines = [f"# Routing -- {device_name}", "", "## Static Routes", "", "| Seq | Destination | Gateway | Interface |", "|---|---|---|---|"]
    for r in static_routes:
        seq = r.get("seq-num", r.get("id", ""))
        lines.append(
            "| {} | {} | {} | {} |".format(
                escape_markdown_cell(seq),
                escape_markdown_cell(r.get("dst")),
                escape_markdown_cell(r.get("gateway")),
                escape_markdown_cell(r.get("device")),
            )
        )
    if not static_routes:
        lines.append("| _(none configured)_ | | | |")

    lines += ["", "## Active Routing Table", "", "| Type | Destination | Gateway | Interface |", "|---|---|---|---|"]
    for r in routing_table:
        destination = r.get("ip_mask", r.get("dst", ""))
        lines.append(
            "| {} | {} | {} | {} |".format(
                escape_markdown_cell(r.get("type")),
                escape_markdown_cell(destination),
                escape_markdown_cell(r.get("gateway")),
                escape_markdown_cell(r.get("interface")),
            )
        )
    if not routing_table:
        lines.append("| _(empty)_ | | | |")

    return "\n".join(lines)


def generate_device_doc(
    device_name: str,
    *,
    status: dict[str, Any],
    interfaces: list[dict[str, Any]],
    vdoms: list[dict[str, Any]],
) -> str:
    lines = [f"# Device Documentation -- {device_name}", "", "## System Status", ""]
    lines.append(f"- Hostname: {status.get('hostname', '-')}")
    lines.append(f"- FortiOS version: {status.get('version', '-')}")
    lines.append(f"- Serial number: {status.get('serial', status.get('serial_number', '-'))}")

    lines += ["", "## Interfaces", "", "| Name | Status |", "|---|---|"]
    for i in interfaces:
        lines.append(
            "| {} | {} |".format(
                escape_markdown_cell(i.get("name")),
                escape_markdown_cell(i.get("status", i.get("link", "-"))),
            )
        )
    if not interfaces:
        lines.append("| _(none)_ | |")

    lines += ["", "## VDOMs", "", "| Name | Enabled |", "|---|---|"]
    for v in vdoms:
        lines.append(
            "| {} | {} |".format(escape_markdown_cell(v.get("name")), escape_markdown_cell(v.get("enabled", "-")))
        )
    if not vdoms:
        lines.append("| _(none)_ | |")

    return "\n".join(lines)


def generate_vpn_doc(
    device_name: str,
    ipsec_tunnels: list[dict[str, Any]],
    ipsec_phase2: list[dict[str, Any]],
    ipsec_status: list[dict[str, Any]],
    ssl_vpn_settings: dict[str, Any],
    ssl_vpn_session_count: int,
) -> str:
    status_by_name = {s.get("name"): s.get("status", "-") for s in ipsec_status}

    lines = [
        f"# VPN -- {device_name}",
        "",
        "## IPsec Tunnels (phase1)",
        "",
        "| Name | Interface | Remote Gateway | IKE Version | Live Status |",
        "|---|---|---|---|---|",
    ]
    for t in ipsec_tunnels:
        name = t.get("name")
        lines.append(
            "| {} | {} | {} | {} | {} |".format(
                escape_markdown_cell(name),
                escape_markdown_cell(t.get("interface")),
                escape_markdown_cell(t.get("remote-gw")),
                escape_markdown_cell(t.get("ike-version", "-")),
                escape_markdown_cell(status_by_name.get(name, "unknown")),
            )
        )
    if not ipsec_tunnels:
        lines.append("| _(none configured)_ | | | | |")

    lines += [
        "",
        "## Phase2 Traffic Selectors",
        "",
        "| Name | Tunnel (phase1) | Source Subnet | Destination Subnet |",
        "|---|---|---|---|",
    ]
    for p2 in ipsec_phase2:
        lines.append(
            "| {} | {} | {} | {} |".format(
                escape_markdown_cell(p2.get("name")),
                escape_markdown_cell(p2.get("phase1name")),
                escape_markdown_cell(p2.get("src-subnet")),
                escape_markdown_cell(p2.get("dst-subnet")),
            )
        )
    if not ipsec_phase2:
        lines.append("| _(none configured)_ | | | |")

    lines += [
        "",
        "## SSL VPN",
        "",
        f"- Port: {ssl_vpn_settings.get('port', '-')}",
        f"- Source interface: {join_names(ssl_vpn_settings.get('source-interface')) or '-'}",
        f"- Active sessions: {ssl_vpn_session_count}",
    ]

    return "\n".join(lines)


def generate_system_config_doc(
    device_name: str,
    *,
    dns: dict[str, Any],
    ntp: dict[str, Any],
    syslog: dict[str, Any],
    snmp_sysinfo: dict[str, Any],
    snmp_communities: list[dict[str, Any]],
    admins: list[dict[str, Any]],
    ha: dict[str, Any],
    global_settings: dict[str, Any],
) -> str:
    lines = [f"# System Configuration -- {device_name}", "", "## Global", ""]
    lines.append(f"- Hostname: {global_settings.get('hostname', '-')}")
    lines.append(f"- Timezone: {global_settings.get('timezone', '-')}")
    lines.append(f"- Admin HTTPS port: {global_settings.get('admin-sport', '-')}")
    lines.append(f"- Admin SSH port: {global_settings.get('admin-ssh-port', '-')}")

    lines += [
        "",
        "## DNS",
        "",
        f"- Primary: {dns.get('primary', '-')}",
        f"- Secondary: {dns.get('secondary', '-')}",
    ]

    lines += [
        "",
        "## NTP",
        "",
        f"- Sync enabled: {ntp.get('ntpsync', '-')}",
        f"- Servers: {join_names(ntp.get('server')) or ntp.get('server', '-')}",
    ]

    lines += [
        "",
        "## Syslog",
        "",
        f"- Status: {syslog.get('status', '-')}",
        f"- Server: {syslog.get('server', '-')}",
        f"- Port: {syslog.get('port', '-')}",
    ]

    lines += [
        "",
        "## SNMP",
        "",
        f"- Agent status: {snmp_sysinfo.get('status', '-')}",
        "",
        "| Community |",
        "|---|",
    ]
    for c in snmp_communities:
        lines.append(f"| {escape_markdown_cell(c.get('name'))} |")
    if not snmp_communities:
        lines.append("| _(none configured)_ |")

    lines += ["", "## Admin Accounts", "", "| Username | Access Profile |", "|---|---|"]
    for a in admins:
        lines.append(
            "| {} | {} |".format(
                escape_markdown_cell(a.get("name")), escape_markdown_cell(a.get("accprofile", "-"))
            )
        )
    if not admins:
        lines.append("| _(none)_ | |")

    lines += [
        "",
        "## HA",
        "",
        f"- Mode: {ha.get('mode', '-')}",
        f"- Group ID: {ha.get('group-id', '-')}",
    ]

    return "\n".join(lines)
