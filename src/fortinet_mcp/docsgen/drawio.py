"""
Draw.io / diagrams.net XML generation for device topology. Built with
`xml.etree.ElementTree` rather than string concatenation so object names
containing `<`, `&`, etc. can never produce malformed or injected XML.
"""
from __future__ import annotations

from typing import Any
from xml.etree.ElementTree import Element, SubElement, tostring

from ._util import safe_id

_ROW_HEIGHT = 80
_BOX_WIDTH = 160
_BOX_HEIGHT = 40


def _add_vertex(root: Element, cell_id: str, label: str, x: int, y: int, *, style: str) -> None:
    cell = SubElement(
        root, "mxCell", {"id": cell_id, "value": label, "style": style, "vertex": "1", "parent": "1"}
    )
    SubElement(
        cell,
        "mxGeometry",
        {"x": str(x), "y": str(y), "width": str(_BOX_WIDTH), "height": str(_BOX_HEIGHT), "as": "geometry"},
    )


def _add_edge(root: Element, edge_id: str, source: str, target: str) -> None:
    cell = SubElement(
        root,
        "mxCell",
        {
            "id": edge_id,
            "style": "edgeStyle=orthogonalEdgeStyle;html=1;",
            "edge": "1",
            "parent": "1",
            "source": source,
            "target": target,
        },
    )
    SubElement(cell, "mxGeometry", {"relative": "1", "as": "geometry"})


def generate_topology(
    device_name: str,
    interfaces: list[dict[str, Any]],
    static_routes: list[dict[str, Any]],
    virtual_ips: list[dict[str, Any]],
) -> str:
    mxfile = Element("mxfile")
    diagram = SubElement(mxfile, "diagram", {"name": "Topology"})
    model = SubElement(
        diagram,
        "mxGraphModel",
        {"dx": "800", "dy": "600", "grid": "1", "gridSize": "10", "page": "1"},
    )
    root = SubElement(model, "root")
    SubElement(root, "mxCell", {"id": "0"})
    SubElement(root, "mxCell", {"id": "1", "parent": "0"})

    fw_id = "n_fw"
    _add_vertex(root, fw_id, device_name, 40, 200, style="rounded=1;whiteSpace=wrap;html=1;fillColor=#dae8fc;")

    edge_counter = 0
    iface_names = {i.get("name") for i in interfaces if i.get("name")}
    iface_ids: dict[str, str] = {}
    for row, name in enumerate(sorted(iface_names)):
        cell_id = f"iface_{safe_id(name)}"
        iface_ids[name] = cell_id
        _add_vertex(root, cell_id, name, 280, row * _ROW_HEIGHT + 40, style="rounded=1;whiteSpace=wrap;html=1;")
        edge_counter += 1
        _add_edge(root, f"e{edge_counter}", fw_id, cell_id)

    next_row = len(iface_names)
    for route in static_routes:
        dst = route.get("dst")
        if not dst:
            continue
        cell_id = f"net_{safe_id(dst)}"
        _add_vertex(root, cell_id, dst, 520, next_row * _ROW_HEIGHT + 40, style="whiteSpace=wrap;html=1;")
        via_iface = route.get("device")
        source_id = iface_ids.get(via_iface, fw_id)
        edge_counter += 1
        _add_edge(root, f"e{edge_counter}", source_id, cell_id)
        next_row += 1

    for vip in virtual_ips:
        name = vip.get("name")
        extip, mappedip = vip.get("extip"), vip.get("mappedip")
        if not name or not extip or not mappedip:
            continue
        cell_id = f"vip_{safe_id(name)}"
        label = f"VIP {name}\n{extip} -> {mappedip}"
        _add_vertex(root, cell_id, label, 520, next_row * _ROW_HEIGHT + 40, style="whiteSpace=wrap;html=1;fillColor=#d5e8d4;")
        extintf = vip.get("extintf")
        source_id = iface_ids.get(extintf, fw_id)
        edge_counter += 1
        _add_edge(root, f"e{edge_counter}", source_id, cell_id)
        next_row += 1

    return '<?xml version="1.0" encoding="UTF-8"?>\n' + tostring(mxfile, encoding="unicode")
