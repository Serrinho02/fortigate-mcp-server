"""
Tests for the pure docsgen/* rendering functions -- no adapters, no I/O,
just plain interface/route/VIP/policy dicts in, diagram/markdown text out.
"""
import xml.etree.ElementTree as ET

from src.fortinet_mcp.docsgen import drawio, markdown, mermaid, plantuml

INTERFACES = [{"name": "port1", "status": "up"}, {"name": "port2", "status": "down"}]
STATIC_ROUTES = [{"dst": "10.0.0.0/8", "gateway": "192.168.1.1", "device": "port1"}]
VIPS = [{"name": "web_vip", "extip": "1.2.3.4", "mappedip": "10.0.0.5", "extintf": "port1"}]


class TestMermaidTopology:
    def test_includes_device_and_interfaces(self):
        result = mermaid.generate_topology("fw01", INTERFACES, [], [])
        assert "flowchart LR" in result
        assert '"fw01"' in result
        assert "port1" in result and "port2" in result

    def test_includes_static_route_destination(self):
        result = mermaid.generate_topology("fw01", INTERFACES, STATIC_ROUTES, [])
        assert "10.0.0.0/8" in result

    def test_includes_vip_mapping(self):
        result = mermaid.generate_topology("fw01", INTERFACES, [], VIPS)
        assert "web_vip" in result
        assert "1.2.3.4" in result and "10.0.0.5" in result

    def test_handles_empty_input_without_error(self):
        result = mermaid.generate_topology("fw01", [], [], [])
        assert "flowchart LR" in result

    def test_sanitizes_names_with_special_characters(self):
        result = mermaid.generate_topology("fw01", [{"name": "vlan.100"}], [], [])
        assert "vlan_100" in result  # node id sanitized
        assert "vlan.100" in result  # original label preserved


class TestPlantUmlTopology:
    def test_wraps_in_startuml_enduml(self):
        result = plantuml.generate_topology("fw01", INTERFACES, [], [])
        assert result.startswith("@startuml")
        assert result.rstrip().endswith("@enduml")

    def test_includes_route_and_vip(self):
        result = plantuml.generate_topology("fw01", INTERFACES, STATIC_ROUTES, VIPS)
        assert "10.0.0.0/8" in result
        assert "web_vip" in result


class TestDrawioTopology:
    def test_produces_valid_xml(self):
        result = drawio.generate_topology("fw01", INTERFACES, STATIC_ROUTES, VIPS)
        root = ET.fromstring(result.split("\n", 1)[1])  # strip the XML declaration line
        assert root.tag == "mxfile"

    def test_contains_expected_vertex_labels(self):
        result = drawio.generate_topology("fw01", INTERFACES, STATIC_ROUTES, VIPS)
        assert 'value="fw01"' in result
        assert 'value="port1"' in result
        assert "10.0.0.0/8" in result
        assert "web_vip" in result

    def test_special_characters_do_not_break_xml(self):
        tricky = [{"name": "a<b&c\"d"}]
        result = drawio.generate_topology("fw01", tricky, [], [])
        # must still parse as valid XML -- ElementTree escapes automatically
        ET.fromstring(result.split("\n", 1)[1])

    def test_empty_input_still_produces_valid_xml_with_device_node(self):
        result = drawio.generate_topology("fw01", [], [], [])
        root = ET.fromstring(result.split("\n", 1)[1])
        assert root.tag == "mxfile"
        assert 'value="fw01"' in result


class TestMarkdownPolicyDoc:
    def test_renders_policy_table(self):
        policies = [
            {
                "policyid": 1, "name": "Allow_HTTP",
                "srcintf": [{"name": "port1"}], "dstintf": [{"name": "port2"}],
                "srcaddr": [{"name": "LAN"}], "dstaddr": [{"name": "all"}],
                "service": [{"name": "HTTP"}], "action": "accept", "status": "enable",
                "comments": "web access",
            }
        ]
        result = markdown.generate_policy_doc("fw01", policies)
        assert "Firewall Policies -- fw01" in result
        assert "Allow_HTTP" in result
        assert "web access" in result

    def test_empty_policy_list_still_renders_table_header(self):
        result = markdown.generate_policy_doc("fw01", [])
        assert "no policies" in result.lower()

    def test_pipe_character_in_comment_is_escaped(self):
        policies = [{"policyid": 1, "comments": "a|b"}]
        result = markdown.generate_policy_doc("fw01", policies)
        assert "a\\|b" in result


class TestMarkdownRoutingDoc:
    def test_renders_static_routes_and_routing_table(self):
        static_routes = [{"seq-num": 1, "dst": "10.0.0.0/8", "gateway": "192.168.1.1", "device": "port1"}]
        routing_table = [{"type": "static", "dst": "0.0.0.0/0", "gateway": "192.168.1.1", "interface": "port1"}]
        result = markdown.generate_routing_doc("fw01", static_routes, routing_table)
        assert "Routing -- fw01" in result
        assert "10.0.0.0/8" in result
        assert "0.0.0.0/0" in result

    def test_empty_input_does_not_crash(self):
        result = markdown.generate_routing_doc("fw01", [], [])
        assert "none configured" in result.lower()
        assert "empty" in result.lower()


class TestMarkdownDeviceDoc:
    def test_renders_status_interfaces_and_vdoms(self):
        result = markdown.generate_device_doc(
            "fw01",
            status={"hostname": "FW01", "version": "v7.4.0", "serial": "FGT123"},
            interfaces=[{"name": "port1", "status": "up"}],
            vdoms=[{"name": "root", "enabled": True}],
        )
        assert "FW01" in result
        assert "v7.4.0" in result
        assert "port1" in result
        assert "root" in result

    def test_missing_fields_use_placeholders_not_crash(self):
        result = markdown.generate_device_doc("fw01", status={}, interfaces=[], vdoms=[])
        assert "fw01" in result


class TestMarkdownVpnDoc:
    def test_renders_tunnels_with_live_status(self):
        tunnels = [{"name": "tunnel1", "interface": "wan1", "remote-gw": "203.0.113.1", "ike-version": "2"}]
        phase2 = [{"name": "selector1", "phase1name": "tunnel1", "src-subnet": "10.0.0.0/24", "dst-subnet": "10.1.0.0/24"}]
        status = [{"name": "tunnel1", "status": "up"}]
        ssl_settings = {"port": 443, "source-interface": [{"name": "wan1"}]}

        result = markdown.generate_vpn_doc("fw01", tunnels, phase2, status, ssl_settings, 2)

        assert "VPN -- fw01" in result
        assert "tunnel1" in result
        assert "203.0.113.1" in result
        assert "| tunnel1 |" in result and "up" in result
        assert "selector1" in result
        assert "10.0.0.0/24" in result and "10.1.0.0/24" in result
        assert "Active sessions: 2" in result

    def test_tunnel_without_live_status_shows_unknown(self):
        tunnels = [{"name": "tunnel1", "interface": "wan1", "remote-gw": "203.0.113.1"}]
        result = markdown.generate_vpn_doc("fw01", tunnels, [], [], {}, 0)
        assert "unknown" in result

    def test_empty_input_does_not_crash(self):
        result = markdown.generate_vpn_doc("fw01", [], [], [], {}, 0)
        assert "none configured" in result.lower()
        assert "Active sessions: 0" in result


class TestMarkdownSystemConfigDoc:
    def test_renders_all_sections(self):
        result = markdown.generate_system_config_doc(
            "fw01",
            dns={"primary": "8.8.8.8", "secondary": "8.8.4.4"},
            ntp={"ntpsync": "enable", "server": "pool.ntp.org"},
            syslog={"status": "enable", "server": "10.0.0.50", "port": 514},
            snmp_sysinfo={"status": "enable"},
            snmp_communities=[{"name": "monitoring"}],
            admins=[{"name": "admin", "accprofile": "super_admin"}],
            ha={"mode": "a-p", "group-id": 10},
            global_settings={"hostname": "fw01", "timezone": "04"},
        )
        assert "System Configuration -- fw01" in result
        assert "8.8.8.8" in result
        assert "pool.ntp.org" in result
        assert "10.0.0.50" in result
        assert "monitoring" in result
        assert "super_admin" in result
        assert "a-p" in result

    def test_empty_input_does_not_crash(self):
        result = markdown.generate_system_config_doc(
            "fw01", dns={}, ntp={}, syslog={}, snmp_sysinfo={}, snmp_communities=[], admins=[], ha={},
            global_settings={},
        )
        assert "System Configuration -- fw01" in result
        assert "none configured" in result.lower()
