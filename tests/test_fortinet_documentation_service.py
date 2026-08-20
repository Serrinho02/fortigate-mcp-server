"""
Tests for DocumentationService: wiring device resolution + adapter fetch
into the pure docsgen functions, using the same mock_fortigate_api fixture
as the other Service-layer tests.
"""
import pytest

from src.fortinet_mcp.services.documentation_service import DocumentationService


@pytest.fixture
def service(fortigate_manager):
    return DocumentationService(fortigate_manager)


@pytest.fixture
def registered(fortigate_manager, mock_fortigate_api):
    fortigate_manager.devices["test_device"] = mock_fortigate_api
    return mock_fortigate_api


class TestGenerateTopology:
    @pytest.mark.asyncio
    async def test_mermaid_format_default(self, service, registered):
        result = await service.generate_topology("test_device")
        assert "flowchart LR" in result[0].text

    @pytest.mark.asyncio
    async def test_drawio_format(self, service, registered):
        result = await service.generate_topology("test_device", diagram_format="drawio")
        assert "mxfile" in result[0].text

    @pytest.mark.asyncio
    async def test_plantuml_format(self, service, registered):
        result = await service.generate_topology("test_device", diagram_format="plantuml")
        assert "@startuml" in result[0].text

    @pytest.mark.asyncio
    async def test_invalid_format_returns_formatted_error(self, service, registered):
        result = await service.generate_topology("test_device", diagram_format="svg")
        assert "error" in result[0].text.lower() or "unknown" in result[0].text.lower()

    @pytest.mark.asyncio
    async def test_unknown_device_returns_formatted_error(self, service):
        result = await service.generate_topology("nope")
        assert "not found" in result[0].text.lower() or "error" in result[0].text.lower()


class TestGeneratePolicyDoc:
    @pytest.mark.asyncio
    async def test_renders_live_policies(self, service, registered):
        result = await service.generate_policy_doc("test_device", vdom="root")
        registered.get_firewall_policies.assert_awaited_once_with(vdom="root")
        assert "Allow_HTTP" in result[0].text


class TestGenerateRoutingDoc:
    @pytest.mark.asyncio
    async def test_renders_live_routes_and_table(self, service, registered):
        result = await service.generate_routing_doc("test_device")
        registered.get_static_routes.assert_awaited_once_with(vdom=None)
        registered.get_routing_table.assert_awaited_once_with(vdom=None)
        assert "10.0.0.0/8" in result[0].text


class TestGenerateSystemConfigDoc:
    @pytest.mark.asyncio
    async def test_renders_live_system_settings(self, service, registered):
        result = await service.generate_system_config_doc("test_device")
        registered.get_dns_settings.assert_awaited_once_with(vdom=None)
        registered.get_ha_config.assert_awaited_once_with(vdom=None)

        text = result[0].text
        assert "System Configuration -- test_device" in text
        assert "8.8.8.8" in text  # DNS primary from mock
        assert "public" in text  # SNMP community from mock

    @pytest.mark.asyncio
    async def test_degrades_gracefully_when_a_field_fetch_fails(self, service, registered):
        registered.get_ntp_settings.side_effect = Exception("boom")
        result = await service.generate_system_config_doc("test_device")
        assert "error" not in result[0].text.lower()


class TestExportMarkdown:
    @pytest.mark.asyncio
    async def test_combines_device_policy_and_routing_sections(self, service, registered):
        result = await service.export_markdown("test_device")
        text = result[0].text
        assert "Device Documentation" in text
        assert "Firewall Policies" in text
        assert "Routing --" in text
        assert "FortiGate" in text  # hostname from mock system status

    @pytest.mark.asyncio
    async def test_includes_system_config_section(self, service, registered):
        result = await service.export_markdown("test_device")
        text = result[0].text
        assert "System Configuration --" in text
        assert "8.8.8.8" in text  # DNS primary from mock


class TestGenerateVpnDoc:
    @pytest.mark.asyncio
    async def test_renders_ipsec_and_ssl_vpn_sections(self, service, registered):
        result = await service.generate_vpn_doc("test_device", vdom="root")

        registered.get_ipsec_phase1_list.assert_awaited_once_with(vdom="root")
        registered.get_ipsec_phase2_list.assert_awaited_once_with(vdom="root")
        registered.get_ipsec_tunnel_status.assert_awaited_once_with(vdom="root")
        registered.get_ssl_vpn_settings.assert_awaited_once_with(vdom="root")
        registered.get_ssl_vpn_sessions.assert_awaited_once_with(vdom="root")

        text = result[0].text
        assert "VPN -- test_device" in text
        assert "tunnel1" in text
        assert "203.0.113.1" in text
