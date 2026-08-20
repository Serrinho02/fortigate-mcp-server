"""
Tests for the new fortinet_mcp adapter layer (Phase 0 of the platform
rewrite). These are additive: they do not modify any existing test and
exercise only the new `src.fortinet_mcp.adapters` package.
"""
import pytest

from src.fortinet_mcp.adapters.base import Capability, FortinetProductAdapter
from src.fortinet_mcp.adapters.fortios.adapter import FortiOSAdapter
from src.fortinet_mcp.adapters.fortios.factory import (
    build_fortios_adapter,
    register_fortios_adapter,
)
from src.fortinet_mcp.adapters.registry import AdapterRegistry


class TestFortiOSAdapterProtocolConformance:
    def test_implements_fortinet_product_adapter_protocol(self, mock_fortigate_api):
        adapter = FortiOSAdapter(mock_fortigate_api)
        assert isinstance(adapter, FortinetProductAdapter)

    def test_product_type_is_fortios(self, mock_fortigate_api):
        adapter = FortiOSAdapter(mock_fortigate_api)
        assert adapter.product_type == "fortios"

    def test_capabilities_covers_all_resource_types(self, mock_fortigate_api):
        adapter = FortiOSAdapter(mock_fortigate_api)
        caps = adapter.capabilities()
        assert caps == frozenset(Capability)


class TestFortiOSAdapterDelegation:
    """Verify the adapter is a pure delegate: same args in, same result out,
    zero data transformation versus calling FortiGateAPI directly."""

    @pytest.mark.asyncio
    async def test_test_connection_delegates(self, mock_fortigate_api):
        adapter = FortiOSAdapter(mock_fortigate_api)
        result = await adapter.test_connection()
        assert result is True
        mock_fortigate_api.test_connection.assert_awaited_once_with()

    @pytest.mark.asyncio
    async def test_close_delegates(self, mock_fortigate_api):
        adapter = FortiOSAdapter(mock_fortigate_api)
        await adapter.close()
        mock_fortigate_api.close.assert_awaited_once_with()

    @pytest.mark.asyncio
    async def test_get_status_delegates_with_vdom(self, mock_fortigate_api):
        adapter = FortiOSAdapter(mock_fortigate_api)
        result = await adapter.get_status(vdom="customer_a")
        assert result == {"hostname": "FortiGate", "version": "v7.0.0", "status": "ok"}
        mock_fortigate_api.get_system_status.assert_awaited_once_with(vdom="customer_a")

    @pytest.mark.asyncio
    async def test_list_policies_delegates(self, mock_fortigate_api):
        adapter = FortiOSAdapter(mock_fortigate_api)
        result = await adapter.list_policies(vdom="root")
        assert result == {"results": [{"policyid": 1, "name": "Allow_HTTP", "action": "accept"}]}
        mock_fortigate_api.get_firewall_policies.assert_awaited_once_with(vdom="root")

    @pytest.mark.asyncio
    async def test_create_policy_delegates_with_same_payload(self, mock_fortigate_api, sample_policy_data):
        adapter = FortiOSAdapter(mock_fortigate_api)
        result = await adapter.create_policy(sample_policy_data, vdom="root")
        assert result == {"status": "success"}
        mock_fortigate_api.create_firewall_policy.assert_awaited_once_with(
            sample_policy_data, vdom="root"
        )

    @pytest.mark.asyncio
    async def test_delete_policy_delegates(self, mock_fortigate_api):
        adapter = FortiOSAdapter(mock_fortigate_api)
        await adapter.delete_policy("35", vdom="root")
        mock_fortigate_api.delete_firewall_policy.assert_awaited_once_with("35", vdom="root")

    @pytest.mark.asyncio
    async def test_create_address_object_delegates(self, mock_fortigate_api):
        adapter = FortiOSAdapter(mock_fortigate_api)
        data = {"name": "test_addr", "subnet": "192.168.1.0/24"}
        result = await adapter.create_address_object(data)
        assert result == {"status": "success"}
        mock_fortigate_api.create_address_object.assert_awaited_once_with(data, vdom=None)

    @pytest.mark.asyncio
    async def test_get_routing_table_delegates(self, mock_fortigate_api):
        adapter = FortiOSAdapter(mock_fortigate_api)
        result = await adapter.get_routing_table(vdom="root")
        assert result == {"results": [{"dst": "0.0.0.0/0", "gateway": "192.168.1.1"}]}
        mock_fortigate_api.get_routing_table.assert_awaited_once_with(vdom="root")

    @pytest.mark.asyncio
    async def test_delete_virtual_ip_delegates(self, mock_fortigate_api):
        adapter = FortiOSAdapter(mock_fortigate_api)
        await adapter.delete_virtual_ip("test_vip", vdom="root")
        mock_fortigate_api.delete_virtual_ip.assert_awaited_once_with("test_vip", vdom="root")

    @pytest.mark.asyncio
    async def test_list_vdoms_delegates(self, mock_fortigate_api):
        adapter = FortiOSAdapter(mock_fortigate_api)
        result = await adapter.list_vdoms()
        assert result == {"results": [{"name": "root", "enabled": True}]}
        mock_fortigate_api.get_vdoms.assert_awaited_once_with()

    @pytest.mark.asyncio
    async def test_list_ipsec_phase1_delegates(self, mock_fortigate_api):
        adapter = FortiOSAdapter(mock_fortigate_api)
        await adapter.list_ipsec_phase1(vdom="root")
        mock_fortigate_api.get_ipsec_phase1_list.assert_awaited_once_with(vdom="root")

    @pytest.mark.asyncio
    async def test_create_ipsec_phase1_delegates(self, mock_fortigate_api):
        adapter = FortiOSAdapter(mock_fortigate_api)
        data = {"name": "tunnel1", "interface": "wan1", "remote-gw": "203.0.113.1"}
        await adapter.create_ipsec_phase1(data)
        mock_fortigate_api.create_ipsec_phase1.assert_awaited_once_with(data, vdom=None)

    @pytest.mark.asyncio
    async def test_update_ipsec_phase1_delegates(self, mock_fortigate_api):
        adapter = FortiOSAdapter(mock_fortigate_api)
        data = {"remote-gw": "203.0.113.2"}
        await adapter.update_ipsec_phase1("tunnel1", data, vdom="root")
        mock_fortigate_api.update_ipsec_phase1.assert_awaited_once_with("tunnel1", data, vdom="root")

    @pytest.mark.asyncio
    async def test_delete_ipsec_phase1_delegates(self, mock_fortigate_api):
        adapter = FortiOSAdapter(mock_fortigate_api)
        await adapter.delete_ipsec_phase1("tunnel1")
        mock_fortigate_api.delete_ipsec_phase1.assert_awaited_once_with("tunnel1", vdom=None)

    @pytest.mark.asyncio
    async def test_list_ipsec_phase2_delegates(self, mock_fortigate_api):
        adapter = FortiOSAdapter(mock_fortigate_api)
        await adapter.list_ipsec_phase2()
        mock_fortigate_api.get_ipsec_phase2_list.assert_awaited_once_with(vdom=None)

    @pytest.mark.asyncio
    async def test_create_ipsec_phase2_delegates(self, mock_fortigate_api):
        adapter = FortiOSAdapter(mock_fortigate_api)
        data = {"name": "selector1", "phase1name": "tunnel1"}
        await adapter.create_ipsec_phase2(data)
        mock_fortigate_api.create_ipsec_phase2.assert_awaited_once_with(data, vdom=None)

    @pytest.mark.asyncio
    async def test_get_ipsec_tunnel_status_delegates(self, mock_fortigate_api):
        adapter = FortiOSAdapter(mock_fortigate_api)
        result = await adapter.get_ipsec_tunnel_status()
        assert result == {"results": [{"name": "tunnel1", "status": "up"}]}
        mock_fortigate_api.get_ipsec_tunnel_status.assert_awaited_once_with(vdom=None)

    @pytest.mark.asyncio
    async def test_get_ssl_vpn_settings_delegates(self, mock_fortigate_api):
        adapter = FortiOSAdapter(mock_fortigate_api)
        await adapter.get_ssl_vpn_settings()
        mock_fortigate_api.get_ssl_vpn_settings.assert_awaited_once_with(vdom=None)

    @pytest.mark.asyncio
    async def test_get_ssl_vpn_sessions_delegates(self, mock_fortigate_api):
        adapter = FortiOSAdapter(mock_fortigate_api)
        await adapter.get_ssl_vpn_sessions()
        mock_fortigate_api.get_ssl_vpn_sessions.assert_awaited_once_with(vdom=None)


class TestAdapterRegistry:
    def test_register_and_create_returns_adapter_instance(self, mock_fortigate_api):
        registry = AdapterRegistry()
        register_fortios_adapter(registry)

        adapter = registry.create("fortios", mock_fortigate_api)

        assert isinstance(adapter, FortiOSAdapter)
        assert adapter.product_type == "fortios"

    def test_known_product_types(self):
        registry = AdapterRegistry()
        register_fortios_adapter(registry)
        assert registry.known_product_types() == ["fortios"]

    def test_duplicate_registration_raises(self):
        registry = AdapterRegistry()
        register_fortios_adapter(registry)
        with pytest.raises(ValueError, match="already registered"):
            register_fortios_adapter(registry)

    def test_unknown_product_type_raises_with_known_types_listed(self, mock_fortigate_api):
        registry = AdapterRegistry()
        register_fortios_adapter(registry)
        with pytest.raises(ValueError, match="fortimanager"):
            registry.create("fortimanager", mock_fortigate_api)

    def test_build_fortios_adapter_factory(self, mock_fortigate_api):
        adapter = build_fortios_adapter(mock_fortigate_api)
        assert isinstance(adapter, FortiOSAdapter)
