"""Tests for change_dispatch, the generic resource-type -> adapter-method table."""
import pytest

from src.fortinet_mcp.adapters.fortios.adapter import FortiOSAdapter
from src.fortinet_mcp.services import change_dispatch


@pytest.fixture
def adapter(mock_fortigate_api):
    return FortiOSAdapter(mock_fortigate_api)


class TestFetchCurrent:
    @pytest.mark.asyncio
    async def test_returns_none_when_resource_id_is_none(self, adapter):
        result = await change_dispatch.fetch_current(adapter, "firewall_policy", None, "root")
        assert result is None

    @pytest.mark.asyncio
    async def test_unwraps_results_dict(self, adapter, mock_fortigate_api):
        result = await change_dispatch.fetch_current(adapter, "firewall_policy", "35", "root")
        assert result["policyid"] == 35
        mock_fortigate_api.get_firewall_policy_detail.assert_awaited_once_with("35", vdom="root")

    @pytest.mark.asyncio
    async def test_returns_none_when_getter_raises(self, adapter, mock_fortigate_api):
        mock_fortigate_api.get_firewall_policy_detail.side_effect = Exception("not found")
        result = await change_dispatch.fetch_current(adapter, "firewall_policy", "999", "root")
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_none_for_resource_type_without_a_getter(self, adapter):
        result = await change_dispatch.fetch_current(adapter, "address_object", "web1", "root")
        assert result is None

    @pytest.mark.asyncio
    async def test_unknown_resource_type_raises(self, adapter):
        with pytest.raises(ValueError, match="Unknown resource_type"):
            await change_dispatch.fetch_current(adapter, "bogus", "1", "root")


class TestExecute:
    @pytest.mark.asyncio
    async def test_create_calls_with_data_only(self, adapter, mock_fortigate_api, sample_policy_data):
        await change_dispatch.execute(adapter, "firewall_policy", "create", None, sample_policy_data, "root")
        mock_fortigate_api.create_firewall_policy.assert_awaited_once_with(sample_policy_data, vdom="root")

    @pytest.mark.asyncio
    async def test_update_calls_with_id_and_data(self, adapter, mock_fortigate_api):
        data = {"action": "deny"}
        await change_dispatch.execute(adapter, "firewall_policy", "update", "35", data, "root")
        mock_fortigate_api.update_firewall_policy.assert_awaited_once_with("35", data, vdom="root")

    @pytest.mark.asyncio
    async def test_delete_calls_with_id_only(self, adapter, mock_fortigate_api):
        await change_dispatch.execute(adapter, "firewall_policy", "delete", "35", None, "root")
        mock_fortigate_api.delete_firewall_policy.assert_awaited_once_with("35", vdom="root")

    @pytest.mark.asyncio
    async def test_unsupported_operation_for_resource_type_raises(self, adapter):
        with pytest.raises(ValueError, match="does not support operation"):
            await change_dispatch.execute(adapter, "address_object", "bogus_op", "web1", {}, "root")


class TestExtractCreatedResourceId:
    def test_extracts_mkey_when_present(self):
        assert change_dispatch.extract_created_resource_id({"status": "success", "mkey": "42"}) == "42"

    def test_returns_none_when_absent(self):
        assert change_dispatch.extract_created_resource_id({"status": "success"}) is None

    def test_returns_none_for_non_dict_response(self):
        assert change_dispatch.extract_created_resource_id("not a dict") is None


class TestListAll:
    @pytest.mark.asyncio
    async def test_lists_policies(self, adapter, mock_fortigate_api):
        result = await change_dispatch.list_all(adapter, "firewall_policy", "root")
        mock_fortigate_api.get_firewall_policies.assert_awaited_once_with(vdom="root")
        assert result == [{"policyid": 1, "name": "Allow_HTTP", "action": "accept"}]

    @pytest.mark.asyncio
    async def test_lists_address_objects(self, adapter, mock_fortigate_api):
        result = await change_dispatch.list_all(adapter, "address_object", None)
        assert result == [{"name": "test_addr", "subnet": "192.168.1.0/24"}]

    @pytest.mark.asyncio
    async def test_unknown_resource_type_raises(self, adapter):
        with pytest.raises(ValueError, match="Unknown resource_type"):
            await change_dispatch.list_all(adapter, "bogus", "root")

    @pytest.mark.asyncio
    async def test_lists_ipsec_phase1(self, adapter, mock_fortigate_api):
        result = await change_dispatch.list_all(adapter, "ipsec_phase1", "root")
        mock_fortigate_api.get_ipsec_phase1_list.assert_awaited_once_with(vdom="root")
        assert result == [{"name": "tunnel1", "interface": "wan1", "remote-gw": "203.0.113.1"}]

    @pytest.mark.asyncio
    async def test_lists_ipsec_phase2(self, adapter, mock_fortigate_api):
        result = await change_dispatch.list_all(adapter, "ipsec_phase2", None)
        assert result == [{"name": "selector1", "phase1name": "tunnel1"}]


class TestIpsecCrudDispatch:
    @pytest.mark.asyncio
    async def test_fetch_current_ipsec_phase1(self, adapter, mock_fortigate_api):
        result = await change_dispatch.fetch_current(adapter, "ipsec_phase1", "tunnel1", "root")
        mock_fortigate_api.get_ipsec_phase1_detail.assert_awaited_once_with("tunnel1", vdom="root")
        assert result == {"name": "tunnel1", "interface": "wan1", "remote-gw": "203.0.113.1"}

    @pytest.mark.asyncio
    async def test_execute_create_ipsec_phase1(self, adapter, mock_fortigate_api):
        data = {"name": "tunnel1", "interface": "wan1", "remote-gw": "203.0.113.1"}
        await change_dispatch.execute(adapter, "ipsec_phase1", "create", None, data, "root")
        mock_fortigate_api.create_ipsec_phase1.assert_awaited_once_with(data, vdom="root")

    @pytest.mark.asyncio
    async def test_execute_update_ipsec_phase1(self, adapter, mock_fortigate_api):
        data = {"remote-gw": "203.0.113.9"}
        await change_dispatch.execute(adapter, "ipsec_phase1", "update", "tunnel1", data, "root")
        mock_fortigate_api.update_ipsec_phase1.assert_awaited_once_with("tunnel1", data, vdom="root")

    @pytest.mark.asyncio
    async def test_execute_delete_ipsec_phase1(self, adapter, mock_fortigate_api):
        await change_dispatch.execute(adapter, "ipsec_phase1", "delete", "tunnel1", None, "root")
        mock_fortigate_api.delete_ipsec_phase1.assert_awaited_once_with("tunnel1", vdom="root")

    @pytest.mark.asyncio
    async def test_execute_create_ipsec_phase2(self, adapter, mock_fortigate_api):
        data = {"name": "selector1", "phase1name": "tunnel1"}
        await change_dispatch.execute(adapter, "ipsec_phase2", "create", None, data, "root")
        mock_fortigate_api.create_ipsec_phase2.assert_awaited_once_with(data, vdom="root")


class TestSingletonResourceDispatch:
    """dns/ntp/syslog/snmp_sysinfo/system_global/ha have no id -- resource_id
    is always None for them, which must NOT be treated as the "nothing to
    diff, this is a CREATE" shortcut that applies to keyed resources."""

    @pytest.mark.asyncio
    async def test_fetch_current_still_fetches_with_none_resource_id(self, adapter, mock_fortigate_api):
        result = await change_dispatch.fetch_current(adapter, "dns", None, "root")
        mock_fortigate_api.get_dns_settings.assert_awaited_once_with(vdom="root")
        assert result == {"primary": "8.8.8.8", "secondary": "8.8.4.4"}

    @pytest.mark.asyncio
    async def test_fetch_current_returns_none_when_getter_raises(self, adapter, mock_fortigate_api):
        mock_fortigate_api.get_ha_config.side_effect = Exception("boom")
        result = await change_dispatch.fetch_current(adapter, "ha", None, "root")
        assert result is None

    @pytest.mark.asyncio
    async def test_execute_update_calls_without_id(self, adapter, mock_fortigate_api):
        data = {"primary": "1.1.1.1"}
        await change_dispatch.execute(adapter, "dns", "update", None, data, "root")
        mock_fortigate_api.update_dns_settings.assert_awaited_once_with(data, vdom="root")

    @pytest.mark.asyncio
    async def test_create_not_supported_for_singleton(self, adapter):
        with pytest.raises(ValueError, match="does not support operation"):
            await change_dispatch.execute(adapter, "dns", "create", None, {}, "root")

    @pytest.mark.asyncio
    async def test_delete_not_supported_for_singleton(self, adapter):
        with pytest.raises(ValueError, match="does not support operation"):
            await change_dispatch.execute(adapter, "ha", "delete", None, None, "root")

    @pytest.mark.parametrize(
        "resource_type,getter_name",
        [
            ("dns", "get_dns_settings"),
            ("ntp", "get_ntp_settings"),
            ("syslog", "get_syslog_settings"),
            ("snmp_sysinfo", "get_snmp_sysinfo"),
            ("system_global", "get_system_global"),
            ("ha", "get_ha_config"),
        ],
    )
    @pytest.mark.asyncio
    async def test_all_singleton_types_fetch_without_id(
        self, adapter, mock_fortigate_api, resource_type, getter_name
    ):
        await change_dispatch.fetch_current(adapter, resource_type, None, None)
        getattr(mock_fortigate_api, getter_name).assert_awaited_once_with(vdom=None)


class TestKeyedSystemResourceDispatch:
    @pytest.mark.asyncio
    async def test_fetch_current_snmp_community(self, adapter, mock_fortigate_api):
        result = await change_dispatch.fetch_current(adapter, "snmp_community", "1", "root")
        mock_fortigate_api.get_snmp_community_detail.assert_awaited_once_with("1", vdom="root")
        assert result == {"id": 1, "name": "public"}

    @pytest.mark.asyncio
    async def test_execute_create_admin(self, adapter, mock_fortigate_api):
        data = {"name": "svc-account", "password": "s3cr3t"}
        await change_dispatch.execute(adapter, "admin", "create", None, data, "root")
        mock_fortigate_api.create_admin.assert_awaited_once_with(data, vdom="root")

    @pytest.mark.asyncio
    async def test_execute_delete_admin(self, adapter, mock_fortigate_api):
        await change_dispatch.execute(adapter, "admin", "delete", "svc-account", None, "root")
        mock_fortigate_api.delete_admin.assert_awaited_once_with("svc-account", vdom="root")


class TestVdomLifecycleDispatch:
    """vdom/vdom_link are global (not vdom-scoped) but still dispatch through
    the generic keyed-CRUD path with a vdom kwarg that the adapter methods
    accept-but-ignore (see adapters/base.py)."""

    @pytest.mark.asyncio
    async def test_execute_create_vdom(self, adapter, mock_fortigate_api):
        data = {"name": "Alfa"}
        await change_dispatch.execute(adapter, "vdom", "create", None, data, None)
        mock_fortigate_api.create_vdom.assert_awaited_once_with(data)

    @pytest.mark.asyncio
    async def test_execute_delete_vdom(self, adapter, mock_fortigate_api):
        await change_dispatch.execute(adapter, "vdom", "delete", "Alfa", None, None)
        mock_fortigate_api.delete_vdom.assert_awaited_once_with("Alfa")

    @pytest.mark.asyncio
    async def test_vdom_has_no_update_operation(self, adapter):
        with pytest.raises(ValueError, match="does not support operation"):
            await change_dispatch.execute(adapter, "vdom", "update", "Alfa", {}, None)

    @pytest.mark.asyncio
    async def test_execute_create_vdom_link(self, adapter, mock_fortigate_api):
        data = {"name": "link1"}
        await change_dispatch.execute(adapter, "vdom_link", "create", None, data, None)
        mock_fortigate_api.create_vdom_link.assert_awaited_once_with(data)

    @pytest.mark.asyncio
    async def test_fetch_current_vdom_link(self, adapter, mock_fortigate_api):
        result = await change_dispatch.fetch_current(adapter, "vdom_link", "link1", None)
        mock_fortigate_api.get_vdom_link_detail.assert_awaited_once_with("link1")
        assert result == {"name": "link1", "vcluster2": "disable"}

    @pytest.mark.asyncio
    async def test_execute_delete_vdom_link(self, adapter, mock_fortigate_api):
        await change_dispatch.execute(adapter, "vdom_link", "delete", "link1", None, None)
        mock_fortigate_api.delete_vdom_link.assert_awaited_once_with("link1")


class TestInterfaceZoneDhcpDispatch:
    @pytest.mark.asyncio
    async def test_fetch_current_interface(self, adapter, mock_fortigate_api):
        result = await change_dispatch.fetch_current(adapter, "interface", "vlan100", "root")
        mock_fortigate_api.get_interface_detail.assert_awaited_once_with("vlan100", vdom="root")
        assert result["name"] == "vlan100"

    @pytest.mark.asyncio
    async def test_execute_create_interface(self, adapter, mock_fortigate_api):
        data = {"name": "vlan100", "type": "vlan", "interface": "port1", "vlanid": 100}
        await change_dispatch.execute(adapter, "interface", "create", None, data, "root")
        mock_fortigate_api.create_interface.assert_awaited_once_with(data, vdom="root")

    @pytest.mark.asyncio
    async def test_execute_update_interface(self, adapter, mock_fortigate_api):
        data = {"ip": "10.0.0.1 255.255.255.0"}
        await change_dispatch.execute(adapter, "interface", "update", "vlan100", data, "root")
        mock_fortigate_api.update_interface.assert_awaited_once_with("vlan100", data, vdom="root")

    @pytest.mark.asyncio
    async def test_execute_delete_interface(self, adapter, mock_fortigate_api):
        await change_dispatch.execute(adapter, "interface", "delete", "vlan100", None, "root")
        mock_fortigate_api.delete_interface.assert_awaited_once_with("vlan100", vdom="root")

    @pytest.mark.asyncio
    async def test_list_all_zones(self, adapter, mock_fortigate_api):
        result = await change_dispatch.list_all(adapter, "zone", "root")
        mock_fortigate_api.get_zones.assert_awaited_once_with(vdom="root")
        assert result == [{"name": "dmz", "interface": [{"interface-name": "port2"}]}]

    @pytest.mark.asyncio
    async def test_execute_create_zone(self, adapter, mock_fortigate_api):
        data = {"name": "dmz", "interface": [{"interface-name": "port2"}]}
        await change_dispatch.execute(adapter, "zone", "create", None, data, "root")
        mock_fortigate_api.create_zone.assert_awaited_once_with(data, vdom="root")

    @pytest.mark.asyncio
    async def test_fetch_current_dhcp_server(self, adapter, mock_fortigate_api):
        result = await change_dispatch.fetch_current(adapter, "dhcp_server", "1", "root")
        mock_fortigate_api.get_dhcp_server_detail.assert_awaited_once_with("1", vdom="root")
        assert result == {"id": 1, "interface": "vlan100"}

    @pytest.mark.asyncio
    async def test_execute_create_dhcp_server(self, adapter, mock_fortigate_api):
        data = {"interface": "vlan100", "ip-range": [{"start-ip": "10.0.0.10", "end-ip": "10.0.0.100"}]}
        await change_dispatch.execute(adapter, "dhcp_server", "create", None, data, "root")
        mock_fortigate_api.create_dhcp_server.assert_awaited_once_with(data, vdom="root")

    @pytest.mark.asyncio
    async def test_execute_delete_dhcp_server(self, adapter, mock_fortigate_api):
        await change_dispatch.execute(adapter, "dhcp_server", "delete", "1", None, "root")
        mock_fortigate_api.delete_dhcp_server.assert_awaited_once_with("1", vdom="root")
