"""
Pytest configuration and fixtures for FortiGate MCP server tests.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock

from src.fortigate_mcp.core.fortigate import FortiGateManager, FortiGateAPI
from src.fortigate_mcp.config.models import FortiGateDeviceConfig, AuthConfig


@pytest.fixture
def auth_config():
    """Default auth configuration fixture."""
    return AuthConfig(require_auth=False, api_tokens=[], allowed_origins=[])


@pytest.fixture
def fortigate_manager(auth_config):
    """FortiGate manager fixture with no devices."""
    manager = FortiGateManager({}, auth_config)
    yield manager
    manager.devices.clear()


@pytest.fixture
def device_config():
    """Sample device configuration fixture."""
    return FortiGateDeviceConfig(
        host="192.168.1.1",
        username="admin",
        password="password",
        vdom="root",
        verify_ssl=False,
        timeout=30,
        port=443
    )


@pytest.fixture
def mock_fortigate_api():
    """Mock FortiGate API fixture with AsyncMock methods."""
    mock_api = MagicMock(spec=FortiGateAPI)
    mock_api.device_id = "test_device"

    # Mock config attribute
    mock_config = MagicMock()
    mock_config.host = "192.168.1.1"
    mock_config.vdom = "root"
    mock_api.config = mock_config
    mock_api.auth_method = "basic"

    # All API methods are now async - use AsyncMock
    mock_api.test_connection = AsyncMock(return_value=True)
    mock_api.close = AsyncMock()

    mock_api.get_system_status = AsyncMock(return_value={
        "hostname": "FortiGate",
        "version": "v7.0.0",
        "status": "ok"
    })

    mock_api.get_vdoms = AsyncMock(return_value={
        "results": [{"name": "root", "enabled": True}]
    })

    mock_api.get_interfaces = AsyncMock(return_value={
        "results": [
            {"name": "port1", "status": "up"},
            {"name": "port2", "status": "down"}
        ]
    })

    mock_api.get_interface_status = AsyncMock(return_value={
        "results": {"name": "port1", "status": "up", "ip": "192.168.1.1"}
    })

    mock_api.get_firewall_policies = AsyncMock(return_value={
        "results": [{"policyid": 1, "name": "Allow_HTTP", "action": "accept"}]
    })

    mock_api.get_firewall_policy_detail = AsyncMock(return_value={
        "results": {
            "policyid": 35,
            "name": "WAN->ManDown-Project",
            "srcintf": [{"name": "wan1"}],
            "dstintf": [{"name": "internal"}],
            "srcaddr": [{"name": "all"}],
            "dstaddr": [{"name": "Yartu-1-TCP"}],
            "service": [{"name": "ALL"}],
            "action": "accept",
            "status": "enable"
        }
    })

    mock_api.create_firewall_policy = AsyncMock(return_value={"status": "success"})
    mock_api.update_firewall_policy = AsyncMock(return_value={"status": "success"})
    mock_api.delete_firewall_policy = AsyncMock(return_value={"status": "success"})

    mock_api.get_address_objects = AsyncMock(return_value={
        "results": [{"name": "test_addr", "subnet": "192.168.1.0/24"}]
    })
    mock_api.create_address_object = AsyncMock(return_value={"status": "success"})

    mock_api.get_service_objects = AsyncMock(return_value={
        "results": [{"name": "HTTP", "tcp-portrange": "80"}]
    })
    mock_api.create_service_object = AsyncMock(return_value={"status": "success"})

    mock_api.get_static_routes = AsyncMock(return_value={
        "results": [{"dst": "10.0.0.0/8", "gateway": "192.168.1.1"}]
    })
    mock_api.create_static_route = AsyncMock(return_value={"status": "success"})
    mock_api.update_static_route = AsyncMock(return_value={"status": "success"})
    mock_api.delete_static_route = AsyncMock(return_value={"status": "success"})
    mock_api.get_static_route_detail = AsyncMock(return_value={
        "results": {"seq-num": 1, "dst": "10.0.0.0/8", "gateway": "192.168.1.1"}
    })

    mock_api.get_routing_table = AsyncMock(return_value={
        "results": [{"dst": "0.0.0.0/0", "gateway": "192.168.1.1"}]
    })

    mock_api.get_virtual_ips = AsyncMock(return_value={
        "results": [{"name": "test_vip", "extip": "1.2.3.4", "mappedip": "10.0.0.1"}]
    })
    mock_api.create_virtual_ip = AsyncMock(return_value={"status": "success"})
    mock_api.update_virtual_ip = AsyncMock(return_value={"status": "success"})
    mock_api.delete_virtual_ip = AsyncMock(return_value={"status": "success"})
    mock_api.get_virtual_ip_detail = AsyncMock(return_value={
        "results": {"name": "test_vip", "extip": "1.2.3.4", "mappedip": "10.0.0.1"}
    })

    mock_api.get_ipsec_phase1_list = AsyncMock(return_value={
        "results": [{"name": "tunnel1", "interface": "wan1", "remote-gw": "203.0.113.1"}]
    })
    mock_api.get_ipsec_phase1_detail = AsyncMock(return_value={
        "results": {"name": "tunnel1", "interface": "wan1", "remote-gw": "203.0.113.1"}
    })
    mock_api.create_ipsec_phase1 = AsyncMock(return_value={"status": "success"})
    mock_api.update_ipsec_phase1 = AsyncMock(return_value={"status": "success"})
    mock_api.delete_ipsec_phase1 = AsyncMock(return_value={"status": "success"})

    mock_api.get_ipsec_phase2_list = AsyncMock(return_value={
        "results": [{"name": "selector1", "phase1name": "tunnel1"}]
    })
    mock_api.get_ipsec_phase2_detail = AsyncMock(return_value={
        "results": {"name": "selector1", "phase1name": "tunnel1"}
    })
    mock_api.create_ipsec_phase2 = AsyncMock(return_value={"status": "success"})
    mock_api.update_ipsec_phase2 = AsyncMock(return_value={"status": "success"})
    mock_api.delete_ipsec_phase2 = AsyncMock(return_value={"status": "success"})

    mock_api.get_ipsec_tunnel_status = AsyncMock(return_value={
        "results": [{"name": "tunnel1", "status": "up"}]
    })
    mock_api.get_ssl_vpn_settings = AsyncMock(return_value={
        "results": {"port": 443, "source-interface": [{"name": "wan1"}]}
    })
    mock_api.update_ssl_vpn_settings = AsyncMock(return_value={"status": "success"})
    mock_api.get_ssl_vpn_sessions = AsyncMock(return_value={"results": []})

    mock_api.get_dns_settings = AsyncMock(return_value={
        "results": {"primary": "8.8.8.8", "secondary": "8.8.4.4"}
    })
    mock_api.update_dns_settings = AsyncMock(return_value={"status": "success"})

    mock_api.get_ntp_settings = AsyncMock(return_value={
        "results": {"ntpsync": "enable", "server": []}
    })
    mock_api.update_ntp_settings = AsyncMock(return_value={"status": "success"})

    mock_api.get_syslog_settings = AsyncMock(return_value={
        "results": {"status": "enable", "server": "10.0.0.50", "port": 514}
    })
    mock_api.update_syslog_settings = AsyncMock(return_value={"status": "success"})

    mock_api.get_snmp_sysinfo = AsyncMock(return_value={
        "results": {"status": "enable", "description": "FortiGate"}
    })
    mock_api.update_snmp_sysinfo = AsyncMock(return_value={"status": "success"})
    mock_api.get_snmp_communities = AsyncMock(return_value={
        "results": [{"id": 1, "name": "public"}]
    })
    mock_api.get_snmp_community_detail = AsyncMock(return_value={
        "results": {"id": 1, "name": "public"}
    })
    mock_api.create_snmp_community = AsyncMock(return_value={"status": "success"})
    mock_api.update_snmp_community = AsyncMock(return_value={"status": "success"})
    mock_api.delete_snmp_community = AsyncMock(return_value={"status": "success"})

    mock_api.get_system_global = AsyncMock(return_value={
        "results": {"hostname": "FortiGate", "timezone": "04"}
    })
    mock_api.update_system_global = AsyncMock(return_value={"status": "success"})

    mock_api.list_admins = AsyncMock(return_value={
        "results": [{"name": "admin", "accprofile": "super_admin"}]
    })
    mock_api.get_admin_detail = AsyncMock(return_value={
        "results": {"name": "admin", "accprofile": "super_admin"}
    })
    mock_api.create_admin = AsyncMock(return_value={"status": "success"})
    mock_api.update_admin = AsyncMock(return_value={"status": "success"})
    mock_api.delete_admin = AsyncMock(return_value={"status": "success"})

    mock_api.get_ha_config = AsyncMock(return_value={
        "results": {"mode": "standalone", "group-id": 0}
    })
    mock_api.update_ha_config = AsyncMock(return_value={"status": "success"})

    mock_api.create_vdom = AsyncMock(return_value={"status": "success", "mkey": "vdom-alfa"})
    mock_api.delete_vdom = AsyncMock(return_value={"status": "success"})
    mock_api.get_vdom_links = AsyncMock(return_value={
        "results": [{"name": "link1", "vcluster2": "disable"}]
    })
    mock_api.get_vdom_link_detail = AsyncMock(return_value={
        "results": {"name": "link1", "vcluster2": "disable"}
    })
    mock_api.create_vdom_link = AsyncMock(return_value={"status": "success", "mkey": "link1"})
    mock_api.delete_vdom_link = AsyncMock(return_value={"status": "success"})

    mock_api.get_interface_detail = AsyncMock(return_value={
        "results": {"name": "vlan100", "vdom": "root", "ip": "10.0.0.1 255.255.255.0"}
    })
    mock_api.create_interface = AsyncMock(return_value={"status": "success", "mkey": "vlan100"})
    mock_api.update_interface = AsyncMock(return_value={"status": "success"})
    mock_api.delete_interface = AsyncMock(return_value={"status": "success"})

    mock_api.get_zones = AsyncMock(return_value={
        "results": [{"name": "dmz", "interface": [{"interface-name": "port2"}]}]
    })
    mock_api.get_zone_detail = AsyncMock(return_value={
        "results": {"name": "dmz", "interface": [{"interface-name": "port2"}]}
    })
    mock_api.create_zone = AsyncMock(return_value={"status": "success", "mkey": "dmz"})
    mock_api.update_zone = AsyncMock(return_value={"status": "success"})
    mock_api.delete_zone = AsyncMock(return_value={"status": "success"})

    mock_api.get_dhcp_servers = AsyncMock(return_value={
        "results": [{"id": 1, "interface": "vlan100"}]
    })
    mock_api.get_dhcp_server_detail = AsyncMock(return_value={
        "results": {"id": 1, "interface": "vlan100"}
    })
    mock_api.create_dhcp_server = AsyncMock(return_value={"status": "success", "mkey": "2"})
    mock_api.update_dhcp_server = AsyncMock(return_value={"status": "success"})
    mock_api.delete_dhcp_server = AsyncMock(return_value={"status": "success"})

    return mock_api


@pytest.fixture
def sample_policy_data():
    """Sample policy data fixture."""
    return {
        "name": "Test_Policy",
        "srcintf": [{"name": "port1"}],
        "dstintf": [{"name": "port2"}],
        "srcaddr": [{"name": "all"}],
        "dstaddr": [{"name": "all"}],
        "service": [{"name": "ALL"}],
        "action": "accept",
        "schedule": "always",
        "comments": "Test policy created by pytest"
    }
