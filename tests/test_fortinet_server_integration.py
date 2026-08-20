"""
Smoke tests: the legacy stdio/HTTP server entrypoints still construct and
register their full tool set correctly now that the Phase 1
inventory.*/connection.* tools and the Phase 3 change.* tools are wired in
alongside the existing ones. No real device config, no real DB file, no
real OS keyring involved.
"""
import json

import pytest

from src.fortigate_mcp.server import FortiGateMCPServer
from src.fortigate_mcp.server_http import FortiGateMCPHTTPServer

NEW_TOOL_NAMES = {
    "inventory_list_customers",
    "inventory_list_sites",
    "inventory_list_devices",
    "inventory_register_device_pending",
    "inventory_remove_device",
    "connection_connect",
    "connection_list_active",
    "connection_resolve",
    "connection_disconnect",
    "change_apply",
    "change_rollback",
    "change_list_pending",
    "change_history",
    "analysis_find_duplicate_policies",
    "analysis_find_shadowed_policies",
    "analysis_find_any_any",
    "analysis_find_unused_objects",
    "analysis_find_overlapping_subnets",
    "analysis_check_best_practices",
    "analysis_score_security",
    "analysis_compliance_report",
    "doc_generate_topology",
    "doc_generate_policy_doc",
    "doc_generate_routing_doc",
    "doc_export_markdown",
    "doc_generate_vpn_doc",
    "fleet_compare_devices",
    "fleet_search_object",
    "fleet_sync_objects",
    "fleet_replicate_config",
    "fleet_report",
    "intent_create_policy",
    "intent_explain_policy_failure",
    "intent_summarize_device",
    "intent_find_path",
    "vpn_list_ipsec_tunnels",
    "vpn_get_ipsec_tunnel_detail",
    "vpn_create_ipsec_tunnel",
    "vpn_update_ipsec_tunnel",
    "vpn_delete_ipsec_tunnel",
    "vpn_list_ipsec_phase2",
    "vpn_create_ipsec_phase2",
    "vpn_update_ipsec_phase2",
    "vpn_delete_ipsec_phase2",
    "vpn_get_ipsec_status",
    "vpn_get_ssl_vpn_settings",
    "vpn_list_ssl_vpn_sessions",
}

LEGACY_TOOL_NAMES = {
    "list_devices",
    "add_device",
    "remove_device",
    "list_firewall_policies",
    "create_firewall_policy",
}


@pytest.fixture
def empty_config_file(tmp_path):
    config = {
        "server": {"host": "0.0.0.0", "port": 8814, "name": "test", "version": "1.0.0"},
        "fortigate": {"devices": {}},
        "auth": {"require_auth": False, "api_tokens": [], "allowed_origins": []},
        "logging": {"level": "INFO", "console": True},
        "rate_limiting": {"enabled": True, "max_requests_per_minute": 60, "burst_size": 10},
    }
    path = tmp_path / "config.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    return str(path)


@pytest.fixture(autouse=True)
def isolated_inventory_db(tmp_path, monkeypatch):
    db_path = tmp_path / "inventory.db"
    monkeypatch.setenv("FORTINET_MCP_DB_URL", f"sqlite+aiosqlite:///{db_path.as_posix()}")


class TestStdioServerToolRegistration:
    def test_server_constructs_with_new_infra_components(self, empty_config_file):
        server = FortiGateMCPServer(empty_config_file)

        assert server.connection_manager is not None
        assert server.credential_manager is not None
        assert server.adapter_registry.known_product_types() == ["fortios"]
        assert server.change_service is not None
        assert server.mode_policy is not None

    @pytest.mark.asyncio
    async def test_new_and_legacy_tools_are_both_registered(self, empty_config_file):
        server = FortiGateMCPServer(empty_config_file)

        tools = await server.mcp.list_tools()
        names = {t.name for t in tools}

        assert NEW_TOOL_NAMES <= names
        assert LEGACY_TOOL_NAMES <= names


class TestHttpServerToolRegistration:
    def test_server_constructs_with_new_infra_components(self, empty_config_file):
        server = FortiGateMCPHTTPServer(empty_config_file)

        assert server.connection_manager is not None
        assert server.credential_manager is not None
        assert server.adapter_registry.known_product_types() == ["fortios"]
        assert server.change_service is not None
        assert server.mode_policy is not None

    @pytest.mark.asyncio
    async def test_new_and_legacy_tools_are_both_registered(self, empty_config_file):
        server = FortiGateMCPHTTPServer(empty_config_file)

        tools = await server.mcp.list_tools()
        names = {t.name for t in tools}

        assert NEW_TOOL_NAMES <= names
        assert LEGACY_TOOL_NAMES <= names
