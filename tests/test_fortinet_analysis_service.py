"""
Tests for AnalysisService: wiring device resolution + adapter fetch into
the pure domain/analysis functions, using the same mock_fortigate_api
fixture as the other Service-layer tests.
"""
import pytest

from src.fortinet_mcp.services.analysis_service import AnalysisService


@pytest.fixture
def service(fortigate_manager):
    return AnalysisService(fortigate_manager)


@pytest.fixture
def registered(fortigate_manager, mock_fortigate_api):
    fortigate_manager.devices["test_device"] = mock_fortigate_api
    return mock_fortigate_api


def _addr(name, subnet):
    return {"name": name, "type": "ipmask", "subnet": subnet}


class TestFindDuplicatePolicies:
    @pytest.mark.asyncio
    async def test_reports_duplicates_from_live_policies(self, service, registered):
        registered.get_firewall_policies.return_value = {
            "results": [
                {
                    "policyid": 1, "srcintf": [{"name": "port1"}], "dstintf": [{"name": "port2"}],
                    "srcaddr": [{"name": "LAN"}], "dstaddr": [{"name": "all"}],
                    "service": [{"name": "ALL"}], "action": "accept", "status": "enable",
                },
                {
                    "policyid": 2, "srcintf": [{"name": "port1"}], "dstintf": [{"name": "port2"}],
                    "srcaddr": [{"name": "LAN"}], "dstaddr": [{"name": "all"}],
                    "service": [{"name": "ALL"}], "action": "accept", "status": "enable",
                },
            ]
        }

        result = await service.find_duplicate_policies("test_device")

        registered.get_firewall_policies.assert_awaited_once_with(vdom=None)
        assert "1" in result[0].text and "2" in result[0].text

    @pytest.mark.asyncio
    async def test_unknown_device_returns_formatted_error(self, service):
        result = await service.find_duplicate_policies("nope")
        assert "not found" in result[0].text.lower() or "error" in result[0].text.lower()


class TestFindAnyAny:
    @pytest.mark.asyncio
    async def test_flags_any_any_any_policy(self, service, registered):
        registered.get_firewall_policies.return_value = {
            "results": [
                {
                    "policyid": 7, "name": "risky", "srcintf": [{"name": "port1"}], "dstintf": [{"name": "port2"}],
                    "srcaddr": [{"name": "all"}], "dstaddr": [{"name": "all"}],
                    "service": [{"name": "ALL"}], "action": "accept", "status": "enable",
                }
            ]
        }

        result = await service.find_any_any("test_device", vdom="root")

        registered.get_firewall_policies.assert_awaited_once_with(vdom="root")
        assert "risky" in result[0].text


class TestFindUnusedObjects:
    @pytest.mark.asyncio
    async def test_reports_unused_address_service_and_vip(self, service, registered):
        registered.get_firewall_policies.return_value = {
            "results": [
                {
                    "policyid": 1, "srcintf": [{"name": "port1"}], "dstintf": [{"name": "port2"}],
                    "srcaddr": [{"name": "used_addr"}], "dstaddr": [{"name": "all"}],
                    "service": [{"name": "used_svc"}], "action": "accept", "status": "enable",
                }
            ]
        }
        registered.get_address_objects.return_value = {
            "results": [{"name": "used_addr"}, {"name": "unused_addr"}]
        }
        registered.get_service_objects.return_value = {
            "results": [{"name": "used_svc"}, {"name": "unused_svc"}]
        }
        registered.get_virtual_ips.return_value = {"results": [{"name": "unused_vip"}]}

        result = await service.find_unused_objects("test_device")

        text = result[0].text
        assert "unused_addr" in text
        assert "unused_svc" in text
        assert "unused_vip" in text
        assert "used_addr" not in text.replace("unused_addr", "")


class TestFindOverlappingSubnets:
    @pytest.mark.asyncio
    async def test_reports_overlap_from_live_address_objects(self, service, registered):
        registered.get_address_objects.return_value = {
            "results": [_addr("net_big", "10.0.0.0/16"), _addr("net_small", "10.0.1.0/24")]
        }

        result = await service.find_overlapping_subnets("test_device")

        assert "net_big" in result[0].text and "net_small" in result[0].text


class TestCheckBestPractices:
    @pytest.mark.asyncio
    async def test_flags_missing_comment(self, service, registered):
        registered.get_firewall_policies.return_value = {
            "results": [
                {
                    "policyid": 1, "srcintf": [{"name": "port1"}], "dstintf": [{"name": "port2"}],
                    "srcaddr": [{"name": "all"}], "dstaddr": [{"name": "all"}],
                    "service": [{"name": "ALL"}], "action": "accept", "status": "enable",
                    "logtraffic": "enable",
                }
            ]
        }

        result = await service.check_best_practices("test_device")

        assert "no comment" in result[0].text.lower()


class TestCheckSystemConfig:
    @pytest.mark.asyncio
    async def test_flags_default_snmp_community_and_no_ha(self, service, registered):
        # mock_fortigate_api fixture defaults: snmp community "public", one
        # admin account, ha mode "standalone", hostname "FortiGate" -- all
        # expected to be flagged.
        result = await service.check_system_config("test_device")
        text = result[0].text
        assert "public" in text
        assert '"category": "ha"' in text
        assert '"category": "admin"' in text

    @pytest.mark.asyncio
    async def test_unknown_device_returns_formatted_error(self, service):
        result = await service.check_system_config("nope")
        assert "not found" in result[0].text.lower() or "error" in result[0].text.lower()

    @pytest.mark.asyncio
    async def test_degrades_gracefully_when_a_field_fetch_fails(self, service, registered):
        registered.get_ha_config.side_effect = Exception("boom")
        result = await service.check_system_config("test_device")
        text = result[0].text
        assert "System Configuration Findings" in text  # call succeeded despite the failed HA fetch
        assert "public" in text  # other findings (default SNMP community) still present


class TestScoreSecurityAndComplianceReport:
    @pytest.mark.asyncio
    async def test_score_security_reflects_findings(self, service, registered):
        registered.get_firewall_policies.return_value = {
            "results": [
                {
                    "policyid": 1, "srcintf": [{"name": "port1"}], "dstintf": [{"name": "port2"}],
                    "srcaddr": [{"name": "all"}], "dstaddr": [{"name": "all"}],
                    "service": [{"name": "ALL"}], "action": "accept", "status": "enable",
                }
            ]
        }
        registered.get_address_objects.return_value = {"results": []}
        registered.get_service_objects.return_value = {"results": []}
        registered.get_virtual_ips.return_value = {"results": []}

        result = await service.score_security("test_device")

        assert '"score"' in result[0].text
        assert '"grade"' in result[0].text

    @pytest.mark.asyncio
    async def test_compliance_report_bundles_every_finding_category(self, service, registered):
        registered.get_firewall_policies.return_value = {"results": []}
        registered.get_address_objects.return_value = {"results": []}
        registered.get_service_objects.return_value = {"results": []}
        registered.get_virtual_ips.return_value = {"results": []}

        result = await service.compliance_report("test_device")

        text = result[0].text
        for key in (
            "security_score", "any_any_policies", "shadowed_policies", "duplicate_policies",
            "overlapping_subnets", "unused_address_objects", "unused_service_objects",
            "unused_virtual_ips", "best_practice_findings", "system_config_findings",
        ):
            assert key in text

    @pytest.mark.asyncio
    async def test_score_security_reflects_system_config_findings(self, service, registered):
        registered.get_firewall_policies.return_value = {"results": []}
        registered.get_address_objects.return_value = {"results": []}
        registered.get_service_objects.return_value = {"results": []}
        registered.get_virtual_ips.return_value = {"results": []}
        # mock_fortigate_api defaults already include default SNMP community
        # "public", single admin, standalone HA, default hostname.

        result = await service.score_security("test_device")

        assert "system-config" in result[0].text.lower()
