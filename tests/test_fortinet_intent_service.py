"""
Tests for IntentService (Phase 7): natural-language-shaped composites.
create_policy composes a real PolicyService (backed by a real ChangeService,
FULL mode, temp-file SQLite) so the change-engine delegation is exercised
for real, not just asserted by inspection.
"""
import pytest
import pytest_asyncio

from src.fortinet_mcp.infra.db import create_engine, create_session_factory, init_models
from src.fortinet_mcp.services.change_service import ChangeService
from src.fortinet_mcp.services.intent_service import IntentService
from src.fortinet_mcp.services.mode_policy import ModePolicy, OperatingMode
from src.fortinet_mcp.services.policy_service import PolicyService


@pytest_asyncio.fixture
async def session_factory(tmp_path):
    db_url = f"sqlite+aiosqlite:///{(tmp_path / 'inventory.db').as_posix()}"
    engine = create_engine(db_url)
    await init_models(engine)
    factory = create_session_factory(engine)
    yield factory
    await engine.dispose()


@pytest.fixture
def change_service(fortigate_manager, session_factory):
    return ChangeService(fortigate_manager, session_factory, ModePolicy(OperatingMode.FULL))


@pytest.fixture
def policy_service(fortigate_manager, change_service):
    return PolicyService(fortigate_manager, change_service)


@pytest.fixture
def service(fortigate_manager, policy_service):
    return IntentService(fortigate_manager, policy_service)


@pytest.fixture
def registered(fortigate_manager, mock_fortigate_api):
    fortigate_manager.devices["test_device"] = mock_fortigate_api
    return mock_fortigate_api


def _change_id_from(result) -> str:
    for content in result:
        for line in content.text.splitlines():
            if "change_id:" in line:
                return line.split("change_id:", 1)[1].strip()
    raise AssertionError("no change_id found in result")


class TestIntentCreatePolicy:
    @pytest.mark.asyncio
    async def test_exact_interface_and_known_service_match_no_notes(self, service, registered):
        registered.get_interfaces.return_value = {"results": [{"name": "LAN"}, {"name": "wan1"}]}
        registered.get_service_objects.return_value = {"results": [{"name": "HTTPS"}]}
        registered.get_address_objects.return_value = {"results": []}

        result = await service.create_policy("test_device", "Allow_HTTPS", "LAN", "wan1", service="HTTPS")

        assert "matched existing configuration directly" in result[0].text
        assert "change_id" in result[1].text

    @pytest.mark.asyncio
    async def test_unmatched_zone_falls_back_with_a_note(self, service, registered):
        registered.get_interfaces.return_value = {"results": [{"name": "port1"}]}
        registered.get_service_objects.return_value = {"results": []}
        registered.get_address_objects.return_value = {"results": []}

        result = await service.create_policy("test_device", "Allow_HTTPS", "LAN", "Internet", service="HTTPS")

        assert "did not match any existing interface name" in result[0].text
        assert "LAN" in result[0].text and "Internet" in result[0].text

    @pytest.mark.asyncio
    async def test_unknown_non_default_service_notes_and_uses_as_is(self, service, registered):
        registered.get_interfaces.return_value = {"results": [{"name": "LAN"}, {"name": "wan1"}]}
        registered.get_service_objects.return_value = {"results": []}
        registered.get_address_objects.return_value = {"results": []}

        result = await service.create_policy("test_device", "Allow_Custom", "LAN", "wan1", service="MyCustomApp")

        assert "MyCustomApp" in result[0].text
        assert "create_service_object" in result[0].text

    @pytest.mark.asyncio
    async def test_creates_a_real_change_preview_that_can_be_applied(self, service, change_service, registered):
        registered.get_interfaces.return_value = {"results": [{"name": "LAN"}, {"name": "wan1"}]}
        registered.get_service_objects.return_value = {"results": [{"name": "HTTPS"}]}
        registered.get_address_objects.return_value = {"results": []}

        result = await service.create_policy("test_device", "Allow_HTTPS", "LAN", "wan1", service="HTTPS")
        change_id = _change_id_from(result)

        await change_service.apply(change_id)

        registered.create_firewall_policy.assert_awaited_once_with(
            {
                "name": "Allow_HTTPS",
                "srcintf": [{"name": "LAN"}],
                "dstintf": [{"name": "wan1"}],
                "srcaddr": [{"name": "all"}],
                "dstaddr": [{"name": "all"}],
                "service": [{"name": "HTTPS"}],
                "action": "accept",
                "schedule": "always",
                "status": "enable",
            },
            vdom=None,
        )

    @pytest.mark.asyncio
    async def test_missing_required_field_returns_error(self, service, registered):
        result = await service.create_policy("test_device", "", "LAN", "wan1")
        assert "required" in result[0].text.lower() or "error" in result[0].text.lower()


class TestExplainPolicyFailure:
    @pytest.mark.asyncio
    async def test_reports_diagnosis_for_live_policy(self, service, registered):
        registered.get_firewall_policies.return_value = {
            "results": [
                {
                    "policyid": 1, "srcintf": [{"name": "port1"}], "dstintf": [{"name": "port2"}],
                    "srcaddr": [{"name": "all"}], "dstaddr": [{"name": "all"}],
                    "service": [{"name": "ALL"}], "action": "accept", "status": "disable",
                }
            ]
        }

        result = await service.explain_policy_failure("test_device", "1")

        assert "disabled" in result[0].text.lower()

    @pytest.mark.asyncio
    async def test_missing_policy_id_returns_error(self, service, registered):
        result = await service.explain_policy_failure("test_device", "")
        assert "required" in result[0].text.lower() or "error" in result[0].text.lower()


class TestSummarizeDevice:
    @pytest.mark.asyncio
    async def test_reports_key_facts(self, service, registered):
        registered.get_interfaces.return_value = {
            "results": [{"name": "port1", "status": "up"}, {"name": "port2", "status": "down"}]
        }
        registered.get_firewall_policies.return_value = {"results": []}
        registered.get_address_objects.return_value = {"results": []}
        registered.get_service_objects.return_value = {"results": []}
        registered.get_virtual_ips.return_value = {"results": []}

        result = await service.summarize_device("test_device")

        text = result[0].text
        assert "FortiGate" in text  # hostname from mock system status
        assert "2 total (1 up, 1 down)" in text
        assert "Security score: 100/100 (grade A)" in text


class TestFindPath:
    @pytest.mark.asyncio
    async def test_reports_matching_policy(self, service, registered):
        registered.get_firewall_policies.return_value = {
            "results": [
                {
                    "policyid": 5, "name": "Allow_Web", "status": "enable", "action": "accept",
                    "srcaddr": [{"name": "LAN"}], "dstaddr": [{"name": "Internet"}], "service": [{"name": "HTTPS"}],
                }
            ]
        }

        result = await service.find_path("test_device", "LAN", "Internet", service="HTTPS")

        text = result[0].text
        assert '"result": "matched"' in text
        assert '"policy_id": 5' in text

    @pytest.mark.asyncio
    async def test_reports_no_match(self, service, registered):
        registered.get_firewall_policies.return_value = {"results": []}

        result = await service.find_path("test_device", "LAN", "Internet")

        assert '"result": "no_match"' in result[0].text
