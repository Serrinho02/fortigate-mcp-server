"""Tests for the pure domain/fleet_compare.py comparison logic."""
from src.fortinet_mcp.domain.fleet_compare import compare_resource_lists


class TestCompareAddressObjects:
    def test_only_in_a(self):
        result = compare_resource_lists(
            "address_object", [{"name": "web1", "subnet": "10.0.0.0/24"}], []
        )
        assert result["only_in_a"] == ["web1"]
        assert result["only_in_b"] == []
        assert result["identical"] == []
        assert result["different"] == []

    def test_only_in_b(self):
        result = compare_resource_lists(
            "address_object", [], [{"name": "web1", "subnet": "10.0.0.0/24"}]
        )
        assert result["only_in_b"] == ["web1"]

    def test_identical_object_reported_as_identical(self):
        obj = {"name": "web1", "subnet": "10.0.0.0/24"}
        result = compare_resource_lists("address_object", [obj], [dict(obj)])
        assert result["identical"] == ["web1"]
        assert result["different"] == []

    def test_same_name_different_subnet_reported_as_different(self):
        result = compare_resource_lists(
            "address_object",
            [{"name": "web1", "subnet": "10.0.0.0/24"}],
            [{"name": "web1", "subnet": "10.0.1.0/24"}],
        )
        assert result["different"] == [
            {"key": "web1", "changed_fields": {"subnet": {"before": "10.0.0.0/24", "after": "10.0.1.0/24"}}}
        ]


class TestCompareFirewallPolicies:
    def test_keyed_by_policyid_not_name(self):
        result = compare_resource_lists(
            "firewall_policy",
            [{"policyid": 1, "name": "Allow_HTTP", "action": "accept"}],
            [{"policyid": 1, "name": "Allow_HTTP_renamed", "action": "accept"}],
        )
        assert result["different"] == [
            {
                "key": 1,
                "changed_fields": {"name": {"before": "Allow_HTTP", "after": "Allow_HTTP_renamed"}},
            }
        ]


class TestCompareStaticRoutes:
    def test_keyed_by_seq_num_when_present(self):
        result = compare_resource_lists(
            "static_route",
            [{"seq-num": 1, "dst": "10.0.0.0/8", "gateway": "192.168.1.1"}],
            [{"seq-num": 1, "dst": "10.0.0.0/8", "gateway": "192.168.1.2"}],
        )
        assert result["different"][0]["key"] == 1

    def test_falls_back_to_dst_when_seq_num_absent(self):
        result = compare_resource_lists(
            "static_route",
            [{"dst": "10.0.0.0/8", "gateway": "192.168.1.1"}],
            [{"dst": "10.0.0.0/8", "gateway": "192.168.1.1"}],
        )
        assert result["identical"] == ["10.0.0.0/8"]


class TestEmptyInputs:
    def test_both_empty_returns_all_empty_lists(self):
        result = compare_resource_lists("address_object", [], [])
        assert result == {
            "resource_type": "address_object",
            "only_in_a": [],
            "only_in_b": [],
            "identical": [],
            "different": [],
        }
