"""Tests for the pure domain/analysis/diagnosis.py functions."""
from src.fortinet_mcp.domain.analysis.diagnosis import diagnose_policy, find_matching_policy


def _policy(policyid, srcintf="port1", dstintf="port2", srcaddr="all", dstaddr="all",
            service="ALL", action="accept", status="enable", schedule="always", **extra):
    def _field(v):
        return [{"name": n} for n in (v if isinstance(v, list) else [v])]

    return {
        "policyid": policyid,
        "srcintf": _field(srcintf), "dstintf": _field(dstintf),
        "srcaddr": _field(srcaddr), "dstaddr": _field(dstaddr),
        "service": _field(service),
        "action": action, "status": status, "schedule": schedule,
        **extra,
    }


class TestDiagnosePolicy:
    def test_unknown_policy_id_reports_not_found(self):
        result = diagnose_policy(999, [_policy(1)])
        assert result == [{"issue": "not_found", "detail": "No policy with id 999 exists on this device."}]

    def test_disabled_policy_flagged(self):
        result = diagnose_policy(1, [_policy(1, status="disable")])
        assert any(f["issue"] == "disabled" for f in result)

    def test_shadowed_policy_flagged(self):
        policies = [_policy(1, srcaddr="all", dstaddr="all", service="ALL"), _policy(2, srcaddr="LAN")]
        result = diagnose_policy(2, policies)
        assert any(f["issue"] == "shadowed" for f in result)

    def test_string_policy_id_matches_int_stored_id(self):
        result = diagnose_policy("1", [_policy(1, status="disable")])
        assert any(f["issue"] == "disabled" for f in result)

    def test_schedule_restricted_flagged(self):
        result = diagnose_policy(1, [_policy(1, schedule="business-hours")])
        assert any(f["issue"] == "schedule_restricted" for f in result)

    def test_earlier_deny_covering_flagged(self):
        policies = [
            _policy(1, srcaddr="all", dstaddr="all", service="ALL", action="deny"),
            _policy(2, srcaddr="LAN", action="accept"),
        ]
        result = diagnose_policy(2, policies)
        assert any(f["issue"] == "denied_earlier" and "1" in f["detail"] for f in result)

    def test_earlier_deny_after_target_does_not_count(self):
        policies = [
            _policy(1, srcaddr="LAN", action="accept"),
            _policy(2, srcaddr="all", dstaddr="all", service="ALL", action="deny"),
        ]
        result = diagnose_policy(1, policies)
        assert not any(f["issue"] == "denied_earlier" for f in result)

    def test_clean_policy_reports_no_obvious_issue(self):
        result = diagnose_policy(1, [_policy(1)])
        assert result == [
            {
                "issue": "no_obvious_issue",
                "detail": (
                    "No obvious configuration issue found. If traffic still isn't matching, check "
                    "routing, NAT, and interface/zone assignment, or session logs on the device directly."
                ),
            }
        ]


class TestFindMatchingPolicy:
    def test_finds_exact_match(self):
        policies = [_policy(1, srcaddr="LAN", dstaddr="Internet", service="HTTPS")]
        result = find_matching_policy(policies, "LAN", "Internet", "HTTPS")
        assert result["policyid"] == 1

    def test_wildcard_source_matches_anything(self):
        policies = [_policy(1, srcaddr="all", dstaddr="Internet", service="HTTPS")]
        result = find_matching_policy(policies, "AnyRandomSubnet", "Internet", "HTTPS")
        assert result["policyid"] == 1

    def test_service_none_ignores_service_matching(self):
        policies = [_policy(1, srcaddr="LAN", dstaddr="Internet", service="SSH")]
        result = find_matching_policy(policies, "LAN", "Internet")
        assert result["policyid"] == 1

    def test_disabled_policy_is_skipped(self):
        policies = [
            _policy(1, srcaddr="LAN", dstaddr="Internet", service="HTTPS", status="disable"),
            _policy(2, srcaddr="LAN", dstaddr="Internet", service="HTTPS"),
        ]
        result = find_matching_policy(policies, "LAN", "Internet", "HTTPS")
        assert result["policyid"] == 2

    def test_first_match_wins(self):
        policies = [
            _policy(1, srcaddr="all", dstaddr="all", service="ALL", action="deny"),
            _policy(2, srcaddr="LAN", dstaddr="Internet", service="HTTPS", action="accept"),
        ]
        result = find_matching_policy(policies, "LAN", "Internet", "HTTPS")
        assert result["policyid"] == 1
        assert result["action"] == "deny"

    def test_no_match_returns_none(self):
        policies = [_policy(1, srcaddr="LAN", dstaddr="Internet", service="HTTPS")]
        result = find_matching_policy(policies, "DMZ", "Internet", "HTTPS")
        assert result is None
