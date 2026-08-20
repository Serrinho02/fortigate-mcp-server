"""
Tests for the pure domain/analysis/* functions -- no adapters, no I/O,
just plain policy/object dicts in, findings out.
"""
from src.fortinet_mcp.domain.analysis import (
    any_any,
    best_practice,
    duplicate,
    overlap,
    scoring,
    shadowed,
    system_config,
    unused_objects,
)


def _policy(policyid, srcintf="port1", dstintf="port2", srcaddr="all", dstaddr="all",
            service="ALL", action="accept", status="enable", **extra):
    def _field(v):
        return [{"name": n} for n in (v if isinstance(v, list) else [v])]

    return {
        "policyid": policyid,
        "srcintf": _field(srcintf),
        "dstintf": _field(dstintf),
        "srcaddr": _field(srcaddr),
        "dstaddr": _field(dstaddr),
        "service": _field(service),
        "action": action,
        "status": status,
        **extra,
    }


class TestFindDuplicatePolicies:
    def test_identical_criteria_and_action_is_duplicate(self):
        policies = [_policy(1, srcaddr="LAN"), _policy(2, srcaddr="LAN")]
        result = duplicate.find_duplicate_policies(policies)
        assert len(result) == 1
        assert set(result[0]["policy_ids"]) == {1, 2}

    def test_different_action_is_not_a_pure_duplicate(self):
        policies = [_policy(1, srcaddr="LAN", action="accept"), _policy(2, srcaddr="LAN", action="deny")]
        assert duplicate.find_duplicate_policies(policies) == []

    def test_different_criteria_is_not_duplicate(self):
        policies = [_policy(1, srcaddr="LAN"), _policy(2, srcaddr="DMZ")]
        assert duplicate.find_duplicate_policies(policies) == []

    def test_no_policies_returns_empty(self):
        assert duplicate.find_duplicate_policies([]) == []


class TestFindShadowedPolicies:
    def test_broad_earlier_policy_shadows_narrower_later_one(self):
        policies = [_policy(1, srcaddr="all", dstaddr="all", service="ALL"), _policy(2, srcaddr="LAN")]
        result = shadowed.find_shadowed_policies(policies)
        assert result == [
            {
                "shadowed_policy_id": 2,
                "shadowed_by_policy_id": 1,
                "reason": (
                    "Policy 1 is evaluated first and matches all traffic policy 2 would match."
                ),
            }
        ]

    def test_narrower_earlier_policy_does_not_shadow_broader_later_one(self):
        policies = [_policy(1, srcaddr="LAN"), _policy(2, srcaddr="all")]
        assert shadowed.find_shadowed_policies(policies) == []

    def test_disabled_earlier_policy_does_not_shadow(self):
        policies = [_policy(1, srcaddr="all", status="disable"), _policy(2, srcaddr="LAN")]
        assert shadowed.find_shadowed_policies(policies) == []

    def test_identical_narrow_policies_shadow_each_other_in_order(self):
        policies = [_policy(1, srcaddr="LAN"), _policy(2, srcaddr="LAN")]
        result = shadowed.find_shadowed_policies(policies)
        assert result == [
            {
                "shadowed_policy_id": 2,
                "shadowed_by_policy_id": 1,
                "reason": "Policy 1 is evaluated first and matches all traffic policy 2 would match.",
            }
        ]

    def test_disjoint_policies_do_not_shadow(self):
        policies = [_policy(1, srcaddr="LAN"), _policy(2, srcaddr="DMZ")]
        assert shadowed.find_shadowed_policies(policies) == []


class TestFindAnyAnyPolicies:
    def test_all_any_any_any_is_flagged(self):
        policies = [_policy(1, srcaddr="all", dstaddr="all", service="ALL")]
        result = any_any.find_any_any_policies(policies)
        assert result == [{"policy_id": 1, "name": None, "action": "accept", "status": "enable"}]

    def test_partial_any_is_not_flagged(self):
        policies = [_policy(1, srcaddr="all", dstaddr="LAN", service="ALL")]
        assert any_any.find_any_any_policies(policies) == []

    def test_case_insensitive_wildcard_detection(self):
        policies = [_policy(1, srcaddr="Any", dstaddr="ANY", service="any")]
        result = any_any.find_any_any_policies(policies)
        assert len(result) == 1


class TestFindUnusedObjects:
    def test_object_not_referenced_anywhere_is_unused(self):
        objects = [{"name": "web1"}, {"name": "web2"}]
        policies = [_policy(1, srcaddr="web1")]
        result = unused_objects.find_unused(objects, policies, ("srcaddr", "dstaddr"))
        assert result == ["web2"]

    def test_object_referenced_in_dstaddr_counts_as_used(self):
        objects = [{"name": "vip1"}]
        policies = [_policy(1, dstaddr="vip1")]
        assert unused_objects.find_unused(objects, policies, ("srcaddr", "dstaddr")) == []

    def test_service_objects_checked_against_service_field_only(self):
        objects = [{"name": "HTTP-ALT"}]
        policies = [_policy(1, service="ALL")]  # doesn't reference HTTP-ALT
        assert unused_objects.find_unused(objects, policies, ("service",)) == ["HTTP-ALT"]

    def test_no_policies_means_everything_is_unused(self):
        objects = [{"name": "a"}, {"name": "b"}]
        assert unused_objects.find_unused(objects, [], ("srcaddr", "dstaddr")) == ["a", "b"]


class TestFindOverlappingSubnets:
    def test_identical_subnets_are_equal(self):
        objects = [
            {"name": "net_a", "type": "ipmask", "subnet": "10.0.0.0 255.255.255.0"},
            {"name": "net_b", "type": "ipmask", "subnet": "10.0.0.0/24"},
        ]
        result = overlap.find_overlapping_subnets(objects)
        assert result == [{"object_a": "net_a", "object_b": "net_b", "relationship": "equal"}]

    def test_a_contains_b(self):
        objects = [
            {"name": "big", "type": "ipmask", "subnet": "10.0.0.0/16"},
            {"name": "small", "type": "ipmask", "subnet": "10.0.1.0/24"},
        ]
        result = overlap.find_overlapping_subnets(objects)
        assert result == [{"object_a": "big", "object_b": "small", "relationship": "a_contains_b"}]

    def test_b_contains_a(self):
        objects = [
            {"name": "small", "type": "ipmask", "subnet": "10.0.1.0/24"},
            {"name": "big", "type": "ipmask", "subnet": "10.0.0.0/16"},
        ]
        result = overlap.find_overlapping_subnets(objects)
        assert result == [{"object_a": "small", "object_b": "big", "relationship": "b_contains_a"}]

    def test_disjoint_subnets_not_flagged(self):
        objects = [
            {"name": "a", "type": "ipmask", "subnet": "10.0.0.0/24"},
            {"name": "b", "type": "ipmask", "subnet": "192.168.1.0/24"},
        ]
        assert overlap.find_overlapping_subnets(objects) == []

    def test_iprange_overlap_detected(self):
        objects = [
            {"name": "r1", "type": "iprange", "start-ip": "10.0.0.10", "end-ip": "10.0.0.20"},
            {"name": "r2", "type": "iprange", "start-ip": "10.0.0.15", "end-ip": "10.0.0.25"},
        ]
        result = overlap.find_overlapping_subnets(objects)
        assert result == [{"object_a": "r1", "object_b": "r2", "relationship": "overlap"}]

    def test_fqdn_objects_are_skipped_not_errored(self):
        objects = [
            {"name": "site", "type": "fqdn", "fqdn": "example.com"},
            {"name": "net", "type": "ipmask", "subnet": "10.0.0.0/24"},
        ]
        assert overlap.find_overlapping_subnets(objects) == []

    def test_malformed_subnet_is_skipped_not_errored(self):
        objects = [{"name": "bad", "type": "ipmask", "subnet": "not-an-ip"}]
        assert overlap.find_overlapping_subnets(objects) == []


class TestCheckBestPractices:
    def test_accept_without_logging_flagged(self):
        policies = [_policy(1, action="accept", logtraffic="disable")]
        findings = best_practice.check_best_practices(policies)
        assert any(f["issue"].startswith("Accept policy has traffic logging disabled") for f in findings)

    def test_accept_with_logging_not_flagged_for_logging(self):
        policies = [_policy(1, action="accept", logtraffic="enable", comments="x")]
        findings = best_practice.check_best_practices(policies)
        assert not any("logging disabled" in f["issue"] for f in findings)

    def test_missing_comment_flagged(self):
        policies = [_policy(1, logtraffic="enable")]
        findings = best_practice.check_best_practices(policies)
        assert any("no comment" in f["issue"].lower() for f in findings)

    def test_disabled_policy_flagged(self):
        policies = [_policy(1, status="disable", comments="x", logtraffic="enable")]
        findings = best_practice.check_best_practices(policies)
        assert any("disabled" in f["issue"].lower() for f in findings)

    def test_clean_policy_has_no_findings(self):
        policies = [_policy(1, comments="documented", logtraffic="enable")]
        assert best_practice.check_best_practices(policies) == []


class TestCheckSystemConfig:
    _GOOD_BUNDLE = dict(
        dns={"primary": "8.8.8.8"},
        ntp={"ntpsync": "enable"},
        syslog={"status": "enable"},
        snmp_sysinfo={"status": "enable"},
        snmp_communities=[{"name": "monitoring"}],
        admins=[{"name": "admin"}, {"name": "netops"}],
        ha={"mode": "a-p"},
        global_settings={"hostname": "CDM-OBM-HUB-FW01"},
    )

    def test_fully_configured_device_has_no_findings(self):
        assert system_config.check_system_config(**self._GOOD_BUNDLE) == []

    def test_missing_dns_flagged(self):
        bundle = {**self._GOOD_BUNDLE, "dns": {}}
        findings = system_config.check_system_config(**bundle)
        assert any(f["category"] == "dns" for f in findings)

    def test_ntp_disabled_flagged(self):
        bundle = {**self._GOOD_BUNDLE, "ntp": {"ntpsync": "disable"}}
        findings = system_config.check_system_config(**bundle)
        assert any(f["category"] == "ntp" for f in findings)

    def test_syslog_disabled_flagged(self):
        bundle = {**self._GOOD_BUNDLE, "syslog": {"status": "disable"}}
        findings = system_config.check_system_config(**bundle)
        assert any(f["category"] == "syslog" for f in findings)

    def test_default_snmp_community_flagged_as_high_severity(self):
        bundle = {**self._GOOD_BUNDLE, "snmp_communities": [{"name": "public"}]}
        findings = system_config.check_system_config(**bundle)
        matches = [f for f in findings if f["category"] == "snmp"]
        assert len(matches) == 1
        assert matches[0]["severity"] == "high"

    def test_default_snmp_community_not_flagged_when_snmp_disabled(self):
        bundle = {**self._GOOD_BUNDLE, "snmp_sysinfo": {"status": "disable"}, "snmp_communities": [{"name": "public"}]}
        findings = system_config.check_system_config(**bundle)
        assert not any(f["category"] == "snmp" for f in findings)

    def test_only_default_admin_flagged(self):
        bundle = {**self._GOOD_BUNDLE, "admins": [{"name": "admin"}]}
        findings = system_config.check_system_config(**bundle)
        assert any(f["category"] == "admin" for f in findings)

    def test_standalone_ha_flagged(self):
        bundle = {**self._GOOD_BUNDLE, "ha": {"mode": "standalone"}}
        findings = system_config.check_system_config(**bundle)
        assert any(f["category"] == "ha" for f in findings)

    def test_default_hostname_flagged(self):
        bundle = {**self._GOOD_BUNDLE, "global_settings": {"hostname": "FortiGate"}}
        findings = system_config.check_system_config(**bundle)
        assert any(f["category"] == "system_global" for f in findings)

    def test_all_fields_missing_does_not_crash(self):
        findings = system_config.check_system_config()
        assert len(findings) > 0  # everything unconfigured, plenty to flag


class TestScoreSecurity:
    def test_perfect_score_when_nothing_found(self):
        result = scoring.score_security(
            any_any_count=0, shadowed_count=0, duplicate_count=0, unused_count=0, best_practice_issues=[]
        )
        assert result == {"score": 100, "grade": "A", "deductions": []}

    def test_system_config_issues_deduct_points(self):
        result = scoring.score_security(
            any_any_count=0,
            shadowed_count=0,
            duplicate_count=0,
            unused_count=0,
            best_practice_issues=[],
            system_config_issues=[{"severity": "high"}, {"severity": "medium"}],
        )
        assert result["score"] == 93  # 100 - (5 + 2)
        assert result["deductions"][0]["points"] == 7

    def test_system_config_issues_capped(self):
        result = scoring.score_security(
            any_any_count=0,
            shadowed_count=0,
            duplicate_count=0,
            unused_count=0,
            best_practice_issues=[],
            system_config_issues=[{"severity": "high"}] * 10,
        )
        assert result["deductions"][0]["points"] == 15

    def test_none_system_config_issues_adds_no_deduction(self):
        result = scoring.score_security(
            any_any_count=0, shadowed_count=0, duplicate_count=0, unused_count=0,
            best_practice_issues=[], system_config_issues=None,
        )
        assert result == {"score": 100, "grade": "A", "deductions": []}

    def test_any_any_deducts_points_and_is_capped(self):
        result = scoring.score_security(
            any_any_count=10, shadowed_count=0, duplicate_count=0, unused_count=0, best_practice_issues=[]
        )
        assert result["score"] == 60  # 100 - min(10*15, 40)
        assert result["deductions"][0]["points"] == 40

    def test_grade_thresholds(self):
        assert scoring._grade(95) == "A"
        assert scoring._grade(80) == "B"
        assert scoring._grade(65) == "C"
        assert scoring._grade(45) == "D"
        assert scoring._grade(10) == "F"

    def test_score_never_goes_below_zero(self):
        result = scoring.score_security(
            any_any_count=100, shadowed_count=100, duplicate_count=100, unused_count=100,
            best_practice_issues=[{"severity": "high"}] * 50,
        )
        assert result["score"] == 0
        assert result["grade"] == "F"
