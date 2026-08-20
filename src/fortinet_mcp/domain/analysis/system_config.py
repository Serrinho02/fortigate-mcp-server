"""
A small set of best-practice heuristics over device-level system
configuration (DNS/NTP/syslog/SNMP/admin accounts/HA/hostname) -- the
system.*/vdom.* domain's counterpart to best_practice.py's policy checks.
Deliberately modest in scope, same as best_practice.py: easy to extend with
more checks later without touching callers.

Every argument is optional and defaults to an empty dict/list: the caller
(AnalysisService) fetches each field best-effort, since a device/adapter
might not expose every capability, and a missing field should degrade to
"can't verify" rather than crash the whole check.
"""
from __future__ import annotations

from typing import Any, Optional

_WEAK_SNMP_COMMUNITY_NAMES = {"public", "private"}
_DEFAULT_HOSTNAMES = {"", "fortigate"}


def check_system_config(
    *,
    dns: Optional[dict[str, Any]] = None,
    ntp: Optional[dict[str, Any]] = None,
    syslog: Optional[dict[str, Any]] = None,
    snmp_sysinfo: Optional[dict[str, Any]] = None,
    snmp_communities: Optional[list[dict[str, Any]]] = None,
    admins: Optional[list[dict[str, Any]]] = None,
    ha: Optional[dict[str, Any]] = None,
    global_settings: Optional[dict[str, Any]] = None,
) -> list[dict[str, Any]]:
    dns = dns or {}
    ntp = ntp or {}
    syslog = syslog or {}
    snmp_sysinfo = snmp_sysinfo or {}
    snmp_communities = snmp_communities or []
    admins = admins or []
    ha = ha or {}
    global_settings = global_settings or {}

    findings: list[dict[str, Any]] = []

    if not dns.get("primary"):
        findings.append(
            {
                "category": "dns",
                "severity": "medium",
                "issue": "No primary DNS server configured.",
            }
        )

    if ntp.get("ntpsync", "disable") != "enable":
        findings.append(
            {
                "category": "ntp",
                "severity": "medium",
                "issue": "NTP time sync is disabled -- log timestamps and certificate validation can drift.",
            }
        )

    if syslog.get("status", "disable") != "enable":
        findings.append(
            {
                "category": "syslog",
                "severity": "medium",
                "issue": "Remote syslog logging is disabled -- no offsite log retention if the device is lost.",
            }
        )

    if snmp_sysinfo.get("status") == "enable":
        for community in snmp_communities:
            name = community.get("name")
            if isinstance(name, str) and name.lower() in _WEAK_SNMP_COMMUNITY_NAMES:
                findings.append(
                    {
                        "category": "snmp",
                        "severity": "high",
                        "issue": f"SNMP community '{name}' uses a well-known default name -- a common attack target.",
                    }
                )

    if len(admins) <= 1:
        findings.append(
            {
                "category": "admin",
                "severity": "low",
                "issue": "Only the default admin account exists -- no per-user accountability for changes.",
            }
        )

    if ha.get("mode", "standalone") == "standalone":
        findings.append(
            {
                "category": "ha",
                "severity": "low",
                "issue": (
                    "No HA cluster configured -- this device is a single point of failure. "
                    "May be an accepted tradeoff for smaller deployments."
                ),
            }
        )

    hostname = str(global_settings.get("hostname", "")).strip().lower()
    if hostname in _DEFAULT_HOSTNAMES:
        findings.append(
            {
                "category": "system_global",
                "severity": "low",
                "issue": "Device hostname has not been customized from the default.",
            }
        )

    return findings
