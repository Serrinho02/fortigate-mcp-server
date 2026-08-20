# Tool Reference

Auto-reference for every MCP tool this server exposes -- 115 tools across 14 categories. Generated from the live tool registry, so names/descriptions here always match what Claude actually sees.

## Device Management (legacy config.json devices)

| Tool | Description |
|---|---|
| `add_device` | Add a new FortiGate device to the MCP server.  This tool registers a new FortiGate device with the server, configuring connection parameters and authentication credentials.  Parameters: - device_id: Unique identifier for the new device -... |
| `discover_vdoms` | Discover and list all Virtual Domains (VDOMs) on a FortiGate device.  This tool queries the specified FortiGate device to retrieve information about all configured Virtual Domains, including their status and settings.  Parameters: - devi... |
| `get_device_status` | Get detailed system status information for a specific FortiGate device.  This tool retrieves comprehensive system information from a FortiGate device, including hardware details, software version, hostname, and operational status.  Param... |
| `get_server_info` | Get detailed information about the FortiGate MCP server.  This tool provides comprehensive information about the server configuration, capabilities, and current operational status.  Returns: - Server version and build information - Avail... |
| `health_check` | Perform a comprehensive health check of the FortiGate MCP server.  This tool checks the overall health and status of the MCP server, including device connectivity, service availability, and system resources.  Returns: - Overall server he... |
| `list_devices` | List all registered FortiGate devices with their configuration details.  This tool displays information about all FortiGate devices that are currently registered with the MCP server, including connection details, authentication methods, ... |
| `remove_device` | Remove a FortiGate device from the MCP server.  This tool unregisters a FortiGate device from the server, removing all associated configuration and terminating active connections.  Parameters: - device_id: Identifier of the device to rem... |
| `test_device_connection` | Test network connectivity to a specific FortiGate device.  This tool performs a connection test to verify that the MCP server can successfully communicate with the specified FortiGate device.  Parameters: - device_id: Identifier of the F... |

## Inventory (multi-tenant Customer/Site/Device)

| Tool | Description |
|---|---|
| `inventory_list_customers` | List all customers (tenants) in the inventory. |
| `inventory_list_devices` | List devices in the inventory, optionally filtered by customer name. |
| `inventory_list_sites` | List sites, optionally filtered by customer name. |
| `inventory_register_device_pending` | Register a new device in the inventory (metadata only: host, name, customer, site). This does NOT provision credentials -- the returned credential_id must be provisioned by a human running `fortinet-mcp-cred set <credential_id>` locally.... |
| `inventory_remove_device` | Remove a device from the inventory and delete its stored credential from the OS keyring. |

## Connections

| Tool | Description |
|---|---|
| `connection_connect` | Connect to a firewall by name, site, customer, or management IP (e.g. 'Milano', 'Alfa', '10.10.10.1'). Reuses an existing connection if one is already open. If the target matches multiple devices (e.g. a customer or site with several fir... |
| `connection_disconnect` | Disconnect a device (target resolved the same way as connection.connect). |
| `connection_list_active` | List currently open (cached) device connections. |
| `connection_resolve` | Resolve a target string to the matching device(s) without connecting -- useful to check for ambiguity before connection.connect. |

## Firewall Policy & Objects

| Tool | Description |
|---|---|
| `create_address_object` | Create a new address object on a FortiGate device.  This tool adds a new network address object that can be used in firewall policies and other security rules.  Parameters: - device_id: Identifier of the FortiGate device - address_data: ... |
| `create_firewall_policy` | Create a new firewall policy on a FortiGate device.  This tool adds a new security policy to control traffic flow through the FortiGate device, defining rules for source, destination, and services.  Parameters: - device_id: Identifier of... |
| `create_service_object` | Create a new service object on a FortiGate device.  This tool adds a new network service object that defines protocols and ports for use in firewall policies.  Parameters: - device_id: Identifier of the FortiGate device - service_data: S... |
| `delete_firewall_policy` | Delete a firewall policy from a FortiGate device.  This tool removes an existing firewall policy from the device configuration, permanently deleting the specified security rule.  Parameters: - device_id: Identifier of the FortiGate devic... |
| `get_firewall_policy_detail` | Get detailed information for a specific firewall policy |
| `list_address_objects` | List all address objects configured on a FortiGate device.  This tool retrieves all network address objects defined on the device, including IP addresses, subnets, ranges, and FQDN objects.  Parameters: - device_id: Identifier of the For... |
| `list_firewall_policies` | List all firewall policies configured on a FortiGate device.  This tool retrieves and displays all firewall security policies from the specified device and Virtual Domain, showing traffic control rules and settings.  Parameters: - device... |
| `list_service_objects` | List all service objects configured on a FortiGate device.  This tool retrieves all network service objects defined on the device, including TCP/UDP port definitions and protocol specifications.  Parameters: - device_id: Identifier of th... |
| `update_firewall_policy` | Update an existing firewall policy on a FortiGate device.  This tool modifies the configuration of an existing firewall policy, allowing changes to rules, addresses, services, and other settings.  Parameters: - device_id: Identifier of t... |

## Routing, Interfaces, Zones, DHCP

| Tool | Description |
|---|---|
| `create_static_route` | Create a new static route on a FortiGate device.  This tool adds a new static route to the device's routing configuration, defining how traffic to specific networks should be forwarded.  Parameters: - device_id: Identifier of the FortiGa... |
| `delete_static_route` | Delete a static route from a FortiGate device.  This tool removes an existing static route from the device configuration.  Parameters: - device_id: Identifier of the FortiGate device - route_id: ID of the route to delete - vdom: Virtual ... |
| `get_interface_status` | Get detailed status information for a specific network interface on a FortiGate device.  This tool retrieves real-time status and statistics for a single interface, including link state, speed, traffic counters, and error counts.  Parame... |
| `get_routing_table` | Get the current routing table from a FortiGate device.  This tool retrieves the active routing table showing all routes currently installed on the device, including static, dynamic, and connected routes.  Parameters: - device_id: Identif... |
| `get_static_route_detail` | Get detailed information for a specific static route.  This tool retrieves comprehensive configuration details for a specific static route, including all settings and status.  Parameters: - device_id: Identifier of the FortiGate device -... |
| `list_interfaces` | List all network interfaces configured on a FortiGate device.  This tool retrieves information about all network interfaces, including physical ports, VLANs, and virtual interfaces.  Parameters: - device_id: Identifier of the FortiGate d... |
| `list_static_routes` | List all static routes configured on a FortiGate device.  This tool retrieves all manually configured static routes from the device's routing table, showing destination networks and gateways.  Parameters: - device_id: Identifier of the F... |
| `routing_create_dhcp_server` | Propose creating a DHCP server (interface, ip-range, netmask, default-gateway, dns-server1, ...). Returns a diff + change_id. |
| `routing_create_interface` | Propose creating an interface (VLAN sub-interface, loopback, or a vdom-link member interface -- FortiOS does not allow creating new physical ports). Common fields: name, type (vlan/loopback), interface (parent), vlanid, ip, vdom, allowac... |
| `routing_create_zone` | Propose creating a zone (name + member interfaces). Returns a diff + change_id. |
| `routing_delete_dhcp_server` | Propose deleting a DHCP server. Returns a diff + change_id. |
| `routing_delete_interface` | Propose deleting an interface. FortiOS rejects this for physical ports -- only VLAN/loopback/vdom-link member interfaces can actually be deleted. Returns a diff + change_id. |
| `routing_delete_zone` | Propose deleting a zone. Returns a diff + change_id. |
| `routing_list_dhcp_servers` | List DHCP servers. |
| `routing_list_zones` | List zones (named interface groupings used by firewall policies). |
| `routing_update_dhcp_server` | Propose updating a DHCP server. Returns a diff + change_id. |
| `routing_update_interface` | Propose updating an interface (IP/netmask, role, VDOM assignment, allowed access, status). Returns a diff + change_id. |
| `routing_update_zone` | Propose updating a zone's member interfaces. Returns a diff + change_id. |
| `update_static_route` | Update an existing static route on a FortiGate device.  This tool modifies the configuration of an existing static route, allowing changes to destination, gateway, or other settings.  Parameters: - device_id: Identifier of the FortiGate ... |

## Virtual IPs (NAT)

| Tool | Description |
|---|---|
| `create_virtual_ip` | Create a new Virtual IP on a FortiGate device.  This tool adds a new Virtual IP object that can be used for port forwarding, NAT, and external access to internal services.  Parameters: - device_id: Identifier of the FortiGate device - na... |
| `delete_virtual_ip` | Delete a Virtual IP from a FortiGate device.  This tool removes an existing Virtual IP object from the device configuration. Note that Virtual IPs in use by policies cannot be deleted.  Parameters: - device_id: Identifier of the FortiGat... |
| `get_virtual_ip_detail` | Get detailed information for a specific Virtual IP.  This tool retrieves comprehensive configuration details for a specific Virtual IP object, including all settings and mappings.  Parameters: - device_id: Identifier of the FortiGate dev... |
| `list_virtual_ips` | List all Virtual IPs configured on a FortiGate device.  This tool retrieves all Virtual IP objects defined on the device, including port forwarding configurations and NAT mappings.  Parameters: - device_id: Identifier of the FortiGate de... |
| `update_virtual_ip` | Update an existing Virtual IP on a FortiGate device.  This tool modifies the configuration of an existing Virtual IP object, allowing changes to IP addresses, ports, or other settings.  Parameters: - device_id: Identifier of the FortiGat... |

## VPN (IPsec + SSL VPN)

| Tool | Description |
|---|---|
| `vpn_create_ipsec_phase2` | Propose creating an IPsec phase2 traffic selector, linked to an existing tunnel by phase1name. Required for traffic to actually flow through a site-to-site VPN. Returns a diff + change_id. |
| `vpn_create_ipsec_tunnel` | Propose creating an IPsec site-to-site VPN tunnel (phase1-interface: remote gateway, outgoing interface, auth method/PSK, IKE version, proposal). Note: psksecret is a normal argument here and will be visible in the conversation -- FortiG... |
| `vpn_delete_ipsec_phase2` | Propose deleting an IPsec phase2 traffic selector. Returns a diff + change_id. |
| `vpn_delete_ipsec_tunnel` | Propose deleting an IPsec tunnel (phase1-interface). Returns a diff + change_id. |
| `vpn_get_ipsec_status` | Get live IPsec tunnel status (up/down, traffic counters). |
| `vpn_get_ipsec_tunnel_detail` | Get detailed configuration for a specific IPsec tunnel. |
| `vpn_get_ssl_vpn_settings` | Get SSL VPN settings (port, source interface, tunnel IP pools). Read-only. |
| `vpn_list_ipsec_phase2` | List IPsec phase2 traffic selectors (the subnets that pass through a tunnel). |
| `vpn_list_ipsec_tunnels` | List IPsec VPN tunnels (phase1-interface definitions). |
| `vpn_list_ssl_vpn_sessions` | List active SSL VPN sessions (connected remote users). Read-only. |
| `vpn_update_ipsec_phase2` | Propose updating an IPsec phase2 traffic selector. Returns a diff + change_id. |
| `vpn_update_ipsec_tunnel` | Propose updating an existing IPsec tunnel's phase1 configuration. Returns a diff + change_id. |

## System Configuration (DNS-NTP-syslog-SNMP-admin-HA)

| Tool | Description |
|---|---|
| `system_create_admin` | Propose creating a local admin account. Note: `password` is a normal argument here and will be visible in the conversation -- FortiGate never returns it on GET, so there's no read-side leak, but be mindful on write. Returns a diff + chan... |
| `system_create_snmp_community` | Propose creating an SNMP v1/v2c community (name, hosts allowed to query, queries enabled). Returns a diff + change_id. |
| `system_delete_admin` | Propose deleting a local admin account. Returns a diff + change_id. |
| `system_delete_snmp_community` | Propose deleting an SNMP v1/v2c community. Returns a diff + change_id. |
| `system_get_dns` | Get DNS server settings for a device/VDOM. |
| `system_get_global` | Get global system settings (hostname, timezone, admin/mgmt ports, vdom-mode, ...). |
| `system_get_ha_config` | Get high-availability (HA) cluster configuration. |
| `system_get_ntp` | Get NTP settings for a device. |
| `system_get_snmp_sysinfo` | Get global SNMP agent settings (enable/description/contact/location). |
| `system_get_syslog` | Get syslogd (remote logging) settings for a device. |
| `system_list_admins` | List local admin (management user) accounts. |
| `system_list_snmp_communities` | List SNMP v1/v2c communities. SNMPv3 users are not yet supported by this server. |
| `system_update_admin` | Propose updating a local admin account. Returns a diff + change_id. |
| `system_update_dns` | Propose updating DNS server settings (primary/secondary DNS, protocol). Returns a diff + change_id; call change.apply(change_id) to actually apply it. |
| `system_update_global` | Propose updating global system settings (hostname, timezone, admin-sport/admin-ssh-port, vdom-mode, ...). WARNING: changing the admin ports or switching vdom-mode can disrupt the current management session/connection to this device -- re... |
| `system_update_ha_config` | Propose updating HA cluster configuration (mode, group-id/group-name, password, priority, heartbeat/monitor interfaces, override). WARNING: misconfiguration can affect cluster membership and reachability -- review the diff carefully befo... |
| `system_update_ntp` | Propose updating NTP settings (ntpsync, NTP server list, sync interval). Returns a diff + change_id. |
| `system_update_snmp_community` | Propose updating an SNMP v1/v2c community. Returns a diff + change_id. |
| `system_update_snmp_sysinfo` | Propose updating global SNMP agent settings. Returns a diff + change_id. |
| `system_update_syslog` | Propose updating syslogd settings (remote syslog server, port, facility, format). Returns a diff + change_id. |

## VDOM Lifecycle

| Tool | Description |
|---|---|
| `vdom_create` | Propose creating a new VDOM. WARNING: the device must already be in multi-vdom mode -- if discover_vdoms shows only 'root', first call system_update_global with vdom-mode: multi-vdom (see system_tools.py) and apply that change. Enabling ... |
| `vdom_create_link` | Propose creating an inter-VDOM link. FortiOS creates a pair of virtual interfaces (<name>0/<name>1); each side must then be assigned to one of the two VDOMs being joined via create_interface/update_interface (interface tools). Returns a ... |
| `vdom_delete` | Propose deleting a VDOM. All interfaces/policies/objects assigned to it must be moved or removed first, or FortiOS will reject the deletion. Returns a diff + change_id. |
| `vdom_delete_link` | Propose deleting an inter-VDOM link. Returns a diff + change_id. |
| `vdom_list_links` | List inter-VDOM links (virtual interface pairs joining two VDOMs). |

## Analysis & Compliance

| Tool | Description |
|---|---|
| `analysis_check_best_practices` | Check firewall policies against a set of Fortinet-style best-practice heuristics (traffic logging, comments, stale disabled rules). |
| `analysis_check_system_config` | Check device-level system configuration (DNS, NTP, syslog, SNMP communities, admin accounts, HA, hostname) against a set of best-practice heuristics -- the system.*/vdom.* counterpart to analysis_check_best_practices' policy checks. |
| `analysis_compliance_report` | Generate a combined compliance report: security score plus every individual analysis finding, including system configuration checks. |
| `analysis_find_any_any` | Find overly permissive any-source/any-destination/any-service policies. |
| `analysis_find_duplicate_policies` | Find firewall policies with identical match criteria and action -- fully redundant rules where removing either has no effect. |
| `analysis_find_overlapping_subnets` | Find address objects whose subnets/ranges overlap with each other. |
| `analysis_find_shadowed_policies` | Find firewall policies that can never match traffic because an earlier, broader enabled policy already matches everything they would. |
| `analysis_find_unused_objects` | Find address, service, and virtual IP objects not referenced by any firewall policy. |
| `analysis_score_security` | Compute a heuristic 0-100 security score for the device from the other analysis checks, including system configuration. Not an authoritative compliance measure -- a quick signal, not a certification. |

## Documentation Generation

| Tool | Description |
|---|---|
| `doc_export_markdown` | Export a combined Markdown report: device summary, system configuration, firewall policies, and routing, all in one document. |
| `doc_generate_policy_doc` | Generate a Markdown table documenting all firewall policies. |
| `doc_generate_routing_doc` | Generate a Markdown document of static routes and the active routing table. |
| `doc_generate_system_config` | Generate a Markdown document of system configuration: DNS, NTP, syslog, SNMP (agent status + communities), admin accounts, HA, and global settings (hostname/timezone/admin ports). |
| `doc_generate_topology` | Generate a device topology diagram (interfaces, static routes, virtual IPs) in mermaid, drawio, or plantuml format. |
| `doc_generate_vpn_doc` | Generate a Markdown document of VPN configuration: IPsec tunnels with live up/down status, phase2 traffic selectors, and SSL VPN settings/active session count. |

## Fleet (multi-device) Operations

| Tool | Description |
|---|---|
| `fleet_compare_devices` | Compare a resource type (default: firewall_policy) between two devices -- what's only on one side, what's identical, and what differs field-by-field. |
| `fleet_replicate_config` | Like fleet.sync_objects, but for multiple resource types (default: address + service objects) replicated from one source device to every device matched by dest_target (e.g. an entire site). Without confirm=True, only returns the plan. |
| `fleet_report` | Generate a fleet-wide security report: per-device security score plus a fleet summary, for every device matched by target (e.g. a whole customer or site). |
| `fleet_search_object` | Search for an object (by name, or policy id for firewall_policy) across every device matched by target -- or the entire inventory if target is omitted. |
| `fleet_sync_objects` | Copy objects present on a source device but missing on a destination device. Without confirm=True, only returns the plan (what would be created) -- nothing is written. Pass confirm=True to actually execute; still blocked by READ_ONLY/SAF... |

## Natural-Language Intents

| Tool | Description |
|---|---|
| `intent_create_policy` | Create a firewall policy from high-level fields (e.g. 'HTTPS from LAN to Internet' -> source_zone='LAN', dest_zone='Internet', service='HTTPS'). Resolves zone/service names against the device's existing interfaces/service objects, fallin... |
| `intent_explain_policy_failure` | Explain why a specific firewall policy might not be matching traffic as expected: checks whether it's disabled, shadowed by an earlier broader policy, schedule-restricted, or denied by an earlier deny rule. Configuration-level review onl... |
| `intent_find_path` | Simulate FortiGate's first-match-wins policy evaluation for one traffic tuple (source, destination address object names -- or 'any' -- and an optional service name) and report which policy (if any) would handle it. |
| `intent_summarize_device` | Plain-English summary of a device: hostname, FortiOS version, interface up/down counts, policy/object counts, and its security score. |

## Change Engine (preview-apply-rollback)

| Tool | Description |
|---|---|
| `change_apply` | Apply a previously proposed change. Every mutating tool (create_firewall_policy, update_static_route, delete_virtual_ip, ...) returns a change_id instead of executing immediately -- call this to actually run it. Re-validates the current ... |
| `change_history` | Show recent change history (proposed/applied/rolled_back/expired), most recent first. |
| `change_list_pending` | List proposed changes awaiting change.apply (not yet applied, not expired). |
| `change_rollback` | Roll back a previously applied change, restoring the resource to its pre-change state where possible. Recreating a deleted resource may get a new identifier from FortiOS; rolling back a create can only auto-delete the resource if FortiOS... |
