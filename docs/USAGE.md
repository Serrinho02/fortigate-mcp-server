# Usage Guide

Assumes you've already followed [Installation](INSTALLATION.md) and have the server wired into an MCP client. Everything below is phrased as what you'd say to Claude -- it picks the right tool calls.

## Core concepts

- **A device can live in two places.** The legacy `config.json` (flat, one file, unencrypted credentials -- fine for a quick local test) and the inventory database (Customer -> Site -> Device -> VDOM, credentials in your OS keyring -- the intended path for anything real). Every tool resolves a `device_id` against both, so it doesn't matter which one a device came from.
- **You never type an IP into a prompt for a registered device.** `connection_connect("Milano")` or `connection_connect("Alfa")` resolves by name/site/customer through the inventory; if it's ambiguous (e.g. a customer with several firewalls), the error lists the candidates so you can be specific.
- **Every mutation is preview, then apply.** A tool like `create_firewall_policy` never touches the device -- it computes a diff, stores it, and returns a `change_id`. Nothing happens until you (or Claude, on your instruction) calls `change_apply(change_id)`. If the device's state changed in between, `change_apply` refuses and tells you to re-preview.
- **VDOM is a parameter, not a device.** Pass `vdom="root"` (or omit it for the device's default) on any per-VDOM call.

## Walkthrough: registering your first device

> "Register a new device: host 10.10.10.1, name 'HUB-FW01', customer 'Contoso', site 'Milano'."

Claude calls `inventory_register_device_pending`. It returns a `device_id` (e.g. `dev_a83653612dc2`) and a `credential_id` -- and the device is **not usable yet**.

Now, in a terminal, *you* run (not Claude -- this step is deliberately outside the AI's reach):

```bash
fortinet-mcp-cred set cred_a83653612dc2 --auth-type token
```

Paste the FortiGate's API token when prompted. Then:

> "Connect to HUB-FW01 and show me its status."

Claude calls `connection_connect("HUB-FW01")` then `get_device_status`.

## Walkthrough: a first mutation

> "Create a firewall policy on HUB-FW01 called 'Allow-Web' from LAN to WAN, HTTPS, allow."

Claude calls `create_firewall_policy`, which returns something like:

```
Change proposed (not yet applied)
  change_id: chg_9f1a2b3c4d5e
  operation: create
  resource: firewall_policy
  ...
  Diff: { ... }

To apply this change, call change.apply(change_id="chg_9f1a2b3c4d5e").
This preview expires at ... UTC.
```

> "Looks good, apply it."

Claude calls `change_apply("chg_9f1a2b3c4d5e")`. If you'd said "actually, change the service to HTTP too" instead, Claude would re-call `create_firewall_policy` with the corrected data to get a fresh preview -- the old `change_id` is now stale and would be rejected.

`change_list_pending` shows anything proposed-but-not-applied; `change_history` shows everything that's happened; `change_rollback(change_id)` best-effort undoes an applied change (an exact undo for update/delete, a re-create for a deleted resource -- which may get a new FortiOS-assigned id).

## Walkthrough: bootstrapping a device from scratch

A realistic "day 0" sequence, each step preview -> apply as above:

1. `system_update_global` -- hostname, timezone, admin ports
2. `system_update_dns`, `system_update_ntp`, `system_update_syslog` -- point at your resolvers/NTP pool/SIEM
3. `system_create_admin` -- a named admin account (don't leave only the default `admin` around)
4. `routing_create_interface` -- carve out a VLAN sub-interface with an IP
5. `routing_create_zone` -- group interfaces
6. `routing_create_dhcp_server` -- hand out addresses on the new VLAN
7. `create_firewall_policy` -- allow the traffic you actually want

There's no single "bootstrap" tool that does all of this in one call -- Claude sequences the granular tools itself, the same way `intent_create_policy` composes zone/object resolution internally. Just describe the end state you want and let it work through the steps; confirm each `change_apply` as you go (or tell it up front "apply everything as you go" if you trust the sequence).

## Walkthrough: VDOM multi-tenancy

> "Does HUB-FW01 support multiple VDOMs? If not, enable it, then create a VDOM called 'TenantA'."

Claude calls `discover_vdoms` first. If only `root` exists, it needs `system_update_global` with `vdom-mode: multi-vdom` applied first -- **this is a disruptive change**, flagged in the tool's own description: enabling multi-VDOM mode for the first time can require a reboot or briefly drop management connectivity, depending on firmware. Expect Claude to call this out and ask before applying it, not sail through silently.

Once multi-vdom mode is active: `vdom_create({"name": "TenantA"})` -> `change_apply`. To link two VDOMs: `vdom_create_link` creates a pair of virtual interfaces (`<name>0`/`<name>1`) that then each need `routing_update_interface` to assign them to their respective VDOM.

## Walkthrough: VPN

> "Set up a site-to-site tunnel from HUB-FW01 to 203.0.113.1, PSK-based, and let 10.0.0.0/24 talk to 10.1.0.0/24 through it."

Claude calls `vpn_create_ipsec_tunnel` (phase1: gateway/interface/PSK/proposal), then after that's applied, `vpn_create_ipsec_phase2` (the traffic selector linking the two subnets to the tunnel). `vpn_get_ipsec_status` shows live up/down state once both are applied.

Note: the PSK is a normal tool argument here (visible in the conversation), unlike device credentials -- FortiOS never returns it on a GET, so there's no way around passing it once on write. See the main README's Security Model.

## Walkthrough: analysis and compliance

> "Run a compliance report on HUB-FW01."

`analysis_compliance_report` bundles: security score, any-any/shadowed/duplicate policy findings, unused objects, overlapping subnets, policy best-practices, *and* system-configuration best-practices (missing DNS/NTP/syslog, default SNMP community names, single admin account, no HA, unchanged hostname). It's a heuristic signal, not a certified audit -- treat the score as "worth investigating," not ground truth.

Narrower tools exist if you just want one check: `analysis_find_any_any`, `analysis_find_shadowed_policies`, `analysis_check_system_config`, etc. -- see [Tool Reference](TOOLS.md).

## Walkthrough: documentation

> "Generate a topology diagram and a full Markdown writeup of HUB-FW01."

`doc_generate_topology(diagram_format="mermaid")` returns a Mermaid diagram you can paste straight into a Markdown file or GitHub issue. `doc_export_markdown` returns a combined report: device summary, system configuration, firewall policies, and routing, in one document. Narrower generators exist too: `doc_generate_policy_doc`, `doc_generate_vpn_doc`, `doc_generate_system_config`.

## Walkthrough: fleet operations

> "Compare the firewall policies on HUB-FW01 and BRANCH-FW02, and tell me if address object 'internal-dns' exists on every device."

`fleet_compare_devices` and `fleet_search_object` operate across every device the inventory knows about (or a scoped subset), resolved through the same `connection.*` machinery as everything else -- no need to name every device explicitly if you want "the whole estate."

## Read-only reconnaissance, no mode restrictions

Every `list_*`, `get_*`, `analysis_*`, and `doc_*` tool is read-only and works regardless of `FORTINET_MCP_MODE` -- `read_only` mode blocks *previewing* a mutation, not looking at current state.
