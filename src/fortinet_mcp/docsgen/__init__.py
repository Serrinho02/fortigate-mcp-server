"""
Documentation/diagram generation: pure functions that turn plain FortiOS
dicts (interfaces, routes, VIPs, policies, VPN tunnels) into diagram
source or Markdown text. No I/O, no adapter/service imports -- fetching
the live data is DocumentationService's job (services/documentation_service.py).
"""
